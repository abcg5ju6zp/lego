package cmd

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/cmd/internal/flags"
	"github.com/go-acme/lego/v5/cmd/internal/prompt"
	"github.com/go-acme/lego/v5/cmd/internal/storage"
	"github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"
	"github.com/urfave/cli/v3"
)

// keyRolloverService is the subset of *registration.Registrar used by the rollover state machine.
type keyRolloverService interface {
	QueryRegistration(ctx context.Context) (*acme.ExtendedAccount, error)
	KeyRolloverResult(ctx context.Context, newKey crypto.Signer) (acme.Account, error)
}

// keyRolloverServiceFactory builds a client authenticated with the given key
// (but always targeting the same account URL), to probe which key the server currently accepts.
type keyRolloverServiceFactory func(key crypto.Signer) (keyRolloverService, error)

func createAccountKeyRollover() *cli.Command {
	return &cli.Command{
		Name:   "keyrollover",
		Usage:  "Update the account private key.",
		Action: accountKeyRollover,
		Flags:  flags.CreateKeyRolloverFlags(),
	}
}

func accountKeyRollover(ctx context.Context, cmd *cli.Command) error {
	log.Info("Account private key rollover.",
		slog.String("account", storage.GetEffectiveAccountID(cmd.String(flags.FlgEmail), cmd.String(flags.FlgAccountID))),
		slog.String("email", cmd.String(flags.FlgEmail)),
		slog.String("server", cmd.String(flags.FlgServer)),
		slog.String("keyType", cmd.String(flags.FlgKeyType)),
	)

	if !prompt.Confirm("Do you want to proceed?") {
		log.Info("Aborting.")
		return nil
	}

	keyType, err := certcrypto.ToKeyType(cmd.String(flags.FlgKeyType))
	if err != nil {
		return err
	}

	accountsStorage := storage.NewAccountsStorage(cmd.String(flags.FlgPath))

	account, err := accountsStorage.Get(cmd.String(flags.FlgServer), keyType, cmd.String(flags.FlgEmail), cmd.String(flags.FlgAccountID))
	if err != nil {
		return fmt.Errorf("get account: %w", err)
	}

	if account.NeedsRecovery || account.GetRegistration() == nil || account.GetRegistration().Location == "" {
		return errors.New("the account is not registered: register or recover it before rolling its key over")
	}

	newKey, err := getPrivateKey(cmd, keyType)
	if err != nil {
		return fmt.Errorf("get private key: %w", err)
	}

	factory := func(key crypto.Signer) (keyRolloverService, error) {
		// Clone the account so that probing with another key never mutates the current account.
		probeAccount := *account
		probeAccount.SetPrivateKey(key)

		client, clientErr := newClient(cmd, &probeAccount)
		if clientErr != nil {
			return nil, fmt.Errorf("set up client: %w", clientErr)
		}

		return client.Registration, nil
	}

	err = executeKeyRollover(ctx, factory, accountsStorage, account, newKey)
	if err != nil {
		return fmt.Errorf("could not complete key rollover: %w", err)
	}

	return nil
}

// executeKeyRollover runs the crash-safe key rollover state machine.
//
// A pending generation (old key, new key, account URL) is persisted before any remote request.
// The new account is committed only after the remote key change succeeds,
// the returned account is verified, and the local files are synchronized.
// Any failure leaves a state on disk that a subsequent invocation can resume from.
func executeKeyRollover(
	ctx context.Context,
	factory keyRolloverServiceFactory,
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	newKey crypto.Signer,
) error {
	if account.GetRegistration() == nil || account.GetRegistration().Location == "" {
		return errors.New("the account is not registered: register or recover it before rolling its key over")
	}

	oldKey := account.GetPrivateKey()

	oldThumbprint, err := storage.KeyThumbprint(oldKey)
	if err != nil {
		return fmt.Errorf("identify the current private key: %w", err)
	}

	requestedThumbprint, err := storage.KeyThumbprint(newKey)
	if err != nil {
		return fmt.Errorf("identify the new private key: %w", err)
	}

	if oldThumbprint == requestedThumbprint {
		log.Info("The account already uses this private key: nothing to do.")
		return nil
	}

	newKeyType, err := certcrypto.GetPrivateKeyType(newKey)
	if err != nil {
		return fmt.Errorf("get the new private key type: %w", err)
	}

	state, err := accountsStorage.GetKeyRolloverState(account)
	if err != nil {
		return err
	}

	if state == nil {
		return startKeyRollover(ctx, factory, accountsStorage, account, oldKey, newKey, oldThumbprint, requestedThumbprint, newKeyType)
	}

	return resumeKeyRollover(ctx, factory, accountsStorage, account, state, account.GetPrivateKey(), newKey)
}

// startKeyRollover records the pending generation, performs the remote key change,
// verifies the response, and then commits the new account.
func startKeyRollover(
	ctx context.Context,
	factory keyRolloverServiceFactory,
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	oldKey, newKey crypto.Signer,
	oldThumbprint, newThumbprint string,
	newKeyType certcrypto.KeyType,
) error {
	accountURL := account.GetRegistration().Location

	log.Info("Recording the pending key rollover generation.", slog.String("accountURL", accountURL))

	// Stage the new key first: it is never written over the current key before confirmation.
	err := accountsStorage.WritePendingPrivateKey(account, newKey)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	state := &storage.KeyRolloverState{
		Phase:            storage.KeyRolloverPhaseRemote,
		AccountURL:       accountURL,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		NewKeyType:       newKeyType,
		StartedAt:        now,
	}

	err = accountsStorage.SaveKeyRolloverState(account, state)
	if err != nil {
		return err
	}

	log.Info("Requesting the remote key change.")

	service, err := factory(oldKey)
	if err != nil {
		return keepPendingState(state, "create the ACME client", err)
	}

	remoteAccount, err := service.KeyRolloverResult(ctx, newKey)
	if err != nil {
		return keepPendingState(state, "remote key change", err)
	}

	err = validateRolloverAccount(remoteAccount, account.GetRegistration())
	if err != nil {
		return keepPendingState(state, "verify the key change response", err)
	}

	return finishKeyRollover(accountsStorage, account, state, newKey)
}

// resumeKeyRollover continues an interrupted rollover.
// It first discovers which key the server actually accepts, never assuming the remote outcome.
func resumeKeyRollover(
	ctx context.Context,
	factory keyRolloverServiceFactory,
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	currentKey, requestedKey crypto.Signer,
) error {
	log.Warn("Found an unfinished key rollover: resuming it.",
		slog.String("accountURL", state.AccountURL),
		slog.String("phase", string(state.Phase)),
	)

	if state.AccountURL != "" && state.AccountURL != account.GetRegistration().Location {
		return fmt.Errorf(
			"the unfinished rollover refers to account %q but the account file refers to %q: refusing to continue",
			state.AccountURL, account.GetRegistration().Location)
	}

	oldKey, newKey, newKeyInstalled, err := resolveRolloverKeys(accountsStorage, account, state, currentKey, requestedKey)
	if err != nil {
		return err
	}

	// If the server already accepts the new key, the remote part is done: only finalize locally.
	remoteAccount, newKeyAccepted, err := probeAccountKey(ctx, factory, newKey)
	if err != nil {
		return fmt.Errorf("probe the new key against the ACME server: %w", err)
	}

	if newKeyAccepted {
		log.Info("The server already accepts the new key: finalizing the local files.")

		err = validateRolloverAccount(remoteAccount.Account, account.GetRegistration())
		if err != nil {
			return keepPendingState(state, "verify the account while resuming", err)
		}

		return finishKeyRollover(accountsStorage, account, state, newKey)
	}

	return retryRolloverWithOldKey(ctx, factory, accountsStorage, account, state, oldKey, newKey, newKeyInstalled)
}

// retryRolloverWithOldKey handles the resume case where the server does not accept the new key yet:
// it verifies the old key is still accepted, optionally restores it locally, and sends the key change again.
func retryRolloverWithOldKey(
	ctx context.Context,
	factory keyRolloverServiceFactory,
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	oldKey, newKey crypto.Signer,
	newKeyInstalled bool,
) error {
	if oldKey == nil {
		return errors.New("the server does not recognize the new key and the old key is no longer available locally: " +
			"the pending rollover state is kept for manual recovery")
	}

	_, oldKeyAccepted, err := probeAccountKey(ctx, factory, oldKey)
	if err != nil {
		return fmt.Errorf("probe the old key against the ACME server: %w", err)
	}

	if !oldKeyAccepted {
		return fmt.Errorf("neither the old nor the new key are accepted by the server for account %q: "+
			"the pending rollover state is kept for manual recovery", state.AccountURL)
	}

	if newKeyInstalled {
		// The old key is accepted remotely but the local canonical key is the new one.
		// Before retrying, re-stage the new key and restore the confirmed (old) key locally,
		// so that no key material of the pending generation is lost.
		log.Warn("The server still accepts the old key: restoring it locally before retrying the key change.")

		err = accountsStorage.WritePendingPrivateKey(account, newKey)
		if err != nil {
			return fmt.Errorf("re-stage the new private key: %w", err)
		}

		account.SetPrivateKey(oldKey)

		err = accountsStorage.SavePrivateKey(account)
		if err != nil {
			return fmt.Errorf("restore the old private key: %w", err)
		}
	}

	log.Info("The server still accepts the old key: requesting the key change again.")

	service, err := factory(oldKey)
	if err != nil {
		return keepPendingState(state, "create the ACME client", err)
	}

	changedAccount, err := service.KeyRolloverResult(ctx, newKey)
	if err != nil {
		return keepPendingState(state, "remote key change", err)
	}

	err = validateRolloverAccount(changedAccount, account.GetRegistration())
	if err != nil {
		return keepPendingState(state, "verify the key change response", err)
	}

	return finishKeyRollover(accountsStorage, account, state, newKey)
}

// resolveRolloverKeys locates the old and new keys of a pending generation on disk.
//
// The canonical account key must never be mistaken for the unconfirmed new key:
// keys are identified with their recorded JWK thumbprints.
func resolveRolloverKeys(
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	currentKey, requestedKey crypto.Signer,
) (oldKey, newKey crypto.Signer, newKeyInstalled bool, err error) {
	currentThumbprint, err := storage.KeyThumbprint(currentKey)
	if err != nil {
		return nil, nil, false, fmt.Errorf("identify the current private key: %w", err)
	}

	if currentThumbprint != state.NewKeyThumbprint && currentThumbprint != state.OldKeyThumbprint {
		return nil, nil, false, errors.New("the current private key matches neither the old nor the new key of the pending rollover")
	}

	newKey, newKeyInstalled, err = locateNewRolloverKey(accountsStorage, account, state, currentKey, requestedKey, currentThumbprint)
	if err != nil {
		return nil, nil, false, err
	}

	oldKey, err = locateOldRolloverKey(accountsStorage, account, state, currentKey, currentThumbprint)
	if err != nil {
		return nil, nil, false, err
	}

	return oldKey, newKey, newKeyInstalled, nil
}

// locateNewRolloverKey resolves the new key of a pending generation:
// the canonical key when it is already the new one, the staged key otherwise,
// and as a last resort the key provided on the command line (when it matches the recorded generation).
func locateNewRolloverKey(
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	currentKey, requestedKey crypto.Signer,
	currentThumbprint string,
) (crypto.Signer, bool, error) {
	if currentThumbprint == state.NewKeyThumbprint {
		// The canonical key is the new key: local synchronization happened before the interruption.
		return currentKey, true, nil
	}

	// The staged new key is the authoritative material for the recorded generation.
	stagedKey, err := accountsStorage.ReadPendingPrivateKey(account)
	if err == nil {
		stagedThumbprint, thumbErr := storage.KeyThumbprint(stagedKey)
		if thumbErr != nil {
			return nil, false, thumbErr
		}

		if stagedThumbprint != state.NewKeyThumbprint {
			return nil, false, errors.New("the staged private key does not match the pending rollover state")
		}

		return stagedKey, false, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	requestedThumbprint, err := storage.KeyThumbprint(requestedKey)
	if err != nil {
		return nil, false, err
	}

	if requestedThumbprint != state.NewKeyThumbprint {
		return nil, false, errors.New("the new private key of the unfinished rollover is no longer available locally: " +
			"provide the same key file with --private-key to resume, or recover the account manually")
	}

	return requestedKey, false, nil
}

// locateOldRolloverKey resolves the old key of a pending generation:
// the canonical key when it is still the old one, otherwise the key archived during an interrupted commit.
func locateOldRolloverKey(
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	currentKey crypto.Signer,
	currentThumbprint string,
) (crypto.Signer, error) {
	if currentThumbprint == state.OldKeyThumbprint {
		return currentKey, nil
	}

	archivedKey, err := accountsStorage.ReadArchivedPrivateKey(account)
	if err != nil {
		return nil, err
	}

	if archivedKey == nil {
		return nil, nil
	}

	archivedThumbprint, err := storage.KeyThumbprint(archivedKey)
	if err != nil {
		return nil, err
	}

	if archivedThumbprint != state.OldKeyThumbprint {
		return nil, nil
	}

	return archivedKey, nil
}

// probeAccountKey reports whether the ACME server accepts the given key for the account URL.
// A 4xx ACME problem (other than rate limiting) is a definitive rejection;
// network/5xx/429 outcomes are inconclusive and must not destroy the pending state.
func probeAccountKey(ctx context.Context, factory keyRolloverServiceFactory, key crypto.Signer) (*acme.ExtendedAccount, bool, error) {
	service, err := factory(key)
	if err != nil {
		return nil, false, err
	}

	remoteAccount, err := service.QueryRegistration(ctx)
	if err == nil {
		return remoteAccount, true, nil
	}

	problem, ok := errors.AsType[*acme.ProblemDetails](err)
	if ok {
		switch {
		case problem.HTTPStatus == http.StatusTooManyRequests:
			// Rate limited: inconclusive.
		case problem.HTTPStatus > 0 && problem.HTTPStatus < 500:
			// Definitive authentication/account rejection.
			return nil, false, nil
		default:
			// 5xx or unknown status: inconclusive.
		}
	}

	return nil, false, err
}

// validateRolloverAccount checks the account object returned (or fetched) around a key change
// against the locally known registration.
func validateRolloverAccount(remote acme.Account, registered *acme.ExtendedAccount) error {
	if remote.Status != "" && remote.Status != acme.StatusValid {
		return fmt.Errorf("unexpected account status %q after the key change", remote.Status)
	}

	if registered != nil && registered.Orders != "" && remote.Orders != "" && remote.Orders != registered.Orders {
		return fmt.Errorf("account mismatch after the key change: orders URL %q does not match the registered one %q",
			remote.Orders, registered.Orders)
	}

	return nil
}

// finishKeyRollover marks the generation as remotely confirmed and synchronizes the local files,
// then commits (removes the pending state). It is idempotent to support resumes.
func finishKeyRollover(
	accountsStorage *storage.AccountsStorage,
	account *storage.Account,
	state *storage.KeyRolloverState,
	newKey crypto.Signer,
) error {
	state.Phase = storage.KeyRolloverPhaseLocal

	if err := accountsStorage.SaveKeyRolloverState(account, state); err != nil {
		return fmt.Errorf("record remote key rollover confirmation: %w", err)
	}

	err := accountsStorage.CommitKeyRollover(account, state, newKey)
	if err != nil {
		return fmt.Errorf("synchronize the local account files: %w", err)
	}

	log.Info("Account private key rollover completed.")

	return nil
}

// keepPendingState wraps an error with resume guidance, making clear the pending generation is kept.
func keepPendingState(state *storage.KeyRolloverState, step string, err error) error {
	return fmt.Errorf("%s failed: %w (the unfinished rollover for account %q is recorded on disk; rerun this command to resume)",
		step, err, state.AccountURL)
}

// getPrivateKey loads the new private key from the --private-key flag, or generates one.
// It returns the key directly; the key type is derived from the key material by the caller.
func getPrivateKey(cmd *cli.Command, keyType certcrypto.KeyType) (crypto.Signer, error) {
	if cmd.IsSet(flags.FlgPrivateKey) {
		privateKey, err := storage.ReadPrivateKeyFile(cmd.String(flags.FlgPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("load private key: %w", err)
		}

		return privateKey, nil
	}

	log.Debug("Generating a new private key.")

	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("generate a new private key: %w", err)
	}

	return privateKey, nil
}

// Compile-time assertion that *registration.Registrar satisfies keyRolloverService.
var _ keyRolloverService = (*registration.Registrar)(nil)
