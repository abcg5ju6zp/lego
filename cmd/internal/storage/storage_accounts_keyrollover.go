package storage

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-jose/go-jose/v4"
)

const (
	// keyRolloverStateFileName is the name of the file recording the pending,
	// not yet confirmed key rollover generation of an account.
	keyRolloverStateFileName = "keyrollover.json"

	// pendingPrivateKeySuffix is the suffix of the file holding the new private key
	// while the remote key change has not been confirmed.
	// It is never read as the current account key.
	pendingPrivateKeySuffix = ".key.pending"

	// archivedPrivateKeySuffix is the suffix of the file holding the previous private key,
	// archived only after the new key has been confirmed and installed.
	archivedPrivateKeySuffix = ".key.archived"

	keyRolloverStateVersion = 1
)

// KeyRolloverPhase is the phase of a pending key rollover generation.
type KeyRolloverPhase string

const (
	// KeyRolloverPhaseRemote means the remote key change has not been confirmed yet.
	KeyRolloverPhaseRemote KeyRolloverPhase = "remote"

	// KeyRolloverPhaseLocal means the remote key change has been confirmed,
	// and the local file synchronization is in progress (or was interrupted).
	KeyRolloverPhaseLocal KeyRolloverPhase = "local"
)

// KeyRolloverState records a pending, not yet confirmed account key rollover generation.
//
// The file is created before the remote keyChange is sent, and deleted only once:
//   - the remote key change has been accepted and the returned account verified,
//   - the new private key has been installed as the current key,
//   - and the account file has been synchronized.
//
// As long as this file exists, the current account key (see Account.GetPrivateKey)
// remains the confirmed (old) key: the unconfirmed new key only lives in its staging file.
type KeyRolloverState struct {
	Version          int                `json:"version"`
	Phase            KeyRolloverPhase   `json:"phase"`
	AccountURL       string             `json:"accountURL"`
	OldKeyThumbprint string             `json:"oldKeyThumbprint"`
	NewKeyThumbprint string             `json:"newKeyThumbprint"`
	NewKeyType       certcrypto.KeyType `json:"newKeyType,omitempty"`

	StartedAt time.Time `json:"startedAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// KeyThumbprint returns the base64url-encoded JWK thumbprint (RFC 7638) of a key.
// It is used to identify keys of a rollover generation without relying on file names.
func KeyThumbprint(key crypto.Signer) (string, error) {
	if key == nil {
		return "", errors.New("nil private key")
	}

	jwk := jose.JSONWebKey{Key: key.Public()}

	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute key thumbprint: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// keyRolloverPaths gathers the on-disk paths used by a pending key rollover generation.
type keyRolloverPaths struct {
	state        string
	pendingKey   string
	archivedKey  string
	canonicalKey string
}

func (s *AccountsStorage) keyRolloverPaths(account *Account) (keyRolloverPaths, error) {
	server, err := url.Parse(account.Server)
	if err != nil {
		return keyRolloverPaths{}, fmt.Errorf("invalid server URL %q: %w", account.Server, err)
	}

	effectiveAccountID := account.GetID()

	rootUserPath := s.getRootUserPath(server, effectiveAccountID)

	return keyRolloverPaths{
		state:        filepath.Join(rootUserPath, keyRolloverStateFileName),
		pendingKey:   filepath.Join(rootUserPath, effectiveAccountID+pendingPrivateKeySuffix),
		archivedKey:  filepath.Join(rootUserPath, effectiveAccountID+archivedPrivateKeySuffix),
		canonicalKey: s.getAccountKeyPath(server, effectiveAccountID),
	}, nil
}

// GetKeyRolloverState returns the pending key rollover generation recorded for the account.
// It returns (nil, nil) when no rollover is pending.
func (s *AccountsStorage) GetKeyRolloverState(account *Account) (*KeyRolloverState, error) {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return nil, err
	}

	state, err := ReadJSONFile[KeyRolloverState](paths.state)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("could not read the key rollover state file %q: %w", paths.state, err)
	}

	return state, nil
}

// SaveKeyRolloverState records (or updates) the pending key rollover generation.
// The file is written atomically so that a crash never leaves a truncated state.
func (s *AccountsStorage) SaveKeyRolloverState(account *Account, state *KeyRolloverState) error {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return err
	}

	state.Version = keyRolloverStateVersion
	state.UpdatedAt = time.Now().UTC()

	jsonBytes, err := json.MarshalIndent(state, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal the key rollover state: %w", err)
	}

	err = writeFileAtomic(paths.state, append(jsonBytes, '\n'))
	if err != nil {
		return fmt.Errorf("save the key rollover state file: %w", err)
	}

	return nil
}

// DeleteKeyRolloverState commits the rollover by removing its pending generation record.
// A missing state file is not an error.
func (s *AccountsStorage) DeleteKeyRolloverState(account *Account) error {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return err
	}

	err = os.Remove(paths.state)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete the key rollover state file: %w", err)
	}

	return nil
}

// WritePendingPrivateKey stages the new private key in a dedicated file
// which is never read as the current account key while the rollover is unconfirmed.
func (s *AccountsStorage) WritePendingPrivateKey(account *Account, newKey crypto.Signer) error {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(paths.pendingKey), 0o700); err != nil {
		return fmt.Errorf("create the directory for the pending private key: %w", err)
	}

	err = writeFileAtomic(paths.pendingKey, pem.EncodeToMemory(certcrypto.PEMBlock(newKey)))
	if err != nil {
		return fmt.Errorf("write the pending private key: %w", err)
	}

	return nil
}

// ReadPendingPrivateKey reads the staged new private key of the pending rollover.
func (s *AccountsStorage) ReadPendingPrivateKey(account *Account) (crypto.Signer, error) {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return nil, err
	}

	privateKey, err := ReadPrivateKeyFile(paths.pendingKey)
	if err != nil {
		return nil, fmt.Errorf("read the pending private key %q: %w", paths.pendingKey, err)
	}

	return privateKey, nil
}

// ReadArchivedPrivateKey reads the private key archived by the last confirmed rollover.
// It returns (nil, nil) when there is no archived key.
func (s *AccountsStorage) ReadArchivedPrivateKey(account *Account) (crypto.Signer, error) {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return nil, err
	}

	privateKey, err := ReadPrivateKeyFile(paths.archivedKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("read the archived private key %q: %w", paths.archivedKey, err)
	}

	return privateKey, nil
}

// PrivateKeyThumbprint returns the JWK thumbprint of a private key read from a PEM file.
func PrivateKeyThumbprint(filename string) (string, error) {
	privateKey, err := ReadPrivateKeyFile(filename)
	if err != nil {
		return "", err
	}

	return KeyThumbprint(privateKey)
}

// CommitKeyRollover finalizes a confirmed key rollover on the local storage:
//   - archives the previous (old) private key,
//   - installs the pending new private key as the current key,
//   - synchronizes the account file (key material and key type),
//   - and removes the pending generation state and staging files.
//
// It is idempotent: it can be safely called again after a crash at any step.
// The old key is only archived at this point, i.e. after the remote change has been confirmed.
func (s *AccountsStorage) CommitKeyRollover(account *Account, state *KeyRolloverState, newKey crypto.Signer) error {
	paths, err := s.keyRolloverPaths(account)
	if err != nil {
		return err
	}

	newThumbprint, err := KeyThumbprint(newKey)
	if err != nil {
		return err
	}

	if state.NewKeyThumbprint != "" && state.NewKeyThumbprint != newThumbprint {
		return errors.New("the new private key does not match the key recorded in the pending rollover state")
	}

	if err = installRolloverKey(paths, state, newKey, newThumbprint); err != nil {
		return err
	}

	return s.finalizeCommittedRollover(account, state, paths, newThumbprint)
}

// finalizeCommittedRollover verifies the installed key, synchronizes the account file,
// and removes the pending staging file and generation state (the commit point).
func (s *AccountsStorage) finalizeCommittedRollover(
	account *Account,
	state *KeyRolloverState,
	paths keyRolloverPaths,
	newThumbprint string,
) error {
	// Verify the installed key before touching the account file.
	installedKey, err := ReadPrivateKeyFile(paths.canonicalKey)
	if err != nil {
		return fmt.Errorf("verify the installed private key: %w", err)
	}

	installedThumbprint, err := KeyThumbprint(installedKey)
	if err != nil {
		return err
	}

	if installedThumbprint != newThumbprint {
		return errors.New("the installed private key does not match the confirmed new key")
	}

	account.SetPrivateKey(installedKey)

	if state.NewKeyType != "" && account.KeyType != state.NewKeyType {
		account.KeyType = state.NewKeyType
	}

	err = s.Save(account)
	if err != nil {
		return fmt.Errorf("synchronize the account file: %w", err)
	}

	// Commit point: remove the staging file (if it was not moved already) and the generation state.
	if err = os.Remove(paths.pendingKey); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the pending private key file: %w", err)
	}

	if err = os.Remove(paths.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the key rollover state file: %w", err)
	}

	return nil
}

// installRolloverKey archives the confirmed old key and installs the new key.
// It is a no-op when the new key is already the canonical key (interrupted commit resume).
func installRolloverKey(paths keyRolloverPaths, state *KeyRolloverState, newKey crypto.Signer, newThumbprint string) error {
	canonicalKey, err := ReadPrivateKeyFile(paths.canonicalKey)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read the current private key: %w", err)
	}

	if err == nil {
		canonicalThumbprint, thumbErr := KeyThumbprint(canonicalKey)
		if thumbErr != nil {
			return thumbErr
		}

		switch canonicalThumbprint {
		case newThumbprint:
			// The new key is already in place: the commit was interrupted after the key swap.
			return nil
		case state.OldKeyThumbprint, "":
			// The old key is still the current key: archive it before installing the new one.
		default:
			return errors.New("the current private key matches neither the old nor the new key of the pending rollover")
		}

		// The old key is archived only now, i.e. after the remote change has been confirmed.
		if err = os.Rename(paths.canonicalKey, paths.archivedKey); err != nil {
			return fmt.Errorf("archive the previous private key: %w", err)
		}
	}

	return placeNewPrivateKey(paths, newKey, newThumbprint)
}

// placeNewPrivateKey installs the new key from its staging file when available,
// or writes the provided key material otherwise.
func placeNewPrivateKey(paths keyRolloverPaths, newKey crypto.Signer, newThumbprint string) error {
	stagedKey, err := ReadPrivateKeyFile(paths.pendingKey)
	if err == nil {
		stagedThumbprint, thumbErr := KeyThumbprint(stagedKey)
		if thumbErr != nil {
			return thumbErr
		}

		if stagedThumbprint != newThumbprint {
			return errors.New("the staged private key does not match the key of the pending rollover state")
		}

		if err = os.Rename(paths.pendingKey, paths.canonicalKey); err != nil {
			return fmt.Errorf("install the new private key: %w", err)
		}

		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read the staged private key: %w", err)
	}

	err = writeFileAtomic(paths.canonicalKey, pem.EncodeToMemory(certcrypto.PEMBlock(newKey)))
	if err != nil {
		return fmt.Errorf("install the new private key: %w", err)
	}

	return nil
}

// writeFileAtomic writes data to filename via a temp file and an atomic rename,
// so that readers can never observe a partially written file.
func writeFileAtomic(filename string, data []byte) error {
	dir := filepath.Dir(filename)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	defer func() { _ = os.Remove(tmpName) }()

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()
		return err
	}

	if err = tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return err
	}

	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}

	if err = tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, filename)
}
