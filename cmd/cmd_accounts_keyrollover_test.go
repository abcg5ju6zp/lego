package cmd

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/cmd/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRolloverServer     = "https://example.com/dir"
	testRolloverEmail      = "account@example.com"
	testRolloverAccountURL = "https://example.com/acme/acct/123456"
	testRolloverOrdersURL  = "https://example.com/acme/order/123456"
)

func setupRolloverAccount(t *testing.T) (*storage.AccountsStorage, *storage.Account) {
	t.Helper()

	store := storage.NewAccountsStorage(t.TempDir())

	account, err := store.Get(testRolloverServer, certcrypto.EC256, testRolloverEmail, "")
	require.NoError(t, err)

	account.Registration = &acme.ExtendedAccount{
		Account: acme.Account{
			Status: acme.StatusValid,
			Orders: testRolloverOrdersURL,
		},
		Location: testRolloverAccountURL,
	}

	require.NoError(t, store.Save(account))

	return store, account
}

func reloadRolloverAccount(t *testing.T, store *storage.AccountsStorage) *storage.Account {
	t.Helper()

	account, err := store.Get(testRolloverServer, certcrypto.EC256, testRolloverEmail, "")
	require.NoError(t, err)

	return account
}

func thumbOf(key crypto.Signer) string {
	thumbprint, err := storage.KeyThumbprint(key)
	if err != nil {
		panic(err)
	}

	return thumbprint
}

func mustThumbprint(t *testing.T, key crypto.Signer) string {
	t.Helper()

	thumbprint, err := storage.KeyThumbprint(key)
	require.NoError(t, err)

	return thumbprint
}

func generateTestKey(t *testing.T, keyType certcrypto.KeyType) crypto.Signer {
	t.Helper()

	key, err := certcrypto.GeneratePrivateKey(keyType)
	require.NoError(t, err)

	return key
}

// fakeRolloverRemote simulates the ACME server side of a key rollover.
// It tracks which key thumbprints authenticate the account.
type fakeRolloverRemote struct {
	mu       sync.Mutex
	accepted map[string]bool

	orders       string
	changeErr    error
	probeErr     error
	inconsistent bool

	changes int
	queries int

	onChange func(oldKey, newKey crypto.Signer)
}

type fakeRolloverService struct {
	remote *fakeRolloverRemote
	key    crypto.Signer
}

func (s *fakeRolloverService) QueryRegistration(_ context.Context) (*acme.ExtendedAccount, error) {
	s.remote.mu.Lock()
	s.remote.queries++
	s.remote.mu.Unlock()

	if s.remote.probeErr != nil {
		return nil, s.remote.probeErr
	}

	if s.remote.accepted[thumbOf(s.key)] {
		return &acme.ExtendedAccount{
			Account: acme.Account{Status: acme.StatusValid, Orders: s.remote.orders},
		}, nil
	}

	return nil, &acme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: acme.UnauthorizedErrorType}
}

func (s *fakeRolloverService) KeyRolloverResult(_ context.Context, newKey crypto.Signer) (acme.Account, error) {
	if s.remote.onChange != nil {
		s.remote.onChange(s.key, newKey)
	}

	s.remote.mu.Lock()
	defer s.remote.mu.Unlock()

	s.remote.changes++

	if s.remote.changeErr != nil {
		err := s.remote.changeErr
		s.remote.changeErr = nil

		return acme.Account{}, err
	}

	oldThumbprint := thumbOf(s.key)

	if !s.remote.accepted[oldThumbprint] {
		return acme.Account{}, &acme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: acme.UnauthorizedErrorType}
	}

	s.remote.accepted[oldThumbprint] = false
	s.remote.accepted[thumbOf(newKey)] = true

	orders := s.remote.orders
	if s.remote.inconsistent {
		orders = "https://example.com/acme/order/someone-else"
	}

	return acme.Account{Status: acme.StatusValid, Orders: orders}, nil
}

func (r *fakeRolloverRemote) factory(key crypto.Signer) (keyRolloverService, error) {
	return &fakeRolloverService{remote: r, key: key}, nil
}

func TestExecuteKeyRollover_happyPath_pendingStateVisibleDuringRemoteCall(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.RSA2048)
	newThumbprint := mustThumbprint(t, newKey)

	remote := &fakeRolloverRemote{
		accepted: map[string]bool{oldThumbprint: true},
		orders:   testRolloverOrdersURL,
		onChange: func(_, _ crypto.Signer) {
			// While the remote call runs, the pending generation must be fully recorded,
			// and the current account key must still be the unconfirmed old key.
			staged, err := store.ReadPendingPrivateKey(account)
			require.NoError(t, err)
			assert.Equal(t, newThumbprint, mustThumbprint(t, staged))

			state, err := store.GetKeyRolloverState(account)
			require.NoError(t, err)
			require.NotNil(t, state)
			assert.Equal(t, storage.KeyRolloverPhaseRemote, state.Phase)
			assert.Equal(t, testRolloverAccountURL, state.AccountURL)
			assert.Equal(t, oldThumbprint, state.OldKeyThumbprint)
			assert.Equal(t, newThumbprint, state.NewKeyThumbprint)

			reloaded := reloadRolloverAccount(t, store)
			assert.Equal(t, oldThumbprint, mustThumbprint(t, reloaded.GetPrivateKey()),
				"the unconfirmed new key must not be exposed as the current key")
		},
	}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, newKey)
	require.NoError(t, err)

	assert.Equal(t, 1, remote.changes)

	// Committed: new key current, old key archived, state and staging files gone.
	final := reloadRolloverAccount(t, store)
	assert.Equal(t, newThumbprint, mustThumbprint(t, final.GetPrivateKey()))
	assert.Equal(t, certcrypto.RSA2048, final.KeyType)

	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)

	_, err = store.ReadPendingPrivateKey(account)
	assert.ErrorIs(t, err, os.ErrNotExist)

	archived, err := store.ReadArchivedPrivateKey(account)
	require.NoError(t, err)
	require.NotNil(t, archived)
	assert.Equal(t, oldThumbprint, mustThumbprint(t, archived))
}

func TestExecuteKeyRollover_remoteFailure_isResumableWithFreshlyGeneratedKey(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.RSA2048)
	newThumbprint := mustThumbprint(t, newKey)

	remote := &fakeRolloverRemote{
		accepted:  map[string]bool{oldThumbprint: true},
		orders:    testRolloverOrdersURL,
		changeErr: errors.New("connection reset by peer"),
	}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, newKey)
	require.Error(t, err)

	// The failed attempt keeps a resumable state and the staged key.
	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	require.NotNil(t, state)

	reloaded := reloadRolloverAccount(t, store)
	assert.Equal(t, oldThumbprint, mustThumbprint(t, reloaded.GetPrivateKey()))

	// A restart generates a brand new key: the recorded generation must still resume with the staged key.
	unrelatedKey := generateTestKey(t, certcrypto.EC384)

	err = executeKeyRollover(context.Background(), remote.factory, store, account, unrelatedKey)
	require.NoError(t, err)

	assert.Equal(t, 2, remote.changes)

	final := reloadRolloverAccount(t, store)
	assert.Equal(t, newThumbprint, mustThumbprint(t, final.GetPrivateKey()),
		"the resume must complete the recorded generation, not use the freshly generated key")
	assert.Equal(t, certcrypto.RSA2048, final.KeyType)

	state, err = store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestExecuteKeyRollover_resumeWhenServerAlreadyAcceptedNewKey(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.RSA2048)
	newThumbprint := mustThumbprint(t, newKey)

	// Simulate a crash after the remote accepted the new key but before local synchronization.
	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	require.NoError(t, store.SaveKeyRolloverState(account, &storage.KeyRolloverState{
		Phase:            storage.KeyRolloverPhaseRemote,
		AccountURL:       testRolloverAccountURL,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		NewKeyType:       certcrypto.RSA2048,
		StartedAt:        time.Now().UTC(),
	}))

	remote := &fakeRolloverRemote{
		accepted: map[string]bool{newThumbprint: true}, // only the new key is accepted
		orders:   testRolloverOrdersURL,
	}

	// The restart comes with an unrelated freshly generated key: it must be ignored.
	unrelatedKey := generateTestKey(t, certcrypto.EC384)

	err := executeKeyRollover(context.Background(), remote.factory, store, account, unrelatedKey)
	require.NoError(t, err)

	assert.Equal(t, 0, remote.changes, "the completed remote rollover must not be sent again")
	assert.GreaterOrEqual(t, remote.queries, 1)

	final := reloadRolloverAccount(t, store)
	assert.Equal(t, newThumbprint, mustThumbprint(t, final.GetPrivateKey()))
	assert.Equal(t, certcrypto.RSA2048, final.KeyType)

	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestExecuteKeyRollover_resumeAfterInterruptedLocalSwap(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.EC384)
	newThumbprint := mustThumbprint(t, newKey)

	// Prepare state + staged key, then simulate the atomic key swap without removing the state.
	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	state := &storage.KeyRolloverState{
		Phase:            storage.KeyRolloverPhaseLocal,
		AccountURL:       testRolloverAccountURL,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		NewKeyType:       certcrypto.EC384,
		StartedAt:        time.Now().UTC(),
	}
	require.NoError(t, store.SaveKeyRolloverState(account, state))

	matches, err := filepath.Glob(filepath.Join(store.GetRootPath(), "*", testRolloverEmail))
	require.NoError(t, err)
	require.Len(t, matches, 1)

	accountDir := matches[0]

	require.NoError(t, os.Rename(
		filepath.Join(accountDir, testRolloverEmail+".key"),
		filepath.Join(accountDir, testRolloverEmail+".key.archived"),
	))
	require.NoError(t, os.Rename(
		filepath.Join(accountDir, testRolloverEmail+".key.pending"),
		filepath.Join(accountDir, testRolloverEmail+".key"),
	))

	remote := &fakeRolloverRemote{
		accepted: map[string]bool{newThumbprint: true},
		orders:   testRolloverOrdersURL,
	}

	// Restart: reload the account from disk, where the canonical key is already the new one.
	restartedAccount := reloadRolloverAccount(t, store)
	assert.Equal(t, newThumbprint, mustThumbprint(t, restartedAccount.GetPrivateKey()))

	err = executeKeyRollover(context.Background(), remote.factory, store, restartedAccount, generateTestKey(t, certcrypto.EC256))
	require.NoError(t, err)

	assert.Equal(t, 0, remote.changes)

	final := reloadRolloverAccount(t, store)
	assert.Equal(t, newThumbprint, mustThumbprint(t, final.GetPrivateKey()))
	assert.Equal(t, certcrypto.EC384, final.KeyType)

	state, err = store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestExecuteKeyRollover_bothKeysRejected_keepsState(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.RSA2048)
	newThumbprint := mustThumbprint(t, newKey)

	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	state := &storage.KeyRolloverState{
		Phase:            storage.KeyRolloverPhaseRemote,
		AccountURL:       testRolloverAccountURL,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		StartedAt:        time.Now().UTC(),
	}
	require.NoError(t, store.SaveKeyRolloverState(account, state))

	remote := &fakeRolloverRemote{
		accepted: map[string]bool{}, // neither key is accepted
		orders:   testRolloverOrdersURL,
	}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, newKey)
	require.Error(t, err)

	assert.Equal(t, 0, remote.changes)

	loaded, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.NotNil(t, loaded, "the pending state must be kept for manual recovery")

	assert.Equal(t, oldThumbprint, mustThumbprint(t, reloadRolloverAccount(t, store).GetPrivateKey()))
}

func TestExecuteKeyRollover_inconclusiveProbe_keepsState(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldKey := account.GetPrivateKey()
	oldThumbprint := mustThumbprint(t, oldKey)

	newKey := generateTestKey(t, certcrypto.RSA2048)
	newThumbprint := mustThumbprint(t, newKey)

	require.NoError(t, store.WritePendingPrivateKey(account, newKey))
	require.NoError(t, store.SaveKeyRolloverState(account, &storage.KeyRolloverState{
		Phase:            storage.KeyRolloverPhaseRemote,
		AccountURL:       testRolloverAccountURL,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		StartedAt:        time.Now().UTC(),
	}))

	remote := &fakeRolloverRemote{
		accepted: map[string]bool{},
		orders:   testRolloverOrdersURL,
		probeErr: errors.New("network unreachable"),
	}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, newKey)
	require.Error(t, err)

	assert.Equal(t, 0, remote.changes)

	loaded, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.NotNil(t, loaded)
}

func TestExecuteKeyRollover_inconsistentResponse_keepsState(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldThumbprint := mustThumbprint(t, account.GetPrivateKey())
	newKey := generateTestKey(t, certcrypto.RSA2048)

	remote := &fakeRolloverRemote{
		accepted:     map[string]bool{oldThumbprint: true},
		orders:       testRolloverOrdersURL,
		inconsistent: true,
	}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, newKey)
	require.Error(t, err)

	loaded, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.NotNil(t, loaded, "an inconsistent response is an uncertain outcome: the state must be kept")
}

func TestExecuteKeyRollover_sameKeyIsNoOp(t *testing.T) {
	store, account := setupRolloverAccount(t)

	oldThumbprint := mustThumbprint(t, account.GetPrivateKey())

	remote := &fakeRolloverRemote{accepted: map[string]bool{oldThumbprint: true}}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, account.GetPrivateKey())
	require.NoError(t, err)

	assert.Equal(t, 0, remote.changes)

	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestExecuteKeyRollover_unregisteredAccountFails(t *testing.T) {
	store, account := setupRolloverAccount(t)

	account.Registration = nil
	require.NoError(t, store.Save(account))

	remote := &fakeRolloverRemote{accepted: map[string]bool{}}

	err := executeKeyRollover(context.Background(), remote.factory, store, account, generateTestKey(t, certcrypto.EC256))
	require.Error(t, err)

	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)
}
