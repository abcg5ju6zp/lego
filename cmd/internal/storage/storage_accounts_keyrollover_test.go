package storage

import (
	"crypto"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKeyRolloverTestAccount(t *testing.T, store *AccountsStorage, keyTypes ...certcrypto.KeyType) (*Account, *url.URL, crypto.Signer) {
	t.Helper()
	keyType := certcrypto.EC256
	if len(keyTypes) > 0 {
		keyType = keyTypes[0]
	}

	server, err := url.Parse("https://example.com/dir")
	require.NoError(t, err)

	account, err := store.Get(server.String(), keyType, "account@example.com", "")
	require.NoError(t, err)

	account.Registration = &acme.ExtendedAccount{
		Account: acme.Account{
			Status: acme.StatusValid,
			Orders: "https://example.com/acme/order/123456",
		},
		Location: "https://example.com/acme/acct/123456",
	}

	require.NoError(t, store.Save(account))

	oldPrivateKey := account.GetPrivateKey()

	return account, server, oldPrivateKey
}

func TestKeyThumbprint_stableAndDistinct(t *testing.T) {
	key1, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	require.NoError(t, err)

	key2, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	require.NoError(t, err)

	thumb1, err := KeyThumbprint(key1)
	require.NoError(t, err)

	thumb1Again, err := KeyThumbprint(key1)
	require.NoError(t, err)

	thumb2, err := KeyThumbprint(key2)
	require.NoError(t, err)

	assert.Equal(t, thumb1, thumb1Again)
	assert.NotEqual(t, thumb1, thumb2)
}

func TestAccountsStorage_PendingKeyRolloverState_lifecycle(t *testing.T) {
	store := NewAccountsStorage(t.TempDir())

	account, _, _ := newKeyRolloverTestAccount(t, store, certcrypto.EC256)

	state, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	assert.Nil(t, state)

	state = &KeyRolloverState{
		Phase:      KeyRolloverPhaseRemote,
		AccountURL: account.Registration.Location,
		StartedAt:  time.Now().UTC(),
	}

	require.NoError(t, store.SaveKeyRolloverState(account, state))

	paths, err := store.keyRolloverPaths(account)
	require.NoError(t, err)
	require.FileExists(t, paths.state)

	loaded, err := store.GetKeyRolloverState(account)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, keyRolloverStateVersion, loaded.Version)
	assert.Equal(t, KeyRolloverPhaseRemote, loaded.Phase)
	assert.Equal(t, account.Registration.Location, loaded.AccountURL)
	assert.False(t, loaded.UpdatedAt.IsZero())

	require.NoError(t, store.DeleteKeyRolloverState(account))
	assert.NoFileExists(t, paths.state)

	// Deleting a missing state is a no-op.
	require.NoError(t, store.DeleteKeyRolloverState(account))
}

func TestAccountsStorage_PendingPrivateKey_isNeverCurrent(t *testing.T) {
	store := NewAccountsStorage(t.TempDir())

	account, server, oldKey := newKeyRolloverTestAccount(t, store, certcrypto.EC256)

	oldThumbprint, err := KeyThumbprint(oldKey)
	require.NoError(t, err)

	newKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	require.NoError(t, err)

	newThumbprint, err := KeyThumbprint(newKey)
	require.NoError(t, err)

	// Stage the unconfirmed new key.
	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	paths, err := store.keyRolloverPaths(account)
	require.NoError(t, err)
	require.FileExists(t, paths.pendingKey)

	// While the rollover is unconfirmed, the loaded account must keep using the old (current) key.
	reloaded, err := store.Get(server.String(), certcrypto.EC256, "account@example.com", "")
	require.NoError(t, err)

	currentThumbprint, err := KeyThumbprint(reloaded.GetPrivateKey())
	require.NoError(t, err)
	assert.Equal(t, oldThumbprint, currentThumbprint)
	assert.NotEqual(t, newThumbprint, currentThumbprint)

	// The staged key is readable on its own and matches the new key.
	staged, err := store.ReadPendingPrivateKey(account)
	require.NoError(t, err)

	stagedThumbprint, err := KeyThumbprint(staged)
	require.NoError(t, err)
	assert.Equal(t, newThumbprint, stagedThumbprint)

	// The canonical file was never overwritten.
	assert.Equal(t, paths.canonicalKey, store.getAccountKeyPath(server, account.GetID()))
}

func TestAccountsStorage_CommitKeyRollover_installsNewKeyAndArchivesOld(t *testing.T) {
	store := NewAccountsStorage(t.TempDir())

	account, server, oldKey := newKeyRolloverTestAccount(t, store, certcrypto.EC256)

	oldThumbprint, err := KeyThumbprint(oldKey)
	require.NoError(t, err)

	newKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	require.NoError(t, err)

	newThumbprint, err := KeyThumbprint(newKey)
	require.NoError(t, err)

	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	state := &KeyRolloverState{
		Phase:            KeyRolloverPhaseLocal,
		AccountURL:       account.Registration.Location,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		NewKeyType:       certcrypto.RSA2048,
		StartedAt:        time.Now().UTC(),
	}
	require.NoError(t, store.SaveKeyRolloverState(account, state))

	require.NoError(t, store.CommitKeyRollover(account, state, newKey))

	paths, err := store.keyRolloverPaths(account)
	require.NoError(t, err)

	// The generation is committed: state and staging files are gone.
	assert.NoFileExists(t, paths.state)
	assert.NoFileExists(t, paths.pendingKey)

	// The old key has been archived (only after the remote confirmation).
	require.FileExists(t, paths.archivedKey)

	// The canonical key is the new one.
	installed, err := ReadPrivateKeyFile(paths.canonicalKey)
	require.NoError(t, err)

	installedThumbprint, err := KeyThumbprint(installed)
	require.NoError(t, err)
	assert.Equal(t, newThumbprint, installedThumbprint)

	archived, err := ReadPrivateKeyFile(paths.archivedKey)
	require.NoError(t, err)

	archivedThumbprint, err := KeyThumbprint(archived)
	require.NoError(t, err)
	assert.Equal(t, oldThumbprint, archivedThumbprint)

	// The in-memory account and its persisted file are synchronized.
	assert.Equal(t, certcrypto.RSA2048, account.KeyType)

	reloaded, err := store.Get(server.String(), certcrypto.EC256, "account@example.com", "")
	require.NoError(t, err)

	reloadedThumbprint, err := KeyThumbprint(reloaded.GetPrivateKey())
	require.NoError(t, err)
	assert.Equal(t, newThumbprint, reloadedThumbprint)
	assert.Equal(t, certcrypto.RSA2048, reloaded.KeyType)
	assert.False(t, reloaded.NeedsRecovery)
}

func TestAccountsStorage_CommitKeyRollover_idempotentAfterInterruption(t *testing.T) {
	store := NewAccountsStorage(t.TempDir())

	account, server, oldKey := newKeyRolloverTestAccount(t, store, certcrypto.EC256)

	oldThumbprint, err := KeyThumbprint(oldKey)
	require.NoError(t, err)

	newKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC384)
	require.NoError(t, err)

	newThumbprint, err := KeyThumbprint(newKey)
	require.NoError(t, err)

	state := &KeyRolloverState{
		Phase:            KeyRolloverPhaseLocal,
		AccountURL:       account.Registration.Location,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		NewKeyType:       certcrypto.EC384,
		StartedAt:        time.Now().UTC(),
	}
	require.NoError(t, store.SaveKeyRolloverState(account, state))

	paths, err := store.keyRolloverPaths(account)
	require.NoError(t, err)

	// Simulate a crash after the key swap but before the state was removed:
	// canonical key is the new one, old key is archived, staging file is gone.
	require.NoError(t, os.Rename(paths.canonicalKey, paths.archivedKey))

	err = writeFileAtomic(paths.canonicalKey, certcrypto.PEMEncode(newKey))
	require.NoError(t, err)

	assert.NoFileExists(t, paths.pendingKey)

	require.NoError(t, store.CommitKeyRollover(account, state, newKey))

	postPaths, err := store.keyRolloverPaths(account)
	require.NoError(t, err)
	assert.NoFileExists(t, postPaths.state)

	reloaded, err := store.Get(server.String(), certcrypto.EC256, "account@example.com", "")
	require.NoError(t, err)

	reloadedThumbprint, err := KeyThumbprint(reloaded.GetPrivateKey())
	require.NoError(t, err)
	assert.Equal(t, newThumbprint, reloadedThumbprint)
	assert.Equal(t, certcrypto.EC384, reloaded.KeyType)
}

func TestAccountsStorage_CommitKeyRollover_rejectsUnexpectedCanonicalKey(t *testing.T) {
	store := NewAccountsStorage(t.TempDir())

	account, _, oldKey := newKeyRolloverTestAccount(t, store, certcrypto.EC256)

	oldThumbprint, err := KeyThumbprint(oldKey)
	require.NoError(t, err)

	newKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	require.NoError(t, err)

	newThumbprint, err := KeyThumbprint(newKey)
	require.NoError(t, err)

	require.NoError(t, store.WritePendingPrivateKey(account, newKey))

	state := &KeyRolloverState{
		Phase:            KeyRolloverPhaseLocal,
		AccountURL:       account.Registration.Location,
		OldKeyThumbprint: oldThumbprint,
		NewKeyThumbprint: newThumbprint,
		StartedAt:        time.Now().UTC(),
	}

	// Replace the canonical key with an unrelated third key.
	unexpectedKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	require.NoError(t, err)

	account.SetPrivateKey(unexpectedKey)
	require.NoError(t, store.SavePrivateKey(account))

	err = store.CommitKeyRollover(account, state, newKey)
	require.Error(t, err)

	// Nothing was committed: the new key is not installed and the account was not changed.
	reloadedAccount, err := store.Get("https://example.com/dir", certcrypto.EC256, "account@example.com", "")
	require.NoError(t, err)

	unexpectedThumbprint, err := KeyThumbprint(unexpectedKey)
	require.NoError(t, err)

	currentThumbprint, err := KeyThumbprint(reloadedAccount.GetPrivateKey())
	require.NoError(t, err)
	assert.Equal(t, unexpectedThumbprint, currentThumbprint)
}
