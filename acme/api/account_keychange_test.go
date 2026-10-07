package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountService_KeyChange_returnsResponseAccount(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "https://example.com/acme/acct/1"

	server := tester.MockACMEServer().
		Route("POST /keyChange", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			servermock.JSONEncode(acme.Account{
				Status:  acme.StatusValid,
				Orders:  "https://example.com/acme/order/1",
				Contact: []string{"mailto:account@example.com"},
			}).ServeHTTP(rw, req)
		})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", kid, oldKey)
	require.NoError(t, err)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	account, err := core.Accounts.KeyChange(t.Context(), newKey)
	require.NoError(t, err)

	assert.Equal(t, acme.StatusValid, account.Status)
	assert.Equal(t, "https://example.com/acme/order/1", account.Orders)
	assert.Equal(t, []string{"mailto:account@example.com"}, account.Contact)
}

func TestAccountService_KeyChange_emptyBodyResponse(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "https://example.com/acme/acct/1"

	// Some servers (e.g. Pebble) answer a successful key change with an empty 200 body.
	server := tester.MockACMEServer().
		Route("POST /keyChange", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", kid, oldKey)
	require.NoError(t, err)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	account, err := core.Accounts.KeyChange(t.Context(), newKey)
	require.NoError(t, err)
	assert.Empty(t, account.Status)
}

func TestAccountService_KeyChange_malformedResponse(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "https://example.com/acme/acct/1"

	server := tester.MockACMEServer().
		Route("POST /keyChange", servermock.RawStringResponse("not-json")).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", kid, oldKey)
	require.NoError(t, err)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = core.Accounts.KeyChange(t.Context(), newKey)
	require.Error(t, err, "a malformed key change response must be reported so the caller keeps the pending state")
}

func TestAccountService_KeyChange_missingEndpoint(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := tester.MockACMEServer().BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "https://example.com/acme/acct/1", oldKey)
	require.NoError(t, err)

	core.directory.KeyChangeURL = ""

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = core.Accounts.KeyChange(t.Context(), newKey)
	require.Error(t, err)
}
