package http01

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderServer_GetAddress(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "var", "run", "test")

	testCases := []struct {
		desc     string
		server   *ProviderServer
		expected string
	}{
		{
			desc:     "TCP default address",
			server:   NewProviderServer("", ""),
			expected: ":80",
		},
		{
			desc:     "TCP with explicit port",
			server:   NewProviderServer("", "8080"),
			expected: ":8080",
		},
		{
			desc:     "TCP with host and port",
			server:   NewProviderServer("localhost", "8080"),
			expected: "localhost:8080",
		},
		{
			desc:     "UDS socket",
			server:   NewUnixProviderServer(sock, fs.ModeSocket|0o666),
			expected: sock,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			address := test.server.GetAddress()
			assert.Equal(t, test.expected, address)
		})
	}
}

func TestChallenge(t *testing.T) {
	server := tester.MockACMEServer().BuildHTTPS(t)

	providerServer := NewProviderServer("", "23457")

	validate := func(_ context.Context, _ *api.Core, _ string, chlng acme.Challenge) error {
		uri := "http://localhost" + providerServer.GetAddress() + ChallengePath(chlng.Token)

		resp, err := http.DefaultClient.Get(uri)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			t.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			t.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:23457",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http1"},
		},
	}

	err = solver.Solve(t.Context(), authz)
	require.NoError(t, err)
}

func TestChallengeUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only for UNIX systems")
	}

	server := tester.MockACMEServer().BuildHTTPS(t)

	dir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "lego-challenge-test.sock")

	providerServer := NewUnixProviderServer(socket, fs.ModeSocket|0o666)

	validate := func(_ context.Context, _ *api.Core, _ string, chlng acme.Challenge) error {
		// any uri will do, as we hijack the dial
		uri := "http://localhost" + ChallengePath(chlng.Token)

		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		}}

		resp, err := client.Get(uri)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			t.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			t.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http1"},
		},
	}

	err = solver.Solve(t.Context(), authz)
	require.NoError(t, err)
}

func TestChallengeInvalidPort(t *testing.T) {
	server := tester.MockACMEServer().BuildHTTPS(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	validate := func(_ context.Context, _ *api.Core, _ string, _ acme.Challenge) error { return nil }

	solver := NewChallenge(core, validate, NewProviderServer("", "123456"))

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:123456",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http2"},
		},
	}

	err = solver.Solve(t.Context(), authz)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
	assert.Contains(t, err.Error(), "123456")
}

type testProxyHeader struct {
	name   string
	values []string
}

func newTestProxyHeader(name string, values ...string) *testProxyHeader {
	return &testProxyHeader{name: textproto.CanonicalMIMEHeaderKey(name), values: values}
}

func (h *testProxyHeader) update(r *http.Request) {
	if h == nil || len(h.values) == 0 {
		return
	}

	if h.name == "Host" {
		r.Host = h.values[0]
	} else if h.name != "" {
		r.Header[h.name] = h.values
	}
}

func TestChallengeWithProxy(t *testing.T) {
	const (
		ok   = "localhost:23457"
		nook = "example.com"
	)

	testCases := []struct {
		name   string
		header *testProxyHeader
		extra  *testProxyHeader
		isErr  bool
	}{
		// tests for hostMatcher
		{
			name: "no proxy",
		},
		{
			name:   "empty string",
			header: newTestProxyHeader(""),
		},
		{
			name:   "empty Host",
			header: newTestProxyHeader("host"),
		},
		{
			name:   "matching Host",
			header: newTestProxyHeader("host", ok),
		},
		{
			name:   "Host mismatch",
			header: newTestProxyHeader("host", nook),
			isErr:  true,
		},
		{
			name:   "Host mismatch (ignoring forwarding header)",
			header: newTestProxyHeader("host", nook),
			extra:  newTestProxyHeader("X-Forwarded-Host", ok),
			isErr:  true,
		},
		// test for arbitraryMatcher
		{
			name:   "matching X-Forwarded-Host",
			header: newTestProxyHeader("X-Forwarded-Host", ok),
		},
		{
			name:   "matching X-Forwarded-Host (multiple fields)",
			header: newTestProxyHeader("X-Forwarded-Host", ok, nook),
		},
		{
			name:   "matching X-Forwarded-Host (chain value)",
			header: newTestProxyHeader("X-Forwarded-Host", ok+", "+nook),
		},
		{
			name:   "X-Forwarded-Host mismatch",
			header: newTestProxyHeader("X-Forwarded-Host", nook),
			extra:  newTestProxyHeader("host", ok),
			isErr:  true,
		},
		{
			name:   "X-Forwarded-Host mismatch (multiple fields)",
			header: newTestProxyHeader("X-Forwarded-Host", nook, ok),
			isErr:  true,
		},
		{
			name:   "matching X-Something-Else",
			header: newTestProxyHeader("X-Something-Else", ok),
		},
		{
			name:   "matching X-Something-Else (multiple fields)",
			header: newTestProxyHeader("X-Something-Else", ok, nook),
		},
		{
			name:   "matching X-Something-Else (chain value)",
			header: newTestProxyHeader("X-Something-Else", ok+", "+nook),
		},
		{
			name:   "X-Something-Else mismatch",
			header: newTestProxyHeader("X-Something-Else", nook),
			isErr:  true,
		},
		{
			name:   "X-Something-Else mismatch (multiple fields)",
			header: newTestProxyHeader("X-Something-Else", nook, ok),
			isErr:  true,
		},
		{
			name:   "X-Something-Else mismatch (chain value)",
			header: newTestProxyHeader("X-Something-Else", nook+", "+ok),
			isErr:  true,
		},
		// tests for forwardedHeader
		{
			name:   "matching Forwarded",
			header: newTestProxyHeader("Forwarded", fmt.Sprintf("host=%q;foo=bar", ok)),
		},
		{
			name:   "matching Forwarded (multiple fields)",
			header: newTestProxyHeader("Forwarded", fmt.Sprintf("host=%q", ok), "host="+nook),
		},
		{
			name:   "matching Forwarded (chain value)",
			header: newTestProxyHeader("Forwarded", fmt.Sprintf("host=%q, host=%s", ok, nook)),
		},
		{
			name:   "Forwarded mismatch",
			header: newTestProxyHeader("Forwarded", "host="+nook),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (missing information)",
			header: newTestProxyHeader("Forwarded", "for=127.0.0.1"),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (multiple fields)",
			header: newTestProxyHeader("Forwarded", "host="+nook, fmt.Sprintf("host=%q", ok)),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (chain value)",
			header: newTestProxyHeader("Forwarded", fmt.Sprintf("host=%s, host=%q", nook, ok)),
			isErr:  true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testServeWithProxy(t, test.header, test.extra, test.isErr)
		})
	}
}

func testServeWithProxy(t *testing.T, header, extra *testProxyHeader, expectError bool) {
	t.Helper()

	server := tester.MockACMEServer().BuildHTTPS(t)

	options := Options{Address: "localhost:23457"}

	if header != nil {
		options.ProxyHeaderName = header.name
	}

	providerServer := NewProviderServerWithOptions(options)

	validate := func(ctx context.Context, _ *api.Core, _ string, chlng acme.Challenge) error {
		uri := "http://" + providerServer.GetAddress() + ChallengePath(chlng.Token)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			return err
		}

		header.update(req)
		extra.update(req)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			return fmt.Errorf("GET(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			return fmt.Errorf("GET(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:23457",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http1"},
		},
	}

	err = solver.Solve(t.Context(), authz)
	if expectError {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

func TestChallengePath(t *testing.T) {
	testCases := []struct {
		desc     string
		token    string
		expected string
	}{
		{
			desc:     "simple",
			token:    "foo",
			expected: "/.well-known/acme-challenge/foo",
		},
		{
			desc:     "path",
			token:    "../../../../../../tmp/data",
			expected: "/.well-known/acme-challenge/invalid",
		},
		{
			desc:     "path starting with slash",
			token:    "/../../../../../../tmp/data",
			expected: "/.well-known/acme-challenge/invalid",
		},
		{
			desc:     "long path",
			token:    "/foo/foo/foo/foo/foo/foo/foo/../../../../../../tmp/data",
			expected: "/.well-known/acme-challenge/invalid",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.expected, ChallengePath(test.token))
			assert.Equal(t, test.expected, path.Clean(ChallengePath(test.token)))
		})
	}
}

// doChallengeRequest performs a GET request for the given token.
// When host is not empty it overrides the request Host header,
// and extra headers are added as-is.
// It returns the response status code and body.
func doChallengeRequest(t *testing.T, client *http.Client, addr, host, token string, extra ...[2]string) (int, string) {
	t.Helper()

	uri := "http://" + addr + ChallengePath(token)

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	require.NoError(t, err)

	if host != "" {
		req.Host = host
	}

	for _, header := range extra {
		req.Header.Set(header[0], header[1])
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(body)
}

func TestProviderServerMultipleTokens(t *testing.T) {
	const addr = "127.0.0.1:23460"

	providerServer := NewProviderServer("127.0.0.1", "23460")

	ctx := t.Context()

	const (
		domainA = "example-a.com"
		tokenA  = "token-a"
		keyA    = "key-authorization-a"

		domainB = "example-b.com"
		tokenB  = "token-b"
		keyB    = "key-authorization-b"
	)

	require.NoError(t, providerServer.Present(ctx, domainA, tokenA, keyA))
	require.NoError(t, providerServer.Present(ctx, domainB, tokenB, keyB))

	// Both tokens are served at the same time on the same listener,
	// the response is selected from the request path and validated against
	// the request domain.
	status, body := doChallengeRequest(t, http.DefaultClient, addr, domainA, tokenA)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyA, body)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	// A path/domain mismatch must not leak another authorization's key auth.
	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenA)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "TEST", body)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainA, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "TEST", body)

	// An unknown token behaves like the historical mux default: 404.
	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainA, "unknown-token")
	assert.Equal(t, http.StatusNotFound, status)

	// Cleaning up the first authorization only removes its own token.
	require.NoError(t, providerServer.CleanUp(ctx, domainA, tokenA, keyA))

	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainA, tokenA)
	assert.Equal(t, http.StatusNotFound, status)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	// Cleaning up an unknown token must not affect the remaining authorization.
	require.NoError(t, providerServer.CleanUp(ctx, "example-c.com", "token-c", keyB))

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	// The listener is closed only once the last authorization is cleaned up.
	require.NoError(t, providerServer.CleanUp(ctx, domainB, tokenB, keyB))

	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, 0, status)

	// The server can be reused for another order of authorizations.
	const (
		domainC = "example-c.com"
		tokenC  = "token-c"
		keyC    = "key-authorization-c"
	)

	require.NoError(t, providerServer.Present(ctx, domainC, tokenC, keyC))

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainC, tokenC)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyC, body)

	require.NoError(t, providerServer.CleanUp(ctx, domainC, tokenC, keyC))

	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainC, tokenC)
	assert.Equal(t, 0, status)

	// CleanUp without any presented authorization is a no-op.
	require.NoError(t, providerServer.CleanUp(ctx, domainC, tokenC, keyC))
}

func TestProviderServerCancellationIsolation(t *testing.T) {
	const addr = "127.0.0.1:23461"

	providerServer := NewProviderServer("127.0.0.1", "23461")

	ctxA, cancelA := context.WithCancel(t.Context())
	ctxB, cancelB := context.WithCancel(t.Context())

	const (
		domainA = "example-a.com"
		tokenA  = "token-a"
		keyA    = "key-authorization-a"

		domainB = "example-b.com"
		tokenB  = "token-b"
		keyB    = "key-authorization-b"
	)

	require.NoError(t, providerServer.Present(ctxA, domainA, tokenA, keyA))
	require.NoError(t, providerServer.Present(ctxB, domainB, tokenB, keyB))

	// Giving up authorization A must not disturb the shared listener
	// nor authorization B.
	cancelA()

	status, body := doChallengeRequest(t, http.DefaultClient, addr, domainA, tokenA)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyA, body)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	// CleanUp with the already canceled context still only removes token A.
	require.NoError(t, providerServer.CleanUp(ctxA, domainA, tokenA, keyA))

	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainA, tokenA)
	assert.Equal(t, http.StatusNotFound, status)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	cancelB()

	require.NoError(t, providerServer.CleanUp(ctxB, domainB, tokenB, keyB))

	status, _ = doChallengeRequest(t, http.DefaultClient, addr, domainB, tokenB)
	assert.Equal(t, 0, status)
}

func TestProviderServerParallel(t *testing.T) {
	const (
		addr = "127.0.0.1:23462"
		n    = 16
	)

	providerServer := NewProviderServer("127.0.0.1", "23462")

	var (
		wg     sync.WaitGroup
		errMu  sync.Mutex
		failed bool
	)

	markFailed := func() {
		errMu.Lock()
		failed = true
		errMu.Unlock()
	}

	for i := range n {
		domain := fmt.Sprintf("example-%d.com", i)
		token := fmt.Sprintf("token-%d", i)
		keyAuth := fmt.Sprintf("key-authorization-%d", i)

		wg.Go(func() {
			ctx := t.Context()

			err := providerServer.Present(ctx, domain, token, keyAuth)
			if err != nil {
				markFailed()
				return
			}

			status, body := doChallengeRequest(t, http.DefaultClient, addr, domain, token)
			if status != http.StatusOK || body != keyAuth {
				markFailed()
			}

			err = providerServer.CleanUp(ctx, domain, token, keyAuth)
			if err != nil {
				markFailed()
			}
		})
	}

	wg.Wait()

	assert.False(t, failed, "at least one parallel authorization failed to be served")

	// All authorizations are cleaned up, the shared listener must be closed.
	status, _ := doChallengeRequest(t, http.DefaultClient, addr, "example-0.com", "token-0")
	assert.Equal(t, 0, status)
}

func TestProviderServerMultipleTokensWithProxyHeader(t *testing.T) {
	const addr = "127.0.0.1:23464"

	providerServer := NewProviderServerWithOptions(Options{
		Address:         addr,
		ProxyHeaderName: "X-Forwarded-Host",
	})

	ctx := t.Context()

	const (
		domainA = "example-a.com"
		tokenA  = "token-a"
		keyA    = "key-authorization-a"

		domainB = "example-b.com"
		tokenB  = "token-b"
		keyB    = "key-authorization-b"
	)

	require.NoError(t, providerServer.Present(ctx, domainA, tokenA, keyA))
	require.NoError(t, providerServer.Present(ctx, domainB, tokenB, keyB))

	status, body := doChallengeRequest(t, http.DefaultClient, addr, addr, tokenA, [2]string{"X-Forwarded-Host", domainA})
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyA, body)

	status, body = doChallengeRequest(t, http.DefaultClient, addr, addr, tokenB, [2]string{"X-Forwarded-Host", domainB})
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	// The proxy header selects the authorization:
	// token A presented through B's host must fail the domain check.
	status, body = doChallengeRequest(t, http.DefaultClient, addr, addr, tokenA, [2]string{"X-Forwarded-Host", domainB})
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "TEST", body)

	require.NoError(t, providerServer.CleanUp(ctx, domainA, tokenA, keyA))
	require.NoError(t, providerServer.CleanUp(ctx, domainB, tokenB, keyB))
}

func TestProviderServerMultipleTokensUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only for UNIX systems")
	}

	dir := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "lego-challenge-parallel-test.sock")

	providerServer := NewUnixProviderServer(socket, fs.ModeSocket|0o666)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socket)
		},
	}}

	ctx := t.Context()

	const (
		domainA = "example-a.com"
		tokenA  = "token-a"
		keyA    = "key-authorization-a"

		domainB = "example-b.com"
		tokenB  = "token-b"
		keyB    = "key-authorization-b"
	)

	require.NoError(t, providerServer.Present(ctx, domainA, tokenA, keyA))
	require.NoError(t, providerServer.Present(ctx, domainB, tokenB, keyB))

	// addr/host are ignored by the dialer hijack.
	status, body := doChallengeRequest(t, client, "localhost", domainA, tokenA)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyA, body)

	status, body = doChallengeRequest(t, client, "localhost", domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	require.NoError(t, providerServer.CleanUp(ctx, domainA, tokenA, keyA))

	status, _ = doChallengeRequest(t, client, "localhost", domainA, tokenA)
	assert.Equal(t, http.StatusNotFound, status)

	status, body = doChallengeRequest(t, client, "localhost", domainB, tokenB)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, keyB, body)

	require.NoError(t, providerServer.CleanUp(ctx, domainB, tokenB, keyB))
}

// TestChallengeParallelFailureIsolation ensures that when two HTTP-01
// authorizations are solved concurrently, a validation failure for one
// authorization does not prevent the other one from being served and solved.
func TestChallengeParallelFailureIsolation(t *testing.T) {
	server := tester.MockACMEServer().BuildHTTPS(t)

	const addr = "127.0.0.1:23463"

	providerServer := NewProviderServer("127.0.0.1", "23463")

	validate := func(_ context.Context, _ *api.Core, domain string, chlng acme.Challenge) error {
		status, body := doChallengeRequest(t, http.DefaultClient, addr, domain, chlng.Token)
		if status != http.StatusOK || body != chlng.KeyAuthorization {
			return fmt.Errorf("unexpected challenge response: status=%d body=%q", status, body)
		}

		if chlng.Token == "token-fail" {
			return errors.New("simulated validation failure")
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authzFail := acme.Authorization{
		Identifier: acme.Identifier{Value: "example-fail.com"},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "token-fail"},
		},
	}

	authzOK := acme.Authorization{
		Identifier: acme.Identifier{Value: "example-ok.com"},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "token-ok"},
		},
	}

	var (
		wg      sync.WaitGroup
		errFail error
		errOK   error
	)

	wg.Go(func() {
		errFail = solver.Solve(t.Context(), authzFail)
	})

	wg.Go(func() {
		errOK = solver.Solve(t.Context(), authzOK)
	})

	wg.Wait()

	require.Error(t, errFail)
	assert.Contains(t, errFail.Error(), "simulated validation failure")
	assert.NoError(t, errOK)
}
