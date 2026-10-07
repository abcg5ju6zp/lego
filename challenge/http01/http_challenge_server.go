package http01

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/log"
)

var _ challenge.Provider = (*ProviderServer)(nil)

type Options struct {
	Network         string
	NetworkStack    challenge.NetworkStack
	Address         string
	SocketMode      fs.FileMode
	ProxyHeaderName string
}

// challengeEntry holds the details of a single HTTP-01 authorization
// currently hosted by the server.
type challengeEntry struct {
	domain  string
	keyAuth string
}

// ProviderServer implements ChallengeProvider for `http-01` challenge.
// It may be instantiated without using the NewProviderServer function if
// you want only to use the default values.
//
// A single ProviderServer can host the tokens of several authorizations at
// the same time: the HTTP listener is started by the first Present call and
// is only closed once the last authorization has been cleaned up.
type ProviderServer struct {
	network string // must be valid argument to net.Listen
	address string

	socketMode fs.FileMode

	matcher domainMatcher

	mu       sync.Mutex
	tokens   map[string]challengeEntry
	listener net.Listener

	// done is closed when the goroutine running the shared HTTP server exits.
	done chan struct{}
}

// NewProviderServerWithOptions creates a new ProviderServer.
func NewProviderServerWithOptions(opts Options) *ProviderServer {
	if opts.Network == "" {
		opts.Network = "tcp"
	}

	return &ProviderServer{
		network:    opts.NetworkStack.Network(opts.Network),
		address:    opts.Address,
		socketMode: opts.SocketMode,
		matcher:    getMatcher(opts.ProxyHeaderName),
	}
}

// NewProviderServer creates a new ProviderServer on the selected interface and port.
// Setting host and / or port to an empty string will make the server fall back to
// the "any" interface and port 80 respectively.
func NewProviderServer(host, port string) *ProviderServer {
	if port == "" {
		// Fallback to port 80 if the port was not provided.
		port = "80"
	}

	return NewProviderServerWithOptions(Options{
		Network: "tcp",
		Address: net.JoinHostPort(host, port),
	})
}

// NewUnixProviderServer creates a new ProviderServer.
func NewUnixProviderServer(socketPath string, socketMode fs.FileMode) *ProviderServer {
	return NewProviderServerWithOptions(Options{
		Network:    "unix",
		Address:    socketPath,
		SocketMode: socketMode,
	})
}

// Present starts the shared web server (for the first authorization only)
// and makes the token available at `ChallengePath(token)` for web requests.
// Subsequent calls only register the additional token, they do not replace
// the challenges hosted for the other authorizations.
func (s *ProviderServer) Present(ctx context.Context, domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		err := s.start(context.WithoutCancel(ctx))
		if err != nil {
			return err
		}
	}

	s.tokens[token] = challengeEntry{domain: domain, keyAuth: keyAuth}

	return nil
}

// CleanUp removes the token from `ChallengePath(token)`.
// It only affects the authorization it is called for: the shared HTTP server
// keeps serving the other authorizations and is stopped once the last token
// has been removed.
func (s *ProviderServer) CleanUp(_ context.Context, _, token, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		return nil
	}

	// A CleanUp call must only remove its own token:
	// an unknown token (for example a failed or already cleaned up
	// authorization) must not tear down the server of other authorizations.
	if _, ok := s.tokens[token]; !ok {
		return nil
	}

	delete(s.tokens, token)

	if len(s.tokens) > 0 {
		return nil
	}

	// The last authorization is done, stop the shared server.
	// The mutex stays locked until the server is fully stopped,
	// so a concurrent Present cannot bind the address before it is released,
	// and it can restart a fresh server afterwards.
	listener := s.listener
	done := s.done

	s.listener = nil
	s.done = nil
	s.tokens = nil

	if err := listener.Close(); err != nil {
		return fmt.Errorf("close HTTP-01 challenge listener: %w", err)
	}

	<-done

	return nil
}

func (s *ProviderServer) GetAddress() string {
	return s.address
}

// start binds the shared listener and launches the HTTP serving goroutine.
// The context is intentionally detached from the caller: the listener is
// shared between all the presented authorizations, so canceling the context
// of a single authorization must not close it while other challenges are
// still being validated.
func (s *ProviderServer) start(ctx context.Context) error {
	var lc net.ListenConfig

	listener, err := lc.Listen(ctx, s.network, s.GetAddress())
	if err != nil {
		return fmt.Errorf("could not start HTTP server for challenge: %w", err)
	}

	if s.network == "unix" {
		if err = os.Chmod(s.address, s.socketMode); err != nil {
			_ = listener.Close()

			return fmt.Errorf("chmod %s: %w", s.address, err)
		}
	}

	s.listener = listener
	s.tokens = make(map[string]challengeEntry)
	s.done = make(chan struct{})

	go s.serve(listener, s.done)

	return nil
}

// getMatcher gets the matcher for incoming requests.
// By default, it matches the "Host" header value to the domain name.
//
// When the server runs behind a proxy server, this is not the correct place to look at;
// Apache and NGINX have traditionally moved the original Host header into a new header named "X-Forwarded-Host".
// Other webservers might use different names;
// and RFC7239 has standardized a new header named "Forwarded" (with slightly different semantics).
//
// The exact behavior depends on the value of proxyHeaderName:
// - "" (the empty string) and "Host" will restore the default and only check the Host header
// - "Forwarded" will look for a Forwarded header, and inspect it according to https://www.rfc-editor.org/rfc/rfc7239.html
// - any other value will check the header value with the same name.
func getMatcher(proxyHeaderName string) domainMatcher {
	switch h := textproto.CanonicalMIMEHeaderKey(proxyHeaderName); h {
	case "", "Host":
		return &hostMatcher{}
	case "Forwarded":
		return &forwardedMatcher{}
	default:
		return arbitraryMatcher(h)
	}
}

func (s *ProviderServer) serve(listener net.Listener, done chan<- struct{}) {
	defer close(done)

	// A single mux serves every hosted token:
	// the handler selects the key authorization from the request path
	// and validates the request domain to prevent DNS rebind attacks.
	mux := http.NewServeMux()
	mux.HandleFunc(PathPrefix, s.handleChallenge)

	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Once httpServer is shut down
	// we don't want any lingering connections, so disable KeepAlives.
	httpServer.SetKeepAlivesEnabled(false)

	err := httpServer.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Warn("http01: HTTP server serve.", log.ErrorAttr(err))
	}
}

func (s *ProviderServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, PathPrefix)

	s.mu.Lock()
	entry, found := s.tokens[token]
	s.mu.Unlock()

	// Unknown tokens get the default "not found" response,
	// matching the historical behavior where only the presented token path
	// was registered on the mux.
	if !found {
		http.NotFound(w, r)
		return
	}

	// The incoming request will be validated to prevent DNS rebind attacks.
	// We only respond with the keyAuth, when we're receiving a GET requests with
	// the "Host" header matching the domain (the latter is configurable though SetProxyHeader).
	if r.Method == http.MethodGet && s.matcher.matches(r, entry.domain) {
		w.Header().Set("Content-Type", "text/plain")

		_, err := w.Write([]byte(entry.keyAuth))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Debug("Served key authentication.", log.DomainAttr(entry.domain))

		return
	}

	log.Warn("http01: Received request but the domain did not match any challenge. Please ensure you are passing the header properly.",
		log.DomainAttr(r.Host),
		slog.String("method", r.Method),
		slog.String("header", s.matcher.name()),
	)

	_, err := w.Write([]byte("TEST"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
