package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Endpoint paths. The two .well-known documents sit at their RFC-mandated paths
// (they cannot move); the AS endpoints we own are namespaced under /oauth/.
const (
	ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
	AuthServerMetadataPath        = "/.well-known/oauth-authorization-server"
	RegisterPath                  = "/oauth/register"
	AuthorizePath                 = "/oauth/authorize"
	TokenPath                     = "/oauth/token"
)

const (
	defaultTokenTTL    = time.Hour
	defaultAuthCodeTTL = time.Minute
	defaultScope       = "mcp"
)

// Config configures the local OAuth server (the self-contained AS + RS).
type Config struct {
	// Store persists the layer's secrets/state. Required.
	Store SecretStore
	// PublicURL is the server's canonical, externally-reachable https URL — the
	// issuer, and the base from which the .well-known + /oauth endpoints are
	// served. Required.
	PublicURL string
	// Resource is the canonical identifier of the protected resource: the MCP
	// endpoint URL including its path (e.g. https://host/mcp). It is the token
	// audience and the `resource` advertised in Protected Resource Metadata.
	// A client binds the audience to the exact endpoint it calls, so this must
	// be the /mcp URL, not the bare host. Defaults to PublicURL when empty.
	Resource string
	// TokenTTL is the access-token lifetime (default 1h).
	TokenTTL time.Duration
	// Scopes advertised in metadata (default ["mcp"]).
	Scopes []string
	// Enrollment, when set, lets a named principal with no binding enroll
	// their downstream credentials in the browser during the approval step
	// (design-docs/enrollment.md). Optional; nil leaves the flow unchanged.
	Enrollment *Enrollment
}

// Server is the self-contained local OAuth Authorization Server and Resource
// Server. It mints its own audience-bound tokens, gates /mcp behind them, and
// serves the discovery + authorization endpoints a remote MCP client drives.
type Server struct {
	publicURL  string
	resource   string
	scopes     []string
	issuer     *Issuer
	pairing    *Pairing
	codes      *authCodeStore
	clients    *clientRegistry
	refresh    *refreshStore
	enrollment *Enrollment
}

// New validates cfg and builds the server, loading or generating its signing key
// and pairing code from the store.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("oauth: Config.Store is required")
	}
	if strings.TrimSpace(cfg.PublicURL) == "" {
		return nil, errors.New("oauth: Config.PublicURL is required")
	}
	publicURL := strings.TrimRight(cfg.PublicURL, "/")
	resource := strings.TrimRight(cfg.Resource, "/")
	if resource == "" {
		resource = publicURL
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{defaultScope}
	}

	if cfg.Enrollment != nil {
		if err := cfg.Enrollment.validate(); err != nil {
			return nil, err
		}
	}

	// Tokens are bound to the resource (the /mcp endpoint), so the client — which
	// binds the audience to the exact URL it calls — accepts them.
	issuer, err := NewIssuer(cfg.Store, publicURL, resource, ttl)
	if err != nil {
		return nil, err
	}
	return &Server{
		publicURL:  publicURL,
		resource:   resource,
		scopes:     scopes,
		issuer:     issuer,
		pairing:    NewPairing(cfg.Store),
		codes:      newAuthCodeStore(defaultAuthCodeTTL),
		clients:    newClientRegistry(cfg.Store),
		refresh:    newRefreshStore(cfg.Store),
		enrollment: cfg.Enrollment,
	}, nil
}

// PairingCode returns the current pairing code (generating it on first use), for
// the boot banner that tells the operator what to enter at /authorize.
func (s *Server) PairingCode() (string, error) { return s.pairing.Code() }

// RegisterRoutes mounts the discovery and authorization endpoints on mux. The
// authorization endpoints stay namespaced under /oauth/; a spec-compliant client
// finds them through the authorization-server metadata.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc(ProtectedResourceMetadataPath, s.handleProtectedResourceMetadata)
	if p := s.resourcePath(); p != "" {
		// RFC 9728 locates a path-bearing resource's metadata at
		// /.well-known/oauth-protected-resource<path>; some clients construct
		// that URL themselves instead of following the challenge's
		// resource_metadata, so serve it there too.
		mux.HandleFunc(ProtectedResourceMetadataPath+p, s.handleProtectedResourceMetadata)
	}
	mux.HandleFunc(AuthServerMetadataPath, s.handleAuthServerMetadata)
	mux.HandleFunc(RegisterPath, s.handleRegister)
	mux.HandleFunc(AuthorizePath, s.handleAuthorize)
	mux.HandleFunc(TokenPath, s.handleToken)
}

// Protect is the Resource-Server middleware: it requires a valid bearer token
// on the wrapped handler (the /mcp endpoint) and attaches the token's
// identity to the request context (PrincipalFrom), otherwise answering 401
// with a WWW-Authenticate pointing at the protected-resource metadata so the
// client can start the OAuth discovery.
func (s *Server) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			s.challenge(w, "missing bearer token")
			return
		}
		v, err := s.issuer.Validate(token)
		if err != nil {
			s.challenge(w, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), *v)))
	})
}

// challenge writes the 401 + WWW-Authenticate that bootstraps discovery.
func (s *Server) challenge(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer resource_metadata=%q", s.prmURL()))
	writeOAuthError(w, http.StatusUnauthorized, "invalid_token", desc)
}

// resourcePath is the path component of the resource identifier (e.g. "/mcp"),
// or "" when the resource is the bare host.
func (s *Server) resourcePath() string {
	if p := strings.TrimPrefix(s.resource, s.publicURL); p != "/" {
		return p
	}
	return ""
}

// prmURL is the Protected Resource Metadata URL advertised in the 401 challenge —
// path-suffixed (per RFC 9728) when the resource carries a path.
func (s *Server) prmURL() string {
	return s.publicURL + ProtectedResourceMetadataPath + s.resourcePath()
}
