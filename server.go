package oauth

import (
	"crypto/ed25519"
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
	// The default (first) audience in multi-resource mode.
	Resource string
	// Resources, when set, makes this a multi-audience Authorization Server:
	// the host case, where one AS fronts several tool mounts. Each entry is a
	// mount's /mcp URL; the AS mints a per-mount audience for the RFC 8707
	// `resource` a client requests, validated against this set. Resource (or
	// PublicURL) is prepended as the default if not already present. Empty
	// leaves the single-resource behavior unchanged.
	Resources []string
	// TokenTTL is the access-token lifetime (default 1h).
	TokenTTL time.Duration
	// Scopes advertised in metadata (default ["mcp"]).
	Scopes []string
	// Enrollment, when set, lets a named principal with no binding enroll
	// their downstream credentials in the browser during the approval step
	// (design-docs/enrollment.md). Optional; nil leaves the flow unchanged.
	Enrollment *Enrollment
	// Asymmetric makes the server sign with an Ed25519 key instead of the
	// default HS256, so delegate resource servers (mounted tools) can validate
	// its tokens with only the public key. The multi-tool host sets this;
	// single-tool `--oauth local` leaves it false (self-signed, self-validated).
	Asymmetric bool
}

// Server is the self-contained local OAuth Authorization Server and Resource
// Server. It mints its own audience-bound tokens, gates /mcp behind them, and
// serves the discovery + authorization endpoints a remote MCP client drives.
type Server struct {
	publicURL string
	resource  string   // the default (primary) audience
	resources []string // all audiences this AS may issue for (incl. resource)
	scopes    []string
	issuer    *Issuer
	pairing   *Pairing
	codes     *authCodeStore
	clients   *clientRegistry
	refresh   *refreshStore
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
	// The allowed audience set: the default resource plus any additional mounts
	// (multi-audience host mode). Deduped, default first.
	resources := []string{resource}
	for _, r := range cfg.Resources {
		if r = strings.TrimRight(r, "/"); r != "" && r != resource && !contains(resources, r) {
			resources = append(resources, r)
		}
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
	// binds the audience to the exact URL it calls — accepts them. The host signs
	// asymmetrically (Ed25519) so mounted tools verify with only its public key;
	// a single-tool server self-signs (HS256).
	newIssuer := NewIssuer
	if cfg.Asymmetric {
		newIssuer = NewEd25519Issuer
	}
	issuer, err := newIssuer(cfg.Store, publicURL, resource, ttl)
	if err != nil {
		return nil, err
	}
	return &Server{
		publicURL:  publicURL,
		resource:   resource,
		resources:  resources,
		scopes:     scopes,
		issuer:     issuer,
		pairing:    NewPairing(cfg.Store),
		codes:      newAuthCodeStore(defaultAuthCodeTTL),
		clients:    newClientRegistry(cfg.Store),
		refresh:    newRefreshStore(cfg.Store),
		enrollment: cfg.Enrollment,
	}, nil
}

// resolveResource maps a client's requested RFC 8707 `resource` to a validated
// audience: empty defaults to the primary resource (single-resource clients
// that omit it); a value must be one of the allowed audiences. ok=false means
// the request targeted a resource this server does not serve.
func (s *Server) resolveResource(requested string) (string, bool) {
	if requested == "" {
		return s.resource, true
	}
	requested = strings.TrimRight(requested, "/")
	if contains(s.resources, requested) {
		return requested, true
	}
	return "", false
}

// contains reports whether v is in xs.
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// PairingCode returns the current pairing code (generating it on first use), for
// the boot banner that tells the operator what to enter at /authorize.
func (s *Server) PairingCode() (string, error) { return s.pairing.Code() }

// PublicKey returns the server's Ed25519 public key when it signs
// asymmetrically (Config.Asymmetric), or nil otherwise. The host hands this to
// each mounted tool at spawn so the tool can validate the host's tokens.
func (s *Server) PublicKey() ed25519.PublicKey { return s.issuer.PublicKey() }

// RegisterRoutes mounts the discovery and authorization endpoints on mux. The
// authorization endpoints stay namespaced under /oauth/; a spec-compliant client
// finds them through the authorization-server metadata.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// The base well-known path serves the default resource's metadata.
	mux.HandleFunc(ProtectedResourceMetadataPath, func(w http.ResponseWriter, _ *http.Request) {
		s.writePRM(w, s.resource)
	})
	// RFC 9728 locates a path-bearing resource's metadata at the suffixed path;
	// some clients construct that URL themselves instead of following the
	// challenge's resource_metadata, so serve each allowed resource there too.
	// In multi-audience (host) mode this is one document per mount, each naming
	// its own resource.
	for _, res := range s.resources {
		res := res
		if suffix := resourceSuffix(s.publicURL, res); suffix != "" {
			mux.HandleFunc(ProtectedResourceMetadataPath+suffix, func(w http.ResponseWriter, _ *http.Request) {
				s.writePRM(w, res)
			})
		}
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
	return protectHandler(s.issuer.Validate, s.prmURL(), next)
}

// protectHandler gates next behind a valid, validate-passing bearer token,
// attaching the carried identity to the request context; otherwise it answers
// the 401 discovery challenge pointing at prmURL. Shared by the local Server
// and a delegate ResourceServer so the gate can't drift between them.
func protectHandler(validate func(string) (*Verified, error), prmURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			challengeUnauthorized(w, prmURL, "missing bearer token")
			return
		}
		v, err := validate(token)
		if err != nil {
			challengeUnauthorized(w, prmURL, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), *v)))
	})
}

// challengeUnauthorized writes the 401 + WWW-Authenticate that bootstraps
// discovery, pointing the client at prmURL for the protected-resource metadata.
func challengeUnauthorized(w http.ResponseWriter, prmURL, desc string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer resource_metadata=%q", prmURL))
	writeOAuthError(w, http.StatusUnauthorized, "invalid_token", desc)
}

// prmURL is the Protected Resource Metadata URL advertised in the 401 challenge —
// path-suffixed (per RFC 9728) when the resource carries a path.
func (s *Server) prmURL() string {
	return protectedResourceMetadataURL(s.publicURL, s.resource)
}

// resourceSuffix is the path of resource under base — e.g. "/mcp" — or "" when
// resource is the bare host (or base itself). Used both to mount the suffixed
// metadata route and to build the metadata URL, so the two agree.
func resourceSuffix(base, resource string) string {
	if p := strings.TrimPrefix(resource, base); p != "/" {
		return p
	}
	return ""
}

// protectedResourceMetadataURL builds the RFC 9728 metadata URL for a resource
// under base: base + the well-known path + the resource's path suffix. It is
// the single source for this security-relevant URL, shared by the local Server
// and a delegate ResourceServer — the URL a delegate challenges toward is the
// exact one the host's Server must serve, so the two cannot drift.
func protectedResourceMetadataURL(base, resource string) string {
	return base + ProtectedResourceMetadataPath + resourceSuffix(base, resource)
}
