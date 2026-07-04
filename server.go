package oauth

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"slices"
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
	// EnrollmentForResource, when set, selects the enrollment per requested
	// resource — the multi-tool host case, where each mount has its own
	// descriptor and its own bridge to the tool's callback. It takes precedence
	// over Enrollment; returning nil means that resource has no enrollment
	// (unbound principals are simply not diverted). Results must be
	// pre-validated with (*Enrollment).Validate — typically once at boot.
	EnrollmentForResource func(resource string) *Enrollment
	// Asymmetric makes the server sign with an Ed25519 key instead of the
	// default HS256, so delegate resource servers (mounted tools) can validate
	// its tokens with only the public key. The multi-tool host sets this;
	// single-tool `--oauth local` leaves it false (self-signed, self-validated).
	Asymmetric bool
	// BindingForResource, when set, transforms a principal's stored binding
	// into the binding a token for `resource` should carry. The multi-tool host
	// uses it to project a namespaced binding (slack:workspace=acme) down to the
	// vocabulary the mount understands (workspace=acme) — the token then reads
	// exactly as a single-tool token does. Nil passes the binding through
	// unchanged (single-tool mode).
	BindingForResource func(binding map[string]string, resource string) map[string]string
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

	enrollmentForResource func(string) *Enrollment
	bindingForResource    func(map[string]string, string) map[string]string
}

// enrollmentFor resolves which enrollment (if any) applies to an authorize
// request: per-resource in host mode, the single configured one otherwise.
func (s *Server) enrollmentFor(p authParams) *Enrollment {
	if s.enrollmentForResource == nil {
		return s.enrollment
	}
	resource, ok := s.resolveResource(p.resource)
	if !ok {
		return nil
	}
	return s.enrollmentForResource(resource)
}

// projectedBinding is the binding a token for this request's resource would
// carry — BindingForResource applied in host mode, the raw binding otherwise.
// The enrollment gate keys off THIS emptiness: a principal bound for lin but
// not slack is unbound from /slack/mcp's point of view.
func (s *Server) projectedBinding(binding map[string]string, p authParams) map[string]string {
	if s.bindingForResource == nil {
		return binding
	}
	resource, ok := s.resolveResource(p.resource)
	if !ok {
		return binding
	}
	return s.bindingForResource(binding, resource)
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
		if r = strings.TrimRight(r, "/"); r != "" && r != resource && !slices.Contains(resources, r) {
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

		enrollmentForResource: cfg.EnrollmentForResource,
		bindingForResource:    cfg.BindingForResource,
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
	if slices.Contains(s.resources, requested) {
		return requested, true
	}
	return "", false
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

// prmURL is the Protected Resource Metadata URL advertised in the 401 challenge —
// path-suffixed (per RFC 9728) when the resource carries a path.
func (s *Server) prmURL() string {
	return protectedResourceMetadataURL(s.publicURL, s.resource)
}
