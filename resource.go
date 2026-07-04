package oauth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ResourceServer is an RS-only OAuth gate for a tool mounted behind a separate
// Authorization Server — the multi-tool host. It validates the host's
// EdDSA-signed tokens for its own audience and 401-challenges toward the host's
// protected-resource metadata, but serves no AS routes, holds no signing key,
// and knows nothing about pairing or enrollment. A tool run with
// `--oauth <host-url>` (delegate mode) uses this; a tool run with
// `--oauth local` uses the full Server instead.
type ResourceServer struct {
	verifier *Issuer
	prmURL   string
}

// RSConfig configures a delegate ResourceServer.
type RSConfig struct {
	// IssuerURL is the host Authorization Server's public URL — the expected
	// `iss` on tokens and the base of the protected-resource-metadata URL the
	// 401 challenge points at. Required.
	IssuerURL string
	// Resource is this tool's audience: the exact mount URL a client calls,
	// e.g. https://host/slack/mcp. Tokens must carry this `aud`, and it must
	// sit under IssuerURL. Required.
	Resource string
	// VerifyKey is the host's Ed25519 public key, handed to the tool at spawn.
	// Required.
	VerifyKey ed25519.PublicKey
}

// NewResourceServer validates cfg and builds a delegate resource server. The
// protected-resource-metadata URL it challenges toward is derived as the host's
// RFC 9728 well-known path suffixed with the resource's path (so a client that
// constructs it directly finds it on the host).
func NewResourceServer(cfg RSConfig) (*ResourceServer, error) {
	issuerURL := strings.TrimRight(cfg.IssuerURL, "/")
	resource := strings.TrimRight(cfg.Resource, "/")
	if issuerURL == "" {
		return nil, errors.New("oauth: RSConfig.IssuerURL is required")
	}
	if resource == "" {
		return nil, errors.New("oauth: RSConfig.Resource is required")
	}
	if !strings.HasPrefix(resource, issuerURL+"/") {
		return nil, fmt.Errorf("oauth: RSConfig.Resource %q must sit under IssuerURL %q", resource, issuerURL)
	}
	verifier, err := NewEd25519Verifier(issuerURL, resource, cfg.VerifyKey)
	if err != nil {
		return nil, err
	}
	return &ResourceServer{
		verifier: verifier,
		prmURL:   protectedResourceMetadataURL(issuerURL, resource),
	}, nil
}

// Protect gates next behind a valid host-minted token for this resource,
// attaching the caller's identity to the request context (PrincipalFrom);
// otherwise it answers the 401 challenge pointing at the host's metadata.
func (r *ResourceServer) Protect(next http.Handler) http.Handler {
	return protectHandler(r.verifier.Validate, r.prmURL, next)
}
