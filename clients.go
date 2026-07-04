package oauth

import "slices"

// clientsStoreKey holds the JSON map of registered clients in the SecretStore.
const clientsStoreKey = "clients"

// Client is a dynamically-registered OAuth client (RFC 7591). Clients are public
// (PKCE, no secret): Claude and other harnesses each register themselves to get
// an id before the authorize step.
type Client struct {
	ID           string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"client_name,omitempty"`
}

// allowsRedirect reports whether uri exactly matches a registered redirect URI —
// the check that stops an attacker from redirecting an auth code elsewhere.
func (c Client) allowsRedirect(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

// clientRegistry persists dynamically-registered clients via the SecretStore, so
// a client stays registered across restarts (one JSON map under one key).
type clientRegistry struct {
	clients jsonMapStore[Client]
}

func newClientRegistry(store SecretStore) *clientRegistry {
	return &clientRegistry{clients: jsonMapStore[Client]{store: store, key: clientsStoreKey}}
}

// Register creates a client with a fresh id for the given redirect URIs and name.
func (r *clientRegistry) Register(redirectURIs []string, name string) (Client, error) {
	id, err := randToken(16)
	if err != nil {
		return Client{}, err
	}
	c := Client{ID: id, RedirectURIs: redirectURIs, Name: name}
	if err := r.clients.mutate(func(m map[string]Client) bool { m[id] = c; return true }); err != nil {
		return Client{}, err
	}
	return c, nil
}

// Get returns the client for id and whether it is registered.
func (r *clientRegistry) Get(id string) (Client, bool, error) {
	return r.clients.get(id)
}
