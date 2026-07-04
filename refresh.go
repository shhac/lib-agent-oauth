package oauth

// refreshStoreKey holds the JSON map of refresh tokens in the SecretStore. They
// persist so a client stays connected across server restarts.
const refreshStoreKey = "refresh-tokens"

// refreshGrant is what a refresh token stands for: the client and scope a new
// access token should be minted with.
type refreshGrant struct {
	ClientID  string         `json:"client_id"`
	Scope     string         `json:"scope"`
	Resource  string         `json:"resource,omitempty"`
	Principal PrincipalGrant `json:"principal,omitzero"`
}

// refreshStore issues and exchanges refresh tokens, rotating them on use (the
// exchanged token is invalidated and a new one issued), persisted via SecretStore.
type refreshStore struct {
	grants jsonMapStore[refreshGrant]
}

func newRefreshStore(store SecretStore) *refreshStore {
	return &refreshStore{grants: jsonMapStore[refreshGrant]{store: store, key: refreshStoreKey}}
}

// issue stores a fresh refresh token for clientID/scope/resource/principal and
// returns it. resource is carried so a refresh mints a token for the same
// audience as the original grant.
func (s *refreshStore) issue(clientID, scope, resource string, p PrincipalGrant) (string, error) {
	token, err := randToken(32)
	if err != nil {
		return "", err
	}
	if err := s.grants.mutate(func(m map[string]refreshGrant) bool {
		m[token] = refreshGrant{ClientID: clientID, Scope: scope, Resource: resource, Principal: p}
		return true
	}); err != nil {
		return "", err
	}
	return token, nil
}

// removeForPrincipal deletes every refresh token issued under the named
// principal — the revocation half of removing a principal.
func (s *refreshStore) removeForPrincipal(name string) error {
	if name == "" {
		return nil // the anonymous operator is not a removable principal
	}
	return s.grants.mutate(func(m map[string]refreshGrant) bool {
		changed := false
		for tok, g := range m {
			if g.Principal.Name == name {
				delete(m, tok)
				changed = true
			}
		}
		return changed
	})
}

// exchange consumes token (rotation): it returns the grant and removes the token,
// reporting false if it is unknown.
func (s *refreshStore) exchange(token string) (refreshGrant, bool, error) {
	var g refreshGrant
	var found bool
	err := s.grants.mutate(func(m map[string]refreshGrant) bool {
		if g, found = m[token]; found {
			delete(m, token)
		}
		return found
	})
	if err != nil {
		return refreshGrant{}, false, err
	}
	return g, found, nil
}
