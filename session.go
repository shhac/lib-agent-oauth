package oauth

import (
	"net/http"
	"time"
)

// AS sessions: login once, grow into tools. After a person proves membership
// once (pairing code), the AS sets a browser cookie; connecting the NEXT tool
// skips the code and prompts only for the delta — that tool's enrollment, if
// they're unbound for it. Tokens stay per-tool audience-bound; the session
// shares only the identity proof.
//
// Opt-in via Config.SessionTTL (zero keeps today's code-every-time behavior).
// The cookie carries an opaque token; the record stores only the principal
// NAME — the grant is re-resolved from the pairing store on every use, so a
// removed principal's session dies with the principal and a changed binding
// is always fresh. RemovePrincipal also purges the records outright.

// sessionsStoreKey holds the JSON map of AS sessions in the SecretStore.
const sessionsStoreKey = "sessions"

// sessionCookie uses the __Host- prefix: browsers accept it only over https
// with Secure, Path=/, and no Domain — locking it to the exact host origin.
const sessionCookie = "__Host-agent_mcp_session"

// sessionRecord is one browser session. Anonymous marks the shared-operator
// identity (Name == "" is not enough to distinguish "anonymous" from "absent").
type sessionRecord struct {
	Principal string    `json:"principal,omitempty"`
	Anonymous bool      `json:"anonymous,omitempty"`
	Expires   time.Time `json:"expires"`
}

// sessionStore persists AS sessions, pruning expired records as it writes.
type sessionStore struct {
	records jsonMapStore[sessionRecord]
	ttl     time.Duration
	now     func() time.Time // injectable for expiry tests
}

func newSessionStore(store SecretStore, ttl time.Duration) *sessionStore {
	return &sessionStore{
		records: jsonMapStore[sessionRecord]{store: store, key: sessionsStoreKey},
		ttl:     ttl,
		now:     time.Now,
	}
}

// issue mints a session token for the verified identity. Expired records are
// pruned on the same write, so the store cannot grow without bound.
func (s *sessionStore) issue(p PrincipalGrant) (string, error) {
	token, err := randToken(32)
	if err != nil {
		return "", err
	}
	rec := sessionRecord{Principal: p.Name, Anonymous: p.Name == "", Expires: s.now().Add(s.ttl)}
	if err := s.records.mutate(func(m map[string]sessionRecord) bool {
		for t, r := range m {
			if s.now().After(r.Expires) {
				delete(m, t)
			}
		}
		m[token] = rec
		return true
	}); err != nil {
		return "", err
	}
	return token, nil
}

// lookup returns the unexpired record for token.
func (s *sessionStore) lookup(token string) (sessionRecord, bool, error) {
	rec, ok, err := s.records.get(token)
	if err != nil || !ok {
		return sessionRecord{}, false, err
	}
	if s.now().After(rec.Expires) {
		return sessionRecord{}, false, nil
	}
	return rec, true, nil
}

// removeForPrincipal deletes every session belonging to the named principal —
// the browser-session half of removing a principal.
func (s *sessionStore) removeForPrincipal(name string) error {
	if name == "" {
		return nil // the anonymous operator is not a removable principal
	}
	return s.records.mutate(func(m map[string]sessionRecord) bool {
		changed := false
		for tok, rec := range m {
			if rec.Principal == name {
				delete(m, tok)
				changed = true
			}
		}
		return changed
	})
}

// sessionPrincipal resolves the request's session cookie to a live identity:
// the CURRENT pairing record for a named principal (removed → dead session),
// or the zero grant for an anonymous-operator session.
func (s *Server) sessionPrincipal(r *http.Request) (PrincipalGrant, bool, error) {
	if s.sessions == nil {
		return PrincipalGrant{}, false, nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return PrincipalGrant{}, false, nil
	}
	rec, ok, err := s.sessions.lookup(c.Value)
	if err != nil || !ok {
		return PrincipalGrant{}, false, err
	}
	if rec.Anonymous {
		return PrincipalGrant{}, true, nil
	}
	return s.pairing.grantFor(rec.Principal)
}

// maybeStartSession sets the session cookie after a flow the person completed
// by ENTERING a code — a session-resumed flow doesn't re-issue. No-op unless
// sessions are enabled.
func (s *Server) maybeStartSession(w http.ResponseWriter, r *http.Request, p PrincipalGrant) {
	if s.sessions == nil || r.PostForm.Get("pairing_code") == "" {
		return
	}
	token, err := s.sessions.issue(p)
	if err != nil {
		return // the flow still completes; the next tool just asks for the code again
	}
	s.event(Event{Type: EventSessionStarted, Principal: p.Name})
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.sessions.ttl.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
