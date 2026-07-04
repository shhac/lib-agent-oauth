package oauth

// Event is a non-secret notification of an AS lifecycle moment, delivered to
// Config.OnEvent. A host uses these to surface an operator-facing activity
// stream ("alice enrolled for slack") without reaching into the flow.
//
// Events NEVER carry secrets: no pairing codes, no tokens, no submitted
// credential values — only names, labels, and routing data that already
// appear in list output elsewhere.
type Event struct {
	// Type is the lifecycle moment:
	//   client_registered — dynamic client registration completed
	//   paired            — a person proved identity on the approval page
	//   session_started   — a code-entered flow set the login-once cookie
	//   enrolled          — an enrollment callback stored credentials
	//   authorized        — an authorization code was issued (flow complete)
	Type string
	// Principal is the named principal involved; empty = anonymous operator.
	Principal string
	// Client is the registered client's display name, where known.
	Client string
	// Resource is the audience (mount /mcp URL) the flow targets, where known.
	Resource string
	// Via distinguishes how identity was proven on "paired": "code" or
	// "session".
	Via string
}

// Event type values.
const (
	EventClientRegistered = "client_registered"
	EventPaired           = "paired"
	EventSessionStarted   = "session_started"
	EventEnrolled         = "enrolled"
	EventAuthorized       = "authorized"
)

// event delivers e to the configured observer, if any. Called synchronously
// on the request path — observers must be fast and must not block.
func (s *Server) event(e Event) {
	if s.onEvent != nil {
		s.onEvent(e)
	}
}

// eventResource resolves the request's audience for an event's Resource
// field — best-effort: an event is telemetry, never a gate.
func (s *Server) eventResource(p authParams) string {
	resource, _ := s.resolveResource(p.resource)
	return resource
}
