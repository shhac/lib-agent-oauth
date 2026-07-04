# lib-agent-oauth

The self-contained OAuth 2.1 layer for the `agent-*` family: a local
Authorization Server **and** Resource Server, pairing codes, named principals,
credential enrollment + chooser rendering, token mint/validate, PKCE, and
Dynamic Client Registration.

Extracted from `lib-agent-mcp/oauth` so it can be consumed without the
cobra-reflection half of `lib-agent-mcp`: the MCP bridge uses it to gate `/mcp`,
and `agent-mcp-host` uses it to be the family's single authorization server.

## What this is

- **Package `oauth`** at the module root. Depends only on `lib-agent-keyring`
  (the default `SecretStore`) and `golang-jwt/jwt/v5` — plus the stdlib. No
  dependency on cobra, MCP, or any CLI.
- The AS+RS, pairing/principals, and the human-facing pages (pairing-code entry,
  enrollment, chooser, authorize) all live here.

## Mechanism here, policy in the caller

This library owns the OAuth *mechanism*. Callers own *policy*: which principals
exist, what a binding means, how a credential is enrolled/validated. The
`Enrollment` seam (descriptor + callback) and the principal `Binding` map are
how a caller injects policy without this library knowing anything domain-specific.

## Build, test, verify

```bash
GOCACHE=$(pwd)/.cache/go-build GOWORK=off go test ./... -count=1
GOCACHE=$(pwd)/.cache/go-build GOWORK=off go vet ./...
GOWORK=off golangci-lint run ./...
```

## Design docs

The full design lives (for now) in `lib-agent-mcp/design-docs` —
`oauth.md` (the AS+RS design), `multi-user.md` (named principals + the trust
model), and `enrollment.md` (browser credential enrollment). `design-docs/` here
points at them; they may migrate into this repo in a later cleanup.
