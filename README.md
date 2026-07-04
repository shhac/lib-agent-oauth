# lib-agent-oauth

Self-contained OAuth 2.1 for the `agent-*` CLI family: a local Authorization
Server **and** Resource Server in one package — pairing codes, named
principals, browser credential enrollment, token mint/validate, PKCE, and
Dynamic Client Registration — with no dependency on cobra, MCP, or any CLI.

It is the authority behind two things:

- **`lib-agent-mcp`** gates its `/mcp` endpoint with it (a tool acting as its
  own MCP server, `mcp --http --oauth local`).
- **`agent-mcp-host`** uses it to be the family's single Authorization Server,
  in front of many tools under one origin.

Extracted from `lib-agent-mcp/oauth` so the host can own the auth server without
pulling in the MCP-reflection machinery. `lib-agent-mcp` re-exports it under its
own `oauth` import path (type aliases), so existing consumers recompile
unchanged.

Depends only on `lib-agent-keyring` and `golang-jwt/jwt/v5`.

## License

PolyForm Perimeter 1.0.0 — see [LICENSE](LICENSE).
