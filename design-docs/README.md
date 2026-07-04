# Design docs

The OAuth layer's design currently lives in `lib-agent-mcp/design-docs`, where
it was written before this package was extracted:

- **`oauth.md`** — the local AS+RS design (endpoints, pairing code, token
  model, secret storage).
- **`multi-user.md`** — named principals, bindings, and the trust model for
  serving several humans.
- **`enrollment.md`** — browser credential enrollment (descriptor + callback,
  the chooser, the `Snippet` code-block affordance).

These may migrate into this repo in a later cleanup; until then they remain the
authoritative design and describe this package accurately.
