# ak-vault review playbook

Judgment a linter cannot make. Inline safety rules are in [AGENTS.md](./AGENTS.md);
rationale in [ADR 0001](./docs/adr/0001-opt-in-zero-knowledge-sync.md); wire
contract in the [spec](./docs/protocol/v1/spec.md); attacks and their tests in the
[threat model](./docs/security/threat-model.md).

## Product philosophy

- **Local-first.** The local vault is the product; sync is an accessory. Sync-off
  makes no network calls, and `resolve` never waits on the network.
- **Zero-knowledge by construction.** The server stores ciphertext and the metadata
  listed in [data classification](./docs/security/data-classification.md), nothing
  more. No code path may store, log or decrypt plaintext on the server. The only
  plaintext the Worker may handle is the remote-access transit in
  [ADR 0002](./docs/adr/0002-browser-device-relay-and-remote-mcp.md) D7: an MCP `set`
  value until it is sealed or relayed, a write request's name and purpose until they
  are sealed (D8), and relayed metadata results on their way to the MCP client, held
  in memory only and never logged, stored or put in an error.
- **Honest guarantees.** State limitations as plainly as guarantees: vault-wide
  key, no clawback, withheld updates, plaintext released to `run`.
- **Fail closed.** Unknown, malformed, unverifiable or unavailable means refuse.
- **Least privilege.** Separate vaults for separate trust; reader and machine
  identities cannot write; scope never crosses vaults.
- **Opt-in.** Nothing turns sync on implicitly.
- **No claims without proof.** Every guarantee in docs has a vector or a test.
- **Boring, audited crypto.** Spec-listed primitives from audited libraries only.

## Hard rejection criteria

| Reject when | Safe alternative |
|---|---|
| A plaintext value, secret name, token, proof or key reaches a log, metric, trace, error message, fixture or dump | Log route, status, stable code, opaque IDs and sizes only |
| Any last-writer-wins or silent overwrite path | CAS on `base_revision`; `409` with a preserved branch |
| Custom or hand-rolled cryptography, or a primitive outside the spec | Spec primitives from `@noble/*` or Go `crypto`/`x/crypto` |
| A new endpoint without token, proof, live revocation and membership checks | Route through the shared auth path; only `/healthz`, `/v1/meta` and static assets are public; the ak-web revocation webhook and the operator restore route (404 unless its secret is set) are HMAC-authenticated. Remote access ([ADR 0002](./docs/adr/0002-browser-device-relay-and-remote-mcp.md)) adds exactly these: `/app` (static assets) and `/.well-known/oauth-protected-resource/mcp` (public metadata) are public; `/mcp` verifies the MCP token, live revocation by `sid` and vault membership, without a device proof; `/v1/relay`, lookup, seal-key and sealed-queue routes run the full shared pipeline; `GET`/`POST /v1/vaults/:vid/write-requests/:rid[/close]` and the item PUT with `?write_request=` run it and also require a `browser` session of the requesting account, the request ID alone authorizing nothing |
| A doc or comment widens a guarantee without vectors or tests | Add the vector/test first, or narrow the claim |
| Synced policy, profile or metadata can create or widen a grant | Policy is a maximum intersected with local grants |
| Any server-side decryption, server-held vault key, or web decryption | Client-side crypto only. The one web exception ([ADR 0002](./docs/adr/0002-browser-device-relay-and-remote-mcp.md)): the dashboard at `/app` decrypts as an enrolled akv1 device with its own keys, from static assets under a strict CSP (`script-src 'self'`, SRI, no third-party code), with `browser` session-kind restrictions |
| Server can add a device, member or recipient | Owner-signed membership events only |
| Unknown version/algorithm accepted or silently downgraded | Closed sets; new identifier means new protocol version |
| Wire change without regenerated vectors and green Go **and** TS | Follow the spec-change procedure in AGENTS.md |
| A tombstone can be removed or bypassed | Keep tombstones for the vault's life |
| Production config shares a key with ak-web's CLI signer or with staging | Separate secrets per environment |
| A rollback or incident step deletes users' local caches or vaults | Leave local state alone; local resolve is the safe state |

## Review checklist

**Protocol and crypto**

- [ ] Signing contexts and AAD objects match the spec exactly; AAD is rebuilt from
      authenticated context, never taken from the wire.
- [ ] Nonces come from a CSPRNG; only vectors inject fixed nonces.
- [ ] Canonical JSON and base64url rules enforced on decode, not only on encode.
- [ ] Rejection paths have vectors, not just success paths.

**Worker**

- [ ] Every mutation runs inside the vault's Durable Object, serialized.
- [ ] Token, proof, revocation and membership checks pass before any item data is read or written.
- [ ] Revocation lookup failure returns `503`, not success.
- [ ] Errors use stable codes and echo nothing from the request.
- [ ] Limits come from the single limits owner and are published by `/v1/meta`.
- [ ] Tests include the negative case for each new check.

**Data and logs**

- [ ] New fields are classified in [data classification](./docs/security/data-classification.md).
- [ ] Dump/log scan still finds no planted plaintext or names.

**Operations**

- [ ] Config changes respect the kill switch default and environment separation.
- [ ] Runbooks still match the deployed behavior.

**Docs**

- [ ] Docs explain why and point to owners; no copied limits, inventories or
      command tables that will drift.
- [ ] Limitations stay stated wherever guarantees are stated.

## Test expectations

| Change | Minimum evidence |
|---|---|
| Spec or wire format | Regenerated vectors; TS and Go both green; threat model updated if guarantees moved |
| Protocol library (TS or Go) | Full vector suite in that language, plus the other language if shared behavior changed |
| Worker auth, storage or routes | `worker/test/` integration tests including negative cases; typecheck |
| Landing page | Build and visual check at desktop, tablet and mobile; no console errors |
| CI/CD or deploy config | Staging run; production still gated by the Environment reviewer |
| Docs | Links resolve; claims checked against source, tests, vectors or live state |

Evidence must be from the exact head under review. Cancelled or skipped checks are
not evidence.
