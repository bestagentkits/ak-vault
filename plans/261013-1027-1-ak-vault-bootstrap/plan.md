---
status: in-progress
issues: [1, 2, 4, 5, 6, 7, 8]
---

# ak-vault bootstrap (epic #1, issues #2–#8)

## Outcome
Repo `bestagentkits/ak-vault` holds the reviewed-ready protocol v1 (ADR, spec, threat
model, cross-language Go/TS vectors), a Cloudflare Worker + SQLite Durable Object
sync server enforcing CAS/tombstones/membership/auth/revocation, the security test
harness and release gates, and a landing page at https://vault.agentkit.best.

## Constraints
- No custom crypto; audited libs only (noble, Go x/crypto/stdlib).
- Production sync API ships behind kill switch `VAULT_SYNC_ENABLED=false` until #8
  external security review sign-off (epic: "do not deploy production secrets").
- No server-side plaintext; no CLI HS256 key in Worker; staging uses a test-only issuer.
- Cross-repo work (agentkit#2298/2299/2300, ak-web#568/569) is out of this repo's scope.

## Non-goals
Web decryption, server KMS, keyless OIDC, R2 (until measured), D1, paid gating, imports.

## Acceptance (this repo)
- Go and TS reproduce every vector byte-for-byte, including rejection vectors.
- Worker integration tests: CAS/409 preserved branches, tombstones, idempotency,
  cross-tenant, wrong aud/iss/alg, replayed proof, revoked device/session, stale
  membership, injected recipient, reader/machine write denial, dump has no plaintext.
- Landing page live on vault.agentkit.best (desktop/tablet/mobile, no console errors),
  `/healthz` and `/v1/meta` live; staging smoke passes on vault-staging.agentkit.best.
- CI green on main; production deploy gated by GitHub Environment reviewer.

## Phases
| # | Phase | Owner files | Status |
|---|---|---|---|
| 1 | Protocol TS lib + vectors | packages/protocol, protocol/v1 | pending |
| 2 | Landing page + design | worker/public, docs/design-guidelines.md | pending |
| 3 | Docs, AGENTS.md, REVIEW.md | docs/, *.md root | pending |
| 4 | Worker + DO + tests | worker/src, worker/test | pending |
| 5 | Go implementation | go/ | pending |
| 6 | CI/CD + deploy + live verify | .github/, wrangler | pending |

## Assumptions
- One Worker serves landing (static assets) and API (`/v1/*`, `/healthz`, `/internal/*`).
- Revocation feed from ak-web arrives via HMAC-signed webhook (ak-web#568 implements sender).
- #8 external review cannot be self-attested; it stays `blocked` until a human reviewer signs off.
