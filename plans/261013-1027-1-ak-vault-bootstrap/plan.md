---
status: completed
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
| 1 | Protocol TS lib + vectors | packages/protocol, protocol/v1 | done |
| 2 | Landing page + design | worker/public, docs/design-guidelines.md | done |
| 3 | Docs, AGENTS.md, REVIEW.md | docs/, *.md root | done |
| 4 | Worker + DO + tests | worker/src, worker/test | done |
| 5 | Go implementation | go/ | done |
| 6 | CI/CD + deploy + live verify | .github/, wrangler | done |

## Assumptions
- One Worker serves landing (static assets) and API (`/v1/*`, `/healthz`, `/internal/*`).
- Revocation feed from ak-web arrives via HMAC-signed webhook (ak-web#568 implements sender).
- #8 external review cannot be self-attested; it stays `blocked` until a human reviewer signs off.

## Result (2026-10-13)
- Merged: #12 (bootstrap), #15 and #16 (stop the zone's Web Analytics beacon injection on
  HTML via `Cache-Control: no-transform`, HTML only so assets stay compressed).
- Deploy runs green (gate, staging, production) for each merge; production approved by an
  agent under the recorded bootstrap exception (`docs/security/release-gates.md`).
- Live checks: `/healthz` 200 with `sync_enabled:false`, `/v1/meta` limits, `/v1/*` 503
  `sync_disabled`, security headers on `/`, `/security/`, 404; landing page clean in a
  browser (no console errors, no third-party script, no horizontal scroll at 375 px).
- Issues: #2, #4, #5 `shipped`; #6, #7, #8 `blocked` (client work in agentkit#2298/2299,
  external review and soak); follow-ups #9, #13, #14 (`ai-handle`).
- Cross-repo: integration contract on ak-web#568, Go client notes on agentkit#2298, docs
  guide section merged in agentkit-docs#296 (`dev`).
