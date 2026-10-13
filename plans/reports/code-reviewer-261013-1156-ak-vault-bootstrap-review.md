# Code review: ak-vault bootstrap (`8ba05bd..ef142f6`)

Branch `claude/ak-bootstrap-landing-page-79aef2` (== local HEAD `ef142f6`). Read-only; applied REVIEW.md.

## Evidence (at ef142f6)

- `pnpm -r typecheck`: pass (protocol + worker, incl. test and node tsconfigs)
- `pnpm -r test`: protocol 275/275, worker 83/83 pass (the "Network connection lost" line is the expected JWKS-unreachable test, explained in `worker/test/auth-token.test.ts:69`)
- `go test ./...`, `go vet ./...`, `gofmt -l .`: clean
- No caches/processes created (no `.wrangler/`, no servers). Note: `plans/261013-1027-1-ak-vault-bootstrap/plan.md` shows as modified in the worktree; I did not change it (another agent did).

## Verdict

No BLOCKING defects found in the auth core. JWT verify (sig before claims, exact iss/aud, forbidden header params, kid-only JWKS, fail-closed 503), proof binding (htm/htu/ath/bh, jti per device per vault), live revocation (`revoked !== false` fails closed, 503 on registry error), membership-before-proof ordering, role/scope table, CAS/tombstones through `applyRecord`, idempotency (did-scoped key hash, request hash, stored 409s), and the error mapping (fixed messages, no echo) all check out against the spec and tests. The crypto primitives (strict b64url, strict JSON, strict Ed25519 in TS and Go) also match spec §11.

There are 7 SHOULD-FIX items. Two of them (S1, S2) must be closed before the release gate even though production sync is off.

## SHOULD-FIX

**S1. Lost-all-devices recovery can't be done through the API.** Files: `worker/src/vault/vault-authorization.ts:40`, `request-guard.ts` `memberDevice`.
- `recovery.get` requires a current human owner device.
- The device doing recovery is a fresh device that is not in membership. Its GET `/recovery` is therefore 403, and the server cannot verify its proof because it has no `sign_pub` for that device.
- `recovery_sign_sk` lives only inside that bundle. So the recovery-signed `device_add` path in `authorizeMembershipPost` can't be reached unless the user kept an offline copy of the bundle.
- The test `membership.test.ts:128` skips the fetch and uses `fx.recovery.secretKey` directly, so the full flow has no proof (REVIEW: "No claims without proof").
- Fix: decide how the bundle is fetched. Option (a): a bundle-fetch route for `sub == owner_account` whose proof is verified against a `sign_pub` the caller presents, with `did == kid(sign_pub)`. Option (b): explicitly require an offline bundle export. Then add an end-to-end test and document the offline-guessing exposure (anyone with an owner-account ak-web token gets the Argon2 blob).

**S2. Docs contradict the spec on recovery and SAS.**
- `docs/security/key-lifecycle-and-recovery.md:99-105` and `docs/adr/0001-opt-in-zero-knowledge-sync.md:134-140` still say the bundle has no owner signing key and that the SAS transcript format is undefined.
- Spec §3.5 and §11 now define `recovery_sign_sk` and the SAS transcript, and both are implemented.
- Fix: update both docs, and keep the S1 limitation stated until it is resolved.

**S3. Reader and machine devices can write audit entries and checkpoints, against spec §9.4.**
- `vault-authorization.ts:37,39` (`EITHER` scope, `any_device`) conflicts with spec §9.4 (`docs/protocol/v1/spec.md:236`: "`reader` role and `machine` devices are read-only").
- Failure: a compromised reader in a shared vault can append junk ciphertext up to `audit_entries_per_vault` (100k). Nothing is compacted or deleted, so the vault's audit stream is then refused (403) for every device, permanently.
- Fix: either narrow the spec and threat model to say witnesses may append (and add a per-device audit quota), or restrict `audit.post` to writers.

**S4. Any token holder can create persistent Durable Object storage for any vault ID.**
- `vault-durable-object.ts:36` runs `enforceRateLimit` (an INSERT into `rate_counters`) before `authorize`. The constructor also creates the schema.
- Failure: a GET `/v1/vaults/<random id>/membership` from any valid, unrevoked token (any ak-web account) gets a 404, but it leaves a SQLite DO with tables and a row behind. This is unbounded storage and cost growth with no cleanup.
- Fix: check `membership.state()` (or genesis) before any write and skip the counter for missing vaults. Alternatively, keep rate counters in memory. Consider lazy schema creation.

**S5. A vault's change log has no total size limit, and writes slow down as it grows.**
- `item-store.ts:33` loads every digest of the item on every PUT.
- Only `items_per_vault` and `open_conflicts_per_vault` are capped. Revisions and records grow without limit: 120 req/min × 64 KiB is about 11 GB per device per day.
- Failure: a single writer can exhaust DO storage (10 GB). Per-write CPU and memory also grow linearly with the item's history.
- Fix: add a records/bytes-per-vault limit to `LIMITS` (published via `/v1/meta`). Replace the `seen` scan with an indexed `SELECT 1 FROM records WHERE item_id=? AND digest=?` (the `UNIQUE(item_id,digest)` index already exists). This needs `applyRecord` to accept a replay-check callback.

**S6. Deploy workflow gating and secret handling.** File: `.github/workflows/deploy.yml`.
- **No CI gate:** deploy (`:5-9`) does not depend on CI. A red `main` deploys to staging, and production waits only on a human approval.
  - Fix: run typecheck and tests in the deploy jobs, or trigger deploy with `workflow_run` on a successful CI run.
- **Deploys from any branch:** `workflow_dispatch` (`:9`) can deploy any branch. The approver of the production job may approve a non-main ref.
  - Fix: add `if: github.ref == 'refs/heads/main'` and set environment deployment-branch rules to `main`.
- **Token exposed to every step:** `CLOUDFLARE_API_TOKEN` is set at job level (`:22-23`, `:55-56`). Every step can read it: tag-pinned third-party `pnpm/action-setup@v4` and `pnpm install` build scripts (esbuild, workerd, sharp).
  - Fix: set the token only on the "Check credentials" and `wrangler deploy` steps, and pin actions by commit SHA.

**S7. Platform invocation logs likely bypass the operational-logger contract.**
- `wrangler.jsonc:11` enables `observability` with `head_sampling_rate: 1`. Cloudflare invocation logs are on by default and record method + full URL (raw vault ID, item ID, query) plus request metadata. That metadata may include headers (`Authorization`, `AKV-Proof`, `Idempotency-Key`, `AKV-Webhook-Signature`) and the client IP. I did not verify header capture.
- This conflicts with the hashed-vault-tag design (`operational-logger.ts`) and data-classification ("never tokens, proofs, idempotency keys"; "client IPs not written").
- The disclosure-scan test covers only `console.log`.
- Fix: set `"observability": {"enabled": true, "logs": {"invocation_logs": false}}`, or verify what is captured and redacted on staging and record the result in data-classification.

## NIT

- **N1. JWKS:** a failed load is not cached (`jwks.ts:66-80`). While the endpoint is down, every request makes another outbound fetch with up to a 5 s wait. Keys that were already loaded are also dropped after 5 min instead of serving them stale for a bounded time. Add a short negative cache. Optionally serve last-good keys for a bounded period (decide whether that is acceptable under fail-closed).
- **N2. Body reads:** `revocation-webhook.ts:83-85` (before HMAC) and `api-handler.ts:21-23` read the whole body when `Content-Length` is absent (chunked). Read the stream with a byte cap instead.
- **N3. Shared audience:** staging and production use the same `VAULT_AUDIENCE` (`wrangler.jsonc:32,51`). Today the separate issuers prevent cross-acceptance, but a distinct staging audience makes the environment separation explicit if staging ever trusts ak-web's JWKS.
- **N4. Full chain replay on append:** `membership-store.ts` `verifyAppend` replays the whole chain, which can be up to 10k events. Each event costs two Ed25519 checks in pure JS, so an append near the cap may take seconds and block the vault DO. Lower the cap or add a resumable verifier.
- **N5. Silent deploy skips:** when credentials are missing, the deploy jobs finish green without deploying (`deploy.yml` "Check credentials"). Make the production skip a failure, or label the outcome clearly.
- **N6. Webhook retries:** a retried revocation event that was already applied returns 409 `conflict` (`revocation-webhook.ts:99`). Document that ak-web must treat this as success.

## Checked, no issue

- CSP and landing page: no inline script, style or event handlers; JSON-LD is a data block; fonts are self-hosted; security headers are applied to assets, the 404 page and the API.
- CI: `contents: read`, no `pull_request_target`, no untrusted `${{ }}` in `run`, gitleaks scans the full history.
- Webhook: HMAC compared with `subtle.verify` (constant time), ±300 s window, event IDs kept for 15 min, revocations only ever tighten.
- Cross-tenant: a token's `did` must be a device of `sub` in this vault, and the proof's `htu` binds host, vault and item.
- Go and TS strict Ed25519 match spec §11.

## Unresolved questions

1. Are the `CLOUDFLARE_API_TOKEN` secrets scoped per environment (`staging` and `production`), or set at repository level and shared? REVIEW.md requires separate secrets per environment.
2. Is letting readers and machines append audit entries and checkpoints a product decision (spec change) or an implementation slip?
3. Intended recovery bundle retrieval for a device with no membership (S1)?

Status: DONE_WITH_CONCERNS
Summary: Auth, revocation, membership, CAS and crypto paths are correct and tested; tests, typecheck and Go are all green. 7 SHOULD-FIX items remain; the biggest are the lost-all-devices recovery path that can't be reached through the API and deploy-workflow gating and secret scope.
Concerns/Blockers: S1/S2 must close before the release gate. S7 needs a staging check of what Cloudflare invocation logs capture.
