# Review: ak-web PR #571 — vault device tokens + revocation webhook (ak-web#568)

Reviewer: isolated code-reviewer, no implementation history. Read-only.
Head reviewed: `dfa54f99` (branch `feat/vault-device-tokens`, worktree `/Volumes/GOON/www/claudekit/ak-web-vault-tokens-568`).
Contract: ak-vault `docs/protocol/v1/spec.md` §2/§9, `worker/src/auth/jwt-verify.ts`, `worker/src/routes/revocation-webhook.ts`, `worker/src/revocation/revocation-registry.ts`, `REVIEW.md`.

## Evidence (run at dfa54f99)

- `npx jest` on the 11 touched suites (vault lib, token/device/cron routes, cli device sessions, account-merge, fk-drift): 11 suites, 193 tests pass.
- `npx tsc --noEmit -p .`: exit 0.
- `pnpm db:verify-migrations`: "Migration contract valid: 71 journaled migrations through 0070_fine_earthquake".
- `npx drizzle-kit generate`: "No schema changes" (schema and 0070 snapshot agree; nothing written).
- Ed25519 small-order `y` constants checked against libsodium's blocklist encodings: match.

## Verdict

No merge blocker while `VAULT_TOKENS_ENABLED=false` (default). The token, signing input, strict Ed25519 and HMAC paths match the Worker byte for byte. Two revocation gaps (account deletion, 401-as-terminal) must be fixed **before the flag is turned on in production**; they are release-gate items for ak-vault, not reasons to hold this PR.

## 1. Security — token request and token

Verified correct:
- Signing input `utf8("akv1/vault-token-request") || 0x0A || cjson({aud, scope(sorted), sid, sign_pub, ts})` built from server-side `aud`/`sid`, not client values (`lib/vault/vault-token-request.ts:84-91`). Exact 4-key body, strict canonical b64url (round-trip check), safe-integer `ts`, scope subset with duplicate refusal, ±60 s window.
- Strict Ed25519: canonical `A` and `R`, small-order `A` refused before OpenSSL (`lib/vault/ed25519-strict-encoding.ts`), S<L by OpenSSL. Matches spec §11.
- `did = kid(sign_pub)` per §2; Worker requires 16-byte canonical b64 — satisfied.
- Claims vs `worker/src/auth/jwt-verify.ts`: header `{alg:ES256, typ:at+jwt, kid}` (typ accepted by Worker), `iss`, string `aud`, `sub`, `iat=nbf`, `exp=iat+300`, `jti` UUID, `sid` UUID string, `did`, `scope` space-separated subset. P1363 64-byte sig. All ≤256 chars. Match.
- Isolation: `lib/oauth/protocol.ts` untouched, vault origin not in `OAUTH_RESOURCES`; `verifyAccessToken` additionally requires `client_id`/`grant_id` (`lib/oauth/keys.ts:52`), which vault tokens lack — two independent barriers. OAuth tokens lack `sid`/`did` and carry another `aud`, so the Worker refuses them.
- Fail closed: flag off ⇒ 404 on token/devices/revoke routes; audience not exact HTTPS origin, webhook missing/short secret ⇒ 503 before any DB work; signing key/issuer error ⇒ caught ⇒ generic 503 (tested, no env names leaked).
- Binding: upsert with `setWhere(userId, signPub, revokedAt IS NULL)`; refused upsert ⇒ owner+revoked ⇒ 403, else 409. Session re-checked after binding to close the sign-out race (`route.ts:85`).
- Logs: only `error.name`, event IDs and HTTP statuses. No token, key, body or secret logged.

Replay assessment (asked): a captured request can be replayed for ≤60 s (future-dated `ts` also accepted ±60 s), but only together with the caller's CLI bearer, and it only yields another token for the **same** `did`/`sid`. The Worker requires an `AKV-Proof` signed by the `did` key per request (§9.2), so the extra token is useless without the device private key. **Acceptable**; no nonce store needed.

Residual (documented, accepted by spec): a stolen CLI bearer alone can bind attacker-chosen device keys (≤50) and mint tokens for non-member `did`s — enough for the encrypted recovery-bundle fetch only (§9.4), and it can fill the 50-device cap (DoS until the user revokes). The docs' "sign out all sessions first after a lost device" covers it.

## 2. Revocation delivery

Verified correct:
- HMAC: `HMAC-SHA256(utf8(secret), utf8(ts) || "\n" || body)`, unpadded b64url (43 chars, Worker requires 32 bytes, strict decode). Body is `JSON.stringify(payload)` and the same string is sent, so jsonb key reordering is irrelevant. Secret length rule (`>=32` UTF-16 units) mirrors the Worker. `redirect: 'error'`, 3 s timeout. Independent openssl vector in tests.
- Payload: always all four lists; `event_id` UUID matches Worker `^[A-Za-z0-9_-]{1,128}$`; per-list ≤100 checked at enqueue.
- State machine: 2xx/409 delivered; 408/429/5xx/network retry, 30 s doubling capped 1 h, max 20 attempts; other 4xx failed + ops alert (6 h cooldown).
- Concurrency: `FOR UPDATE SKIP LOCKED` claim + 120 s lease + fencing `lease_token` on outcome write; run budget 90 s < lease. Double sends only after lease expiry; Worker 409 within 15 min, and re-application after that is harmless (registry is monotonic). Multiple replicas + k8s CronJob + in-container crond are safe.
- Cron auth: constant-time compare of `Bearer ${CRON_SECRET}`, 500 when unset. Cron works regardless of the feature flag (correct: queued revocations still drain).
- Paths that enqueue: single session revoke (both routes, via `revokeCliDeviceSession`), refresh-family revoke (reuse/expiry, savepoint inside the refresh tx, sent after commit), revoke-all (`min_iat = now+1`), vault device revoke (same tx as the update), account merge (`min_iat` for the source, in the merge tx, cron-delivered).
- Immediate send never fails the user request (`deliverVaultRevocationsNow` swallows, cron retries).

Findings:

### SHOULD-FIX (release-gate) — account deletion queues no revocation
`app/api/gdpr/delete-account/route.ts:79`, `app/api/admin/users/[userId]/orphan/route.ts:114`, `app/api/admin/users/[userId]/claim-email/route.ts:253`; `db/schema/vault-device-keys.ts:22` (`ON DELETE cascade`).
Impact: deleting a user cascades `agentkit_cli_sessions` (so no new mints) and `vault_device_keys`, but already-issued vault tokens stay valid at the Worker for up to 300 s + 60 s skew. Bounded (~6 min), data is E2E-encrypted, and the account owner is usually the actor — so not a merge blocker. It matters when deletion/orphan cleanup is used as a response to compromise, and it breaks the doc claim that every revocation path notifies the Worker. Secondary: the cascade also erases the `did` binding, contradicting the merge comment at `lib/admin/account-merge-fk-coverage.ts:94` ("deleted … would let a revoked key bind again") — a revoked did can be re-bound by a new account (the Worker still refuses it if its `revoke_dids` was delivered, so impact is low).
Fix: before `delete(users)`, inside one transaction (GDPR route currently has none), call
```ts
const dids = (await tx.select({ did: vaultDeviceKeys.did }).from(vaultDeviceKeys)
  .where(and(eq(vaultDeviceKeys.userId, id), isNull(vaultDeviceKeys.revokedAt)))).map((r) => r.did);
const eventId = await enqueueVaultRevocation(
  { userIds: [id], minIat: [{ sub: id, iat: Math.floor(Date.now() / 1000) + 1 }], revokeDids: dids.slice(0, 100) }, tx);
```
(enqueue must run before the cascade because it checks for a device row), then `deliverVaultRevocationsNow([eventId])` after commit. `min_iat` alone already covers every token of the `sub`; `revoke_dids` is defence in depth. Apply the same helper to orphan and claim-email deletes. Add a route test asserting the enqueue precedes the delete.

### SHOULD-FIX (release-gate) — Worker 401/404 classified as permanent failure
`lib/vault/vault-revocation-delivery.ts:49-52`.
The Worker answers 401 for HMAC mismatch **and** timestamp outside ±300 s, and 404 for a wrong path. These are operator/config faults (secret rotated in one place first, trailing newline in the env secret, clock skew, URL typo), not "this body will never be accepted". Today the event is marked `failed` on the first such reply and never retried; after the operator fixes config, every revocation from that window stays lost (≤5-min tokens, but the user was told they were signed out). The alert fires, but there is no requeue tool or runbook.
Fix: keep only 400/413/422 terminal; treat 401/403/404 as `retry` with the normal backoff (still alerting via a "retrying with 4xx" counter), or provide a documented requeue (`UPDATE … SET status='pending', attempts=0 WHERE status='failed'`) in the runbook. Update the test table at `__tests__/lib/vault/vault-revocation-delivery.test.ts` accordingly.

### SHOULD-FIX — single-session revoke and revoke-all enqueue outside the revocation's commit
`lib/agentkit-registry/device-sessions.ts:223` and `:393` (`revokeVaultSessionsBestEffort`, `:354`).
The session `UPDATE` autocommits, then the outbox insert runs separately and its error is logged and swallowed. A crash or DB error between the two loses the event (not a transactional outbox, unlike `revokeSessionFamily` and `revokeVaultDevice`). ak-web's own rule (CLAUDE.md:78) is "never silently swallow an error in a webhook flow — log it and alert"; there is no alert here. Bounded by the 5-min token TTL, so not a blocker.
Fix: wrap update + enqueue in `database.transaction`, using a savepoint for the enqueue as `revokeSessionFamily` does if the "never fail sign-out" trade-off is kept, and alert (not only `console.error`) on enqueue failure.

### SHOULD-FIX — no events queued while webhook config is missing/invalid
`lib/vault/vault-revocation-outbox.ts:56`.
Mint refuses without config, but tokens minted before a config regression (secret shortened, URL removed during rotation) remain live ≤5 min and every revocation during the outage is dropped rather than held. Delivery already leaves rows pending when config is absent (`deliverDueVaultRevocations`), so the outbox can simply always queue (keep the `hasDevice` filter) and let the cron drain after config returns. Update `.env.example`/docs line "No events are queued while either webhook value is missing".

### NIT — revoke-all relies only on `min_iat`, which depends on cross-replica clock agreement
`lib/agentkit-registry/device-sessions.ts:393`. `min_iat` comes from the revoking replica's clock, `iat` from the minting replica's clock. A token minted concurrently on a replica >1 s ahead survives up to 5 min. Also sending `revoke_sids` for the revoked session IDs (chunked by 100) makes revoke-all clock-independent.

### NIT — attempts inflated by the run budget
`lib/vault/vault-revocation-delivery.ts:97,155`. Claim increments `attempts` for every claimed row; rows skipped by the 90 s budget burn an attempt without a send. Harmless at 25/run × 3 s timeout (≤75 s), but it can push an event toward the 20-attempt cap under sustained timeouts. Increment on send instead, or claim fewer rows.

### NIT — first-bind race with refresh-family revoke
`revokeSessionFamily` (`device-sessions.ts:341`) reads `hasDevice` inside the refresh tx before commit; a concurrent first-ever bind for that user can commit after that read, and the mint route's re-check still sees the session active (revoke uncommitted). Result: one ≤5-min token with no event. Requires the user's very first device bind to coincide with refresh-token-reuse detection. Accept or document.

### NIT — spec wording on event IDs
Spec §2 says opaque "event ids" are b64 of 16 random bytes; ak-web sends UUIDs. The Worker accepts both; clarify in ak-vault spec §9.3 that the webhook `event_id` is any `[A-Za-z0-9_-]{1,128}` string, or switch ak-web to b64(16 random bytes).

### NIT — delivery header comment overstates `event_id` single-use
`lib/vault/vault-revocation-delivery.ts:15`. The Worker remembers event IDs for 15 min; later retries are re-applied (idempotent, monotonic). Say "duplicates are harmless" rather than "absorbed".

## 3. Migration 0070 and schema

- Append-only: new journal entry, new SQL, new snapshot; no edits to landed migrations; chain verifier and drizzle drift check pass.
- Constraints: unique `did`, index `user_id`, FK cascade to users; outbox PK `event_id`, index `(status, next_attempt_at)` matches the claim predicate.
- Postprocess allowlist regexes are anchored and limited to brand-new `vault_*` tables — acceptable.
- NIT: `status` is unconstrained `text` in SQL (Drizzle enum is type-only). Add `CHECK (status IN ('pending','delivered','failed'))` in a follow-up migration if the repo does so elsewhere.
- Account merge: `vault_device_keys` classified MOVE (correct: did is globally unique, no collision) and source `sub` cut off with `min_iat`. **Question:** after merge, post-merge tokens carry `sub = target` while vault membership (owner-signed log) still names the source account, so the human is locked out of their vaults until an owner re-adds the target account (§9.4 "sub must be a current member"). Functional, not a security issue; needs a product decision and a docs note in ak-vault.

## 4. Tests and docs

- Refusals are well covered at the route level: flag off, bad audience, short secret, missing/forged/api-key bearer, inactive session, mid-bind sign-out, bad sig, stale ts, bad scope, oversized/non-JSON body, 409/403/device_limit, signing key missing without leakage. Token signature verified against the published JWKS with P1363. Encoding tests run against copied ak-vault vectors.
- SHOULD-FIX (test gap): every DB behavior that carries a security claim is tested only against hand-written Drizzle mocks — the upsert `setWhere` refusal, `FOR UPDATE SKIP LOCKED` claim SQL, lease fencing, `hasDevice` gating, prune. A mock asserting `onConflictDoUpdate` was called with some object does not prove a revoked or foreign did cannot be re-bound. Add at least one real-Postgres test (repo's integration harness, or pglite if available) for `bindVaultDeviceKey` (foreign → refused, revoked → refused, owner → refreshed) and for two concurrent `claimDueEvents` returning disjoint rows.
- NIT: no test runs the actual Worker `verifyToken` on an ak-web-minted token; claims are compared by hand. A shared vector (token + JWKS + fixed `now`) checked into ak-vault would make drift fail CI on both sides.
- Docs (`docs/features/build-with-ak-mcp-oauth.md`) are accurate except: the revocation list omits account deletion (consistent with the code, but should say deletion is not yet covered until fixed); "No events are queued while either webhook value is missing" will change if the outbox finding is adopted.
- NIT: JWS is hand-assembled with `node:crypto` (`lib/oauth/keys.ts:73-82`) rather than `jose.SignJWT` used two functions above, justified by jest's `jose` stub. Correct and small; acceptable, but a second signing path for the same key is a maintenance cost.

## Summary table

| Severity | Finding | Location |
|---|---|---|
| should-fix (release gate) | Account deletion (GDPR, orphan, claim-email) queues no revocation; cascade erases did binding | `app/api/gdpr/delete-account/route.ts:79`, `app/api/admin/users/[userId]/orphan/route.ts:114`, `app/api/admin/users/[userId]/claim-email/route.ts:253`, `db/schema/vault-device-keys.ts:22` |
| should-fix (release gate) | Worker 401/404 (config faults) marked permanently failed, no requeue | `lib/vault/vault-revocation-delivery.ts:49-52` |
| should-fix | Session revoke / revoke-all enqueue not in the revocation commit; error swallowed without alert | `lib/agentkit-registry/device-sessions.ts:223,354-368,393` |
| should-fix | Outbox drops events when webhook config is missing instead of holding them | `lib/vault/vault-revocation-outbox.ts:56` |
| should-fix | Security-bearing SQL (bind upsert, SKIP LOCKED claim, fencing) only tested against mocks | `__tests__/lib/vault/vault-device-keys.test.ts`, `__tests__/lib/vault/vault-revocation-delivery.test.ts` |
| nit | revoke-all uses only `min_iat` (clock-dependent); add `revoke_sids` | `lib/agentkit-registry/device-sessions.ts:393` |
| nit | `attempts` burned for rows skipped by run budget | `lib/vault/vault-revocation-delivery.ts:97,155` |
| nit | First-bind vs refresh-family-revoke race, one ≤5-min token without event | `lib/agentkit-registry/device-sessions.ts:341` |
| nit | `event_id` UUID vs spec §2 "b64 of 16 bytes" wording | ak-vault `docs/protocol/v1/spec.md` §2/§9.3 |
| nit | Comment overstates Worker event_id memory (15 min) | `lib/vault/vault-revocation-delivery.ts:15` |
| nit | `status` has no SQL CHECK | `db/migrations/0070_fine_earthquake.sql` |
| nit | No shared cross-repo token vector; hand-rolled JWS beside jose | `lib/oauth/keys.ts:73-82` |

## Unresolved questions

1. Account merge: should vault membership follow the merge (owner re-adds target) or should ak-web keep minting with `sub = source` alias for vault tokens? Today the merged user loses vault access.
2. Is deleting `vault_device_keys` on account deletion required for GDPR, or may a tombstone (`did`, `revoked_at`, null `user_id`) be kept so a revoked key can never be re-bound?
3. Is there an existing ops procedure to requeue `failed` outbox rows, or should one be added to the runbook?

Status: DONE
Summary: No merge blocker with the flag off; token, signing input, strict Ed25519 and webhook HMAC match the Worker exactly, and tests/typecheck/migration checks pass. Before enabling in production, fix deletion-path revocation and the 401/404-as-terminal delivery rule; three further should-fixes harden the outbox and tests.
Concerns/Blockers: none blocking merge; two release-gate should-fixes listed above.

---

## Re-review at ee55a41a (2026-10-13)

Scope: `git diff dfa54f99 ee55a41a` (29 files) against the findings above, plus the claims under "Review fixes" in `fullstack-developer-261013-1320-ak-web-vault-tokens.md`. Read-only.

### Evidence (at ee55a41a)

- `npx jest __tests__/api __tests__/lib/vault __tests__/lib/agentkit-cli-device-sessions.test.ts lib/admin app/api/admin/users`: 109 suites, 976 tests pass.
- `npx tsc --noEmit -p .`: exit 0.
- `pnpm db:verify-migrations`: valid, 71 migrations through `0070_sudden_dexter_bennett`.
- `npx drizzle-kit generate`: "No schema changes" (schema, regenerated SQL, snapshot and journal agree; nothing written; worktree clean).
- GitHub Actions run 38374743835, headSha `ee55a41ad9f0…`: job "Account-merge FK coverage (migrated DB)" passed; step 12 "Verify ak-vault device binding and revocation outbox" = success, after step 7 "Apply migrations" on a clean `postgres:16` service. "Apply migration chain to clean PostgreSQL" passed. The "Type-check, lint, test, build" and "Final image" jobs were still pending when checked.

### Finding-by-finding

| Original finding | Status | Evidence |
|---|---|---|
| Account deletion queues no revocation | **Closed** | `enqueueVaultAccountDeletionRevocation` (`lib/vault/vault-revocation-outbox.ts`) reads live dids, queues `min_iat = now+1` + `revoke_dids` in the deleting tx before `delete(users)`. GDPR route now wraps enqueue + delete in `db.transaction` and sends after commit; orphan and claim-email do the same inside their existing tx. Route test: an enqueue failure leaves the account undeleted (500). Real-PG script proves the event survives the cascade and names only live dids. Merge-coverage comment corrected. |
| Worker 401/404 terminal | **Closed** | Only 400/413/422 terminal (`TERMINAL_STATUSES`); everything else retries to `VAULT_WEBHOOK_MAX_ATTEMPTS = 20`. Backoff 30 s doubling to a 1 h cap ⇒ about 14 h before `failed`. Cron alert also fires on 4xx-while-retrying (`rejected`), 6 h cooldown via `shouldAlert` ⇒ at most 4 critical alerts/day per incident. Requeue path + runbook added. |
| Session revoke / revoke-all not atomic, swallowed | **Closed** | `revokeCliDeviceSession` and `revokeAllCliDeviceSessions` now update and enqueue in one `database.transaction`; `revokeSessionFamily` enqueues in the refresh tx without a savepoint. Outbox logs, alerts (1 h cooldown) and rethrows ⇒ rollback ⇒ routes answer 500. Tests assert rejection and that nothing is sent. Empty-array return (user without devices) is still truthy, so `{revoked:true}` is correct. |
| Outbox drops events when webhook config missing | **Closed** | Config check removed from the outbox; delivery still returns early without config, so rows stay pending. `.env.example` and docs updated. |
| Security SQL only mock-tested | **Closed** | `scripts/verify-vault-revocation-outbox.ts` runs in CI on a migrated clean Postgres 16 and exits 1 on any failed `check`. It covers: foreign bind refused with the row unchanged, owner refresh, revoked did refused, disjoint concurrent claims, re-claim refused under lease, stale-lease outcome is a no-op, current lease records delivery, 422 ⇒ failed ⇒ requeue resets, deletion event content plus cascade, and the status CHECK. These assertions would fail if `setWhere` or the lease predicate were removed; the author reports the same mutation results. Seeded rows are cleaned up in `finally`. |
| nit: revoke-all `min_iat` only | Closed | Also sends `revoke_sids` for ended sessions; lists >100 are split across events (`buildVaultRevocationPayloads`), with `min_iat` on the first event. |
| nit: attempts burned by run budget | Closed | Attempts counted at outcome (`attempts + 1` in SQL, fenced); claim no longer increments. |
| nit: comment on event_id memory | Closed | Comment now says 409 within 15 min, idempotent re-application after. |
| nit: status CHECK | Closed | `vault_revocation_events_status_check` in schema, SQL and snapshot; real-PG check proves it refuses `bogus`. |
| nit: first-bind vs refresh-revoke race | Accepted, documented | Unchanged; ≤1 token of ≤5 min. Acceptable. |
| nit: event_id UUID vs spec wording | Open (ak-vault side) | Spec clarification belongs in ak-vault. |
| nit: no cross-repo token vector | Open | Unchanged; not blocking. |
| Merge lockout question | Answered | Docs record that a merged user must be re-added or recover (pre-GA). |
| Deletion tombstone question | Answered | Docs: no tombstone; Worker membership binds account+device. I agree; the deletion event also revokes live dids. |

### Requested checks

- **Rollback on enqueue failure / GDPR transactional:** verified in code and tests (above). The enqueue runs before the delete, so the cascade cannot hide device rows from it.
- **Retry cap and alert noise:** cap 20 sends (≈14 h); critical alert at most once per 6 h for delivery and once per 1 h for enqueue failures. Acceptable.
- **Requeue script:** dry run by default; `--apply` required to write; `--event-id` validated as a UUID; unknown args refused; requires `DATABASE_URL`; only `status='failed'` rows change; prints event IDs and last status only, never payloads. Requeueing a 400/422 event just fails again (harmless). Safe.
- **Real-Postgres script in CI:** yes. The step exists in `.github/workflows/ci.yml` (fk-coverage job, which runs on PRs to main/dev and pushes), and it ran green at this head. It fails on regression (`check` throws ⇒ exit 1).
- **Migration 0070 regenerated:** the old `0070_fine_earthquake` is replaced, never landed (PR unmerged). Journal tag/when, snapshot (`checkConstraints`) and SQL agree; the drizzle drift check is clean; the chain verifier passes. The postprocess allowlist still matches because the CHECK sits inside the `CREATE TABLE` statement. Condition: no shared database (staging/preview) may have applied `0070_fine_earthquake`. If one did, it needs a manual cleanup before deploying.

### New observations (none blocking)

- **NIT — refresh-reuse revocation now rolls back with the outbox.** In `lib/agentkit-registry/device-sessions.ts`, `revokeSessionFamily` no longer uses a savepoint, so if the outbox insert fails (and the account has a vault device) the whole refresh tx rolls back, including the theft-response family revoke; the route answers 500 and issues no tokens. Both writes share one database, so this only bites when that database is failing anyway, and the next reuse attempt retries the revoke. It is the correct fail-closed choice for vault consistency. Docs say "no sign-out succeeds without telling the Worker"; they could add that reuse detection is retried on the next attempt.
- **NIT — held events are invisible when webhook config is missing.** `deliverDueVaultRevocations` returns `claimed: 0` without config, so pending rows pile up with no alert. Impact is minimal: minting also fails closed, existing tokens expire within 5 min, and revoked sids/dids cannot mint again. A cron alert on "pending rows older than N minutes" would make a config regression visible.
- **NIT — `rejected` counts 408/429 as well,** so a transient Worker rate limit raises a critical alert (at most once per 6 h). Consider counting only 401/403/404.
- **NIT — runbook wording.** "the Worker ignores an event ID it has already applied" holds only for 15 min; the next clause (re-applying changes nothing) is what makes requeue safe. Reword.
- **NIT — the concurrent-claim check** uses `Promise.all` on one pool and proves disjointness, but not specifically `SKIP LOCKED` (serialized claims would also be disjoint because of the lease). Adequate as a regression guard.
- **Confirm before merge:** the "Type-check, lint, test, build" and "Final image fails closed" jobs at ee55a41a must be green.

### Re-review verdict

All five should-fix findings are closed with code, tests and, where it matters, real-Postgres CI evidence. The fixes introduced no new blocker or should-fix; five nits above.

Status: DONE
Summary: Re-review at ee55a41a: every should-fix is closed and verified (tests 976/976, tsc clean, migration chain + drift clean, real-PG verify step green in CI). Only nits remain.
Blockers remaining: none. Should-fix remaining: none. Open: five new nits, two cross-repo nits (spec event_id wording, shared token vector), and two pending CI jobs to confirm green before merge.
