# Revocation registry capacity: analysis (#65, #63)

Date: 2026-10-16 (Asia/Saigon). Read-only analysis against `origin/main` at `7cd04e0`. The local worktree branch is behind `main`, so line citations are from `main`. No code, PR, deploy or load test.

## Outcome
- Analysis and recommendation posted on #65: https://github.com/bestagentkits/ak-vault/issues/65#issuecomment-6213539129
- Linking comment posted on #63: https://github.com/bestagentkits/ak-vault/issues/63#issuecomment-6213540948
- `ai-handle` label added to #65 and #63, and verified with `gh issue view`.

## Facts (file:line at 7cd04e0)

**Check per request.** `worker/src/routes/api-handler.ts:34-36` runs `verifyToken` and then `assertNotRevoked` on every `/v1` request except `/v1/meta`. This happens before the body is read and before the vault Durable Object call (`:41`). `worker/src/auth/revocation-check.ts:10,15-20` uses a single `idFromName('global')`; an error gives `503` with `Retry-After: 5`, and an answer that is not `false` gives `401`.

**Stored.** `worker/src/revocation/revocation-registry.ts:34-40` holds `revoked_sids`, `revoked_dids`, `min_iat` (per `sub`) and `webhook_events` (15 min TTL, `:26`). `isRevoked` (`:44-49`) is three synchronous point reads. Nothing is pruned (#10).

**Write.** `worker/src/routes/revocation-webhook.ts:67-99`: HMAC, a ±300 s window, a strict body, then `applyBatch` as a single `transactionSync` (`revocation-registry.ts:52-67`). The state is monotonic (grow-only sets plus a max register), so applying batches is commutative and idempotent. A replay returns `409`.

ak-web treats `2xx` and `409` as delivered, and retries anything else 20 times with 30 s doubling backoff (`lib/vault/vault-revocation-delivery.ts:33,38-39,58-61`, branch `feat/vault-device-tokens`). Token TTL is 300 s (`app/api/agentkit/vault/token/route.ts:13`, same branch).

**Promise.**
- spec `docs/protocol/v1/spec.md:413-414` ("every request consults the revocation registry", errors give `503`);
- threat model `:69-70` and S5 `:89`;
- release gates `:93-94` ("refused on its next request even with an unexpired token");
- ADR 0001 `:80`.

In effect, "next request" means the first request after the webhook is acknowledged.

**Why ~10/s.** `docs/operations/cost-model.md:97-98` computes `1 / active time per check` (117 ms and 110 ms). That is an inference, not a measured throughput:
- Cloudflare bills Durable Object duration as wall-clock time shared across concurrent requests, with a soft limit of 1,000 req/s per object.
- The registry read zero rows in the 2026-10-15 run.
- Registry duration per request in the 2026-10-16 phases (cost-model `:73-78`) was about 120 ms for a pull, about 53 ms for a write, and about 24 ms for a refusal, for the same check work.
- The cause of the 110–120 ms is not established.
- DO `cpuTime` is collected (`worker/scripts/cost-measurement/cost-analytics.ts:93`) but not published. The true knee needs a lab ramp test.

## Option verdicts (detail in the #65 comment)
- **(a) Push to vault objects.** There is no sid→vault index and no did/sub→vault index, so gaps fail open. High effort. Rejected on its own.
- **(b) Hash shards.** By sid or did, this needs 3 calls per request. By sub, the webhook would have to carry sub per entry, which changes the webhook body and ak-web.
- **(b′) Replicate: write all, read one.** No wire change, guarantee preserved by holding the ack until every replica has applied the batch. **Recommended.**
- **(c) TTL cache.** Weakens "next request". Needs an owner decision. Not recommended.
- **(d) Per-`jti` vault cache with push invalidation.** This is the cost lever. Its value falls with adaptive polling (300 s tokens), so defer it until #63 item 4 is measured.

## Phased plan
1. **Phase 0 (#65).** Documented GraphQL query plus a scheduled check. The threshold is 4 checks/s sustained over 15 min, plus any sustained `503 unauthorized`. Then run the lab open-loop ramp (5–400 req/s) using registry-only refusals that exercise all three lookups. Record the knee and reset the threshold to 50% of it.
2. **Phase 1.** `global` becomes the coordinator, with replicas `replica-0..N-1`:
   - webhook acks only after all replicas apply; `409` only after the fan-out is complete;
   - replicas seed from the coordinator and fail closed;
   - reads go to `hash(did) mod N`;
   - spec §9.3, threat model S5 and release-gates text change in the same PR; no vectors or Go.
3. **Phase 2.** The (d) cache only if cost data justify it after #63 items 1 and 4.

## Concerns
- Release gates say "a few dozen devices" at 15 s, but 8.5/s × 15 s is about 127 devices at one request per sync. This only holds if a sync makes 3–4 requests, which is not verified.
- The 300 s token TTL and the ak-web retry policy were read from the ak-web branch `feat/vault-device-tokens` (local worktree), not from a confirmed production deploy.
- A scheduled alert needs an analytics-read token in CI. That is an owner decision.
- Every capacity number for the replica count N depends on the Phase 0 lab measurement, which was not run.

## Unresolved questions
- How many requests does one client sync cycle make, and what is the production client interval (15 s default vs. the cost model's 60 s)?
- Does the owner accept a CI-held analytics-read token for alerting, or only a documented manual query?
- Does any retained cost report already hold the registry's `cpuTime`?
