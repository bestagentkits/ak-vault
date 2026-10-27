# Registry throughput lab: measured knee

Issue #91 · PR #98 (merged as `dd6696d`) · Deploy run https://github.com/bestagentkits/ak-vault/actions/runs/38906401875 (pending; not approved by me)

## Outcome
- The global revocation registry's knee is **about 1,000 checks a second**, between 800 and 1,000.
  - At 1,000/s, registry wall p99 rose to 1,241 ms, from 177 to 199 ms at 400 to 600/s. Wall p50 went to 172 ms and client p50 to 448 ms. There was 1 registry error and no client `503`.
  - 800/s held (wall p99 314 ms).
  - CPU per check stayed flat at 0.20 to 0.23 ms, so this is queueing in the one object.
- The derived 8 to 10/s was wrong by about 100×. It inverted active time, which measures how long the object stays awake, not what a check costs.
- Alert threshold: **500 checks/s** sustained over 15 min, half the knee. It is in the runbook (the section #89 added), the cost model and release gates.

## Method
- Script: `pnpm registry:load` (`worker/scripts/registry-load/`). It deploys a lab Worker (`ak-vault-lab-regload-*`) from the staging config, with a self-signed lab issuer and a random webhook secret.
- Seed: 10k sids, dids and subs through the signed webhook. Each request carried a fresh token for a seeded sub (`min_iat` a day ahead) with a random sid and did. All three lookups ran and the Worker refused `401` (1 row read per check, 0 vault requests).
- Open-loop steps of 55 s, spread over forked generator processes. The knee rule uses the `503` share, unanswered requests above the baseline, and client or registry-wall p99 above 2× the first step's.
- Analytics: per-step Durable Object analytics.
- Cost guard: the worst-case estimate must be under $2 before any traffic.

## Runs (2026-10-16, Worker code `121c9b3`; the refused path is unchanged on main)

| Run | Steps | Result |
|---|---|---|
| 1 (single process) | 5 to 400/s | 0 `503`, wall p99 110 to 234 ms |
| 2 (single process) | 5, 400, 600/s | 400 clean. At 600 the generator fell behind (lag p99 13 s): 96 `503`, 11k no answer. Superseded |
| 3 (multi-process) | 5 to 1,000/s | Knee at 1,000 (table in `docs/operations/cost-model.md#revocation-registry-throughput`) |

- Two attempts aborted before the ramp. In the first, seed webhooks got `404` because the new hostname had not reached every edge. In the second, a control probe lost its connection. I fixed both with a 10-consecutive readiness check and retries.
- Totals: about 294k ramp requests. The worst-case estimates sum to under $1.10; actual cost is likely within the included monthly amounts.
- Cleanup: every lab Worker and its Durable Object namespaces were deleted, and an independent API listing shows 0 `ak-vault-lab-*` scripts or namespaces.

## Files (PR #98)
- `worker/scripts/registry-load/{run-registry-load,registry-load-traffic,registry-load-generator,registry-load-analysis}.ts`, `README.md`
- `worker/scripts/cost-measurement/staging-lab-config.ts` (extracted; `run-cost-measurement.ts` uses it)
- `worker/scripts/platform-log-scan/lab-client.ts`: `privateJwk`/`fromPrivateJwk`, key handed over IPC only
- `worker/test/registry-load-analysis.test.ts`, `worker/package.json` (`registry:load`)
- `docs/operations/cost-model.md`, `docs/operations/runbooks.md` (threshold 4 → 500/s), `docs/security/release-gates.md` (Capacity paragraph)

## Evidence
- `pnpm typecheck`: pass. `pnpm test`: protocol 439, worker 221, all pass. `pnpm build`: pass.
- PR CI: TypeScript, Go cross-verification and secret scan all green. Squash auto-merged.
- Isolated review against REVIEW.md, twice:
  - The first narrowed the claims and exposed the generator limit.
  - The second reported 5 should-fix doc items; I fixed them all and a re-check returned DONE.
- Evidence comment: https://github.com/bestagentkits/ak-vault/issues/91#issuecomment-6216213008. Issue #91 is labelled `shipped`.

## Is Phase 1 (registry replication) needed before GA?
Not for capacity at small or mid GA scale. It depends on the target:
- At the client's 15 s default interval, the knee is about 15,000 active devices and the alert fires at about 7,500, roughly 2,500 vaults of 3.
- At 60 s polling it is about 60,000 devices; 10k vaults × 3 is 500/s, exactly the alert threshold.
- With 5 min adaptive polling (#63 item 4), 10k vaults is about 100/s.
- Replication becomes required before GA only if the GA target exceeds about 2,500 vaults at 15 s polling, or about 10k vaults at 60 s.
- The single object stays a single location and dependency (an availability concern, not throughput). That is the remaining reason for Phase 1 (#10).

## Cleanup
- Worktree, local and remote branch removed. No `.wrangler/`, no `akvault-regload-*` temp dirs.
- My scratch logs and reports deleted. No processes left running.

## Unresolved questions
- The Deploy run for `dd6696d` is pending, probably queued behind the earlier Deploy (`ea0270f`) waiting on the owner's production approval. Only the owner approves.
- The GA scale target (vaults, poll interval) decides whether Phase 1 replication blocks GA. That is an owner decision.
- `docs/operations/rehearsal-2026-10.md:165` still states about 10 checks/s. It is a dated record and was left unchanged.

Status: DONE
Summary: Measured knee is about 1,000 checks/s (between 800 and 1,000), alert at 500/s. Script, docs and evidence are merged in #98; the labs are deleted.
Concerns: Deploy is pending owner approval. The Phase 1 GA need depends on the owner's scale target.
PR URL: https://github.com/bestagentkits/ak-vault/pull/98
Deploy run URL: https://github.com/bestagentkits/ak-vault/actions/runs/38906401875
Measured knee: about 1,000 checks/s (800/s sustained without degradation)
