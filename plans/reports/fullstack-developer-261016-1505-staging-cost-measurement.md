# Staging cost measurement (#50 / #8 cost gate)

## Outcome
PR #75 (https://github.com/bestagentkits/ak-vault/pull/75) squash-merged (`aafd812`), `Refs #50`. Gate NOT ticked: measured on a lab Worker built from the staging commit/config, not on the staging Worker. Owner decision requested on #8.

## Why not the staging Worker itself
- Staging trusts only ak-web staging tokens; owner decided 2026-10-16 (#8) "no authenticated staging session will be used"; runbook says staging no longer uses a test-only issuer.
- A synthetic-issuer override on staging would reverse those decisions and leave permanent synthetic vault/registry rows (no delete route). Advisor (kongming) concurred. Fork posted: https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6211030336

## What shipped
- `worker/scripts/cost-measurement/` (`pnpm cost:measure`): staging baseline (read-only GraphQL), lab Worker from `env.staging` of wrangler.jsonc (only name, synthetic issuer, webhook secret differ), phased workload (pull no-op, push, device add, device remove+rekey, revocation), per-phase GraphQL (workersInvocationsAdaptive, durableObjectsInvocationsAdaptiveGroups, durableObjectsPeriodicGroups, durableObjectsSqlStorageGroups), lab deletion verified.
- `cost-projection.ts` + `worker/test/cost-projection.test.ts` (pins published figures).
- `deleteLab` moved into lab-worker-lifecycle.ts with lab-name guard; `saigonStamp`/`outsideRepository` exported from scan-options.ts.
- Docs: cost-model.md (Measured 2026-10-16 section, estimates 100/1k/10k/100k lazy+active, per vault/device, levers table); release-gates.md cost-gate bullet only; docs/README.md nav.

## Measured (lab at b49865c, staging config, 1,104 requests, 08:17-08:33 UTC)
| Op | CPU | DO req | Duration GB-s | Rows read | Rows written |
|---|---|---|---|---|---|
| No-op pull (steady) | 1.9 ms | 2 | 0.0116 + 0.0150 | 6.6 | 4.74 |
| Item write | 2.0 ms | 2 | 0.0085 + 0.0066 | 16.2 | 13.2 |
| Device add (2 req) | 8.1 ms | 4 | 0.028 | 24.8 | 17.8 |
| Device remove + rekey (3 req) | 7.0 ms | 6 | 0.028 | 48.4 | 30.1 |
| Revocation webhook | - | 1 | - | 1 | 5 |
| Refused revoked request | 2.8 ms | 1 | 0.003 | 1 | 0 |

- Rows/pull reproduced (4.76 -> 4.74). DO active time per pull higher than 2026-10-15 (vault 90 ms, registry 117 ms; unexplained) -> registry ceiling ~8.5 checks/s.
- Projection 10k vaults active: ~$7,426/mo (rows written $6,166). Levers: zero-write pulls ~$1,288; + cached registry ~$850; 5-min polling alone ~$1,509; all three ~$193.
- Staging baseline (7 d to 08:12 UTC): 1,779 Worker req, 0 err, 19 vault / 21 registry DO req, vault 245,760 B stored.

## Evidence
- `pnpm typecheck` green; `pnpm test` protocol 385/385, worker 178/178 (after rebase on 6851b0b).
- CI on PR #75: TypeScript, Go cross-verification, Secret scan all pass.
- Isolated code-reviewer vs REVIEW.md: no blockers; all should-fix items fixed (cleanup status on every path, flushed exit, not-sampled storage, pinned figures, report-dir check), re-reviewed.
- Both lab Workers (`ak-vault-lab-cost-20261016151256`, `-151555`) confirmed deleted, 0 DO namespaces.
- No deploys/traffic to staging or production by me.

## Issues / labels
- #50: assigned, `in progress` -> `in review` -> removed both (left open: PR is Refs, real fix is zero-write pulls). `done` not set because the PR does not close it.
- Comments: #50, #63 (lever table), #8 (fork + evidence).

## Deploy
Run https://github.com/bestagentkits/ak-vault/actions/runs/38876447524: staging success, production waiting for owner approval (not approved).

## Cleanup
Worktree removed, lab temp dirs gone, scratch removed, no wrangler/harness processes.

## Notes
- 2 of 720 polls returned 401; cause not established (possibly harness network retry refused as proof replay).
- Staging analytics later in the day showed new vault DO traffic (146 req, 6 errors over 7 d), likely the concurrent #51 restore work; not investigated.

## Unresolved questions
- Owner: accept method (b) (lab at staging commit/config) as meeting the cost gate, or require (a) synthetic issuer on staging?
- Why DO active time per pull varied (50 ms vs 90 ms vault) between runs.
