# Staging rehearsal and cost measurement (#8 gates)

## Outcome
- PR #54 merged at 2026-10-15T15:05Z (squash 9281f61). CI was green: TypeScript, Go and secret scan.
- Evidence log: `docs/operations/rehearsal-2026-10.md`.
- Evidence comment on #8: https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6195252299
- The production deploy of 9281f61 is left for the coordinator to approve.

## Rehearsed

### Staging (3dcec74), UTC
- **Rollback:**
  - 14:05:14: rolled back to 7d807d78 (a94b1ba). Live in about 6 s, healthy.
  - 14:06:28: rolled forward to c2c18885.
- **Kill switch:**
  - 14:07:03: `wrangler deploy --env staging --var VAULT_SYNC_ENABLED:false`. `/v1/*` returned 503 `sync_disabled`; healthz, meta and the landing page stayed up.
  - 14:09:52: restored by rolling back to c2c18885. Sync was back on by 14:10:25.
  - Stale responses appeared for up to 12 s after each switch.
- **Final state:** staging is on the CI-deployed version (3f77991 since 14:34) with sync on.

### Lab Worker (`ak-vault-restore-drill`, deleted 14:56)
The lab ran the real Worker source with a synthetic issuer and drill-only PITR RPCs. Staging has no restore route and accepts only ak-web-minted tokens.
- **Backup, restore and undo:** pass.
  - Integrity verified: same digests and log head, membership chain verifies.
  - The laptop, which witnessed `log_seq` 4, raised `rollback`. The owner, which had only witnessed the backup point, accepted the restored state, as expected.
  - Undo through the returned bookmark restored the exact pre-restore state.
- **`getBookmarkForTime`:**
  - Fails on a young object.
  - Resolves earlier than requested: about 90 s early for a point 107 s old, exact at 318 s.
- **Wire change (#48/#49) upgrade, 3dcec74 to 3f77991, with pre-upgrade backup:**
  - Backfill is correct.
  - Vaults whose removals predate `log_head` are refused by clients, but the Worker still serves them. A reset is needed; restoring a backup does not help.

### Cost (lab at 3f77991, 1,090 calls)
| Input | Measured | Model |
|---|---|---|
| Worker CPU per call | 3.3 ms | 2 ms |
| DO requests per call | 1.98 | 2 |
| Vault DO active time per request | 50 ms | 50 ms |
| Rows written per call | 4.76, pulls included | 0 for pulls |

- At 10,000 vaults with active polling the estimate moves from about $1,039 to about $7,109 a month.
- One revocation registry handles about 10 checks a second.

## Runbook and cost-model fixes (in the PR)
- A rollback restores the target version's vars, so it can re-enable sync.
- CI redeploys replace a rollback.
- `wrangler rollback` without `--name` targets production.
- Propagation delay after a deploy.
- A staging kill-switch procedure.
- Restore steps, including the undo bookmark and the fact that time lookups are approximate.
- The log_head revision reset, and recording the pre-deploy backup point.
- Cost model: measured inputs, revised estimates, and the registry caveat.

## Gaps filed (ai-handle)
- #50: rows written per pull.
- #51: no operator restore path; the spec's re-seed reference is unspecified.
- #52: the Worker serves vaults with pre-log_head removals.
- #53: kill switch and rollback are undone by CI; no fast production kill switch.
- A registry latency measurement was posted on #10.

## Review
An isolated reviewer found no blockers. Seven non-blocking items, one low item, and one stale number found on re-review are all fixed. It reproduced the cost arithmetic.

## Cleanup
- Lab Worker and its DO namespaces deleted.
- Worktree, local branch, `.wrangler/`, synthetic keys and state removed.
- No processes left running.

## Concerns
- I ran `git reset --hard` in the worktree once and discarded uncommitted runbook edits. I reapplied them; nothing else was lost.
- #8 was auto-closed at 14:25 by #46: the phrase "Does not close #8" triggered GitHub's closing keyword. I flagged it on #8 and did not reopen it.

Status: DONE_WITH_CONCERNS
Summary: Rollback and kill switch were rehearsed on staging. Restore, rollback detection, the wire-change upgrade and cost were rehearsed on an ephemeral lab Worker. Runbooks and the cost model are corrected in merged PR #54, the evidence is on #8, and four gaps are filed.
Concerns/Blockers: the staging-side restore needs #51; an authenticated staging run needs the owner's `ak login` against ak-web staging; #8 is closed by mistake.
Unresolved questions: Should #8 be reopened? Is a direct emergency kill switch allowed on production (#53)?
