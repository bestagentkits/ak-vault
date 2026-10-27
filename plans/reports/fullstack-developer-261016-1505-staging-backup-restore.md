# Staging backup/restore release gate (#51)

Status: DONE_WITH_CONCERNS. The gate is met on staging, and PR #77 merged with `Closes #51`.

## PRs
- #73 (merged `6851b0b`): adds the operator point-in-time restore route `POST /internal/v1/operator`.
  - Off (404) unless `VAULT_OPERATOR_SECRET` is set.
  - Requests carry an HMAC-SHA256 signature in the body, bound to the origin and a ±60 s window.
  - A restore is compare-and-swap on the current bookmark. The vault refuses requests from scheduling until a confirmed restart.
  - Only one vault object per request, never the revocation registry.
  - Includes 17 tests, the operator CLI, the rehearsal script, and updates to the runbook, threat model (T8) and data classification.
- #77 (merged `4725a2f`): the evidence and decision docs.
  - Spec §6 drops the unspecified client re-seed: v1 has no automatic re-convergence, and recovery is operational.
  - The ADR 0001 open item is reworded.
  - Runbook: reconciliation bullet and step 8.
  - Rehearsal log: new section "Staging restore (2026-10-16)".
  - Release gates: backup/restore gate ticked (#51 lines only).
  - T8 now cites the staging evidence.

## Staging evidence (UTC)
- The secret was put at 08:33:27 and deleted at 08:43:49. Afterwards `secret list` no longer shows it and the route answers 404.
- Storage mechanics, 08:35:57 to 08:36:01:
  - The bookmark is stable when nothing writes.
  - A restore and its undo each move the bookmark forward.
  - Every replay gets 409.
  - A time lookup on a young object gets 400.
- Client rehearsal, 08:42:20 to 08:42:54, passed:
  - A device that witnessed newer state refuses the restored vault with `rollback`. A device that never saw newer state accepts it, which is the documented limitation.
  - A restored log that regrew past the witnessed position is refused. `checkRollback` alone passes it.
  - The undo returns the witnessed digest, and the device that wrote after the restore then refuses.
  - The pre-genesis restore and its undo work.
- Checks at the head:
  - `pnpm typecheck` and `pnpm test` pass (protocol 385, worker 171).
  - `pnpm vectors` produces no diff.
  - `go test -count=1 ./...` passes.
  - CI is green.
- Review: an isolated reviewer checked against REVIEW.md. Round 1 found no blockers and three should-fix items; all were fixed, and round 2 approved.

## Deploy
- The #77 Deploy run is pending: https://github.com/bestagentkits/ak-vault/actions/runs/38877177114. It is queued behind the #75 run 38876447524, which is waiting for production approval. I did not approve either.

## Follow-ups
- #76 (`ai-handle`): no TS/Go test or vector proves a restored-then-regrown log is refused, and `checkRollback` alone passes it. It also asks to confirm the agentkit client handles this case.

## Owner actions
- Revoke the two synthetic staging device keys, labelled "owner" and "laptop". They are bound to the owner's staging account and were minted around 08:41 to 08:42 UTC.
- The staging CLI session is already revoked: ak-web answers 401 "session has ended".
- Delete `/tmp/akv-staging-restore-home` and `/tmp/ak-dev-51`, which were left for the coordinator.

## Cleanup
- The worktree and local branch are removed, as are the scratch files (including the device seeds and session token).
- The operator secret is deleted on staging.
- No processes I started are running.

## Unresolved questions
- Does the agentkit sync client have a test for a log restored and regrown past the witnessed position? This is tracked in #76.
