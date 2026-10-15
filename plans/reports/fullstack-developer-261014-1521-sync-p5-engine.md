# Sync engine (agentkit#2298, engine phase): implementation report

- PR: https://github.com/bestagentkits/agentkit/pull/2375 (base `dev`, label `os-specific`)
- Branch commit: 6f938a417, squashed onto origin/dev 90d0e5ede
- Merge sha: 3fa9a5b9afa8dfac84ffb99adba495c40dc1bb0c (squash-merged into `dev`). The dev full-suite run it triggered (38573656536) was force-cancelled, and #2298 got a one-line comment.
- Package: `apps/cli/internal/runtime/secretsync/`, top-level files only. `internal/akvfake` and `internal/faultproxy` come from dev (#2364) unchanged. No new packages, so `go-test-shards.json` is unchanged.

## Public API (for the CLI and settle phases)

- `Open(ctx, OpenOptions)` and `Enable(ctx, EnableOptions)` (resumable). Both return `(*Engine, Report, error)`.
- `Engine.SyncOnce(ctx, SyncOptions)`, `Engine.Settle(ctx, ref, keep, opts)` with keep `local`, `remote` or `KeepBranchPrefix+id`, and `Engine.Close()`.
- `ReadStatus(ctx, dir, target)`, `ReadConfig`, `WriteConfig`, `CheckStoreTarget`.
- `HTTPTransport`, `PayloadFromLocal`, `LocalFromPayload`, `PayloadKind`, `IsAlarm`.
- Report attention codes are listed in `engine.go`: conflict, item_quarantined, discarded_deleted_remotely, skipped_repair, repaired_vanished, unapplied, recovery_enrollment, mass_delete_blocked, rekey_pending, local_only, legacy_rewrite and push_refused.
- Errors: `ErrSettlePending`, `ErrNoConflict`, `ErrNotSynced`, `ErrInvalidOptions`, `ErrPushRefused`, `ErrMissingVaultKey`, and `*AlarmError`. An alarm is persisted.

## Deviations from the design, with reasons

1. **A replaced index uses a "replaced" detect mode instead of exiting with code 2.** Sync keeps running, nothing is deleted remotely, and the change is reported.
2. **Held applied and replayed positions are kept in memory only.** A crash means the next process re-verifies them from the log.
3. **Checkpoints are posted directly, not through the outbox.**
4. **Head digests are never pruned.**
5. **`config.json` is written last on enable.** This is what makes enable resumable.
6. **Outbox rows complete only once they appear in the log.**
7. **Refused records:**
   - A refused record is parked and reported.
   - It is dropped after 3 permanent refusals; the secret is flagged local-only.
   - Deletions are never dropped.
8. **Settle:**
   - It returns `ErrSettlePending` while own rows are queued.
   - It can find a deleted item by its branch.
9. **A Set that crashed mid-apply is detected only when the remote moves.**
10. **Local-only items are not reconciled with remote heads.**
11. **There is no writer-role check.** Vaults are owner-only in v1.
12. **Deleted-item markers (added during review).**
    - After a deletion, the mapping row is kept with a zero value MAC, the last metadata MAC and the tombstone revision.
    - Restores, legacy rewrites and crashed applies therefore never resurrect a deleted secret.
    - A live ref under a marker is treated as the deleted secret coming back, and kept local, in either case:
      - its metadata matches the marker;
      - it was last rotated before the verified tombstone was signed.
    - Any other ref under a marker is a deliberate write and becomes a new item.
13. **A `409 tombstoned` answer is acted on only once the verified head's tombstone revision passes the record's base.** Until then the row waits and is reported as push_refused/tombstoned.
14. **A `bad_request` answer to a checkpoint raises the rollback alarm.**

## Evidence (at 6f938a417)

- `go test -race -count=1 ./internal/runtime/secretsync/...`: all 6 packages ok.
- `go vet`: clean.
- `golangci-lint run --config ../../.golangci.yml ./internal/runtime/secretsync/...`: 0 issues.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed, receipt written.
  - It flagged OS risk (full-module Go), so the PR carries `os-specific`.
  - Branch commits failed commitlint because their headers were longer than 100 characters, so the branch was squashed into a single commit before the push. The tree is identical.
- Full-module `go test ./...` on macOS: 221 packages ok and two failures, both in packages that do not import `secretsync`. `kitcmd` hit the default 10-minute timeout under full-machine parallelism; CI runs it sharded and it passed there. `runtimeprobe` failed on a host-dependent known-install probe. The diff touches only top-level `secretsync` files..
- CI: one run (38572628376 plus the os-specific workflow 38572629683), all required checks green: Go checks, Go vet on all platforms, kitcmd shards, risk-selected contracts, source policy, `required` and `os-required`. Native OS lanes were skipped by their selector..

Benchmark (Apple M1 Pro, `-benchmem`, count 3):

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| StateDigest2000 | 1.64-1.82 ms | 1.09 MB | 8030 |
| StateDigestInitialPull2000 | about 1.59 s | 1.1 GB | 8.06M |

## Review rounds

Each round used a fresh, isolated code-reviewer, judged against REVIEW.md, the design (including its Revision 3 notes) and the spec.

- **Rounds 1-7:** fixes before the session summary. See the branch history in `backup/sync-p5-pre-squash`, which is deleted at cleanup.
- **Round 8:**
  - Restore resurrected deletions; fixed with markers.
  - A second legacy rewrite was missed; fixed.
  - A crash followed by a delete resurrected a create; fixed with create markers and a replay journal check.
  - A checkpoint `bad_request` was swallowed; fixed.
- **Round 9:**
  - A stale marker seq forced restore mode.
  - A kept ref stalled a new remote item.
  - Both fixed.
- **Round 10:**
  - A re-create at a stale marker base was refused and then deleted; fixed by making the re-create a new item.
  - Legacy stamping and two restores; fixed by matching the metadata fingerprint.
- **Round 11:**
  - A re-create behind a refused own deletion was deleted; fixed with settleOwnDeletion and in-order reseal.
  - A restored older version of a deleted secret was resurrected; fixed with the tombstone signed-time rule.
- **Round 12:**
  - Major: an own deletion refused under a re-created head stayed pending forever; fixed.
  - An orphan drop dropped the marker; fixed.
- **Round 13:**
  - Blocker: an unverified `409 tombstoned` deleted a local edit.
  - Major: settle checked the head revision instead of the tombstone revision, so a re-create was lost to a race.
  - Both were fixed with the verified-tombstone gate and regression tests.
- **Round 14:**
  - No blocker or major.
  - Minor findings fixed: an own deletion undone by a peer's re-create is now reported, a test now covers the dropped re-create marker (mutation-checked), and a stale comment was corrected.

## Accepted trade-offs and residual risks

- The tombstone signed time trusts the signer's clock. A peer with a far-future clock keeps restored copies of its deleted secrets local.
- An edit made after a crash during a create-apply becomes a new item and then a conflict. Nothing is lost.
- A crashed edit-apply followed by a delete becomes a branch.
- A crash, then a create and delete of the same name, deletes the remote item.
- A checkpoint `bad_request` reuses the rollback alarm code.
- A value kept local after a restore is overwritten by a later remote head.
- A deliberate write under a restored or legacy index stays local, and is reported.
- A non-author retire can leave an open branch.
- The value-only same-value link is kept.
- The deletion journal has a cap.
- A server that keeps answering tombstoned without a verified deletion leaves the row pending. This is reported every cycle.

## Open questions

- Should a checkpoint `bad_request` get its own alarm code instead of rollback?
- Should the tombstone signed time be bounded by local receive time to limit clock skew?

Status: DONE_WITH_CONCERNS
Summary: The sync engine shipped in #2375 (merge 3fa9a5b9a) after 14 isolated review rounds, the last with no blockers or majors. Race tests, vet, lint, preflight and CI are green, and the state digest takes about 1.7 ms at 2000 items.
Concerns: (1) The accepted trade-offs above, chiefly the clock-trusting tombstone rule and the reuse of the rollback alarm code. (2) Rounds 1-7 history survives only in the review transcripts, because the branch was squashed for commitlint. (3) The local full-module Go run had two failures outside this package (kitcmd timeout, runtimeprobe host probe); they were not investigated and no issue was opened.
