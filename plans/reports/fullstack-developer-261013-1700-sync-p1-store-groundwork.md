# Sync client P1: store groundwork (agentkit#2298)

**Status:** done, PR open as a draft and not merged.

- **PR:** https://github.com/bestagentkits/agentkit/pull/2323 (base `dev`, label `os-specific`).
- **Branch and worktree:** `feat/secrets-sync-store-groundwork` at `/Volumes/GOON/www/claudekit/agentkit-wt-sync-p1`.
- **Head:** `a92cb0fdb`. Commits: `9f10c0a5c` (feature), `65b31d442` (review fixes), `6d37c1b07` (tests and comments), `486b8c70c` (sidecar self-heal), `55e8263f6` (heal review fixes), `6e04a6162` (sidecar bound, write-order test), `484d38456` (far-ahead sidecar heals), `a92cb0fdb` (gap-edge tests, comments).

## What landed

All changes are in `apps/cli/internal/runtime/secrets/`, inside the P1 file ownership. Note that the design's `runtime/secrets` is `apps/cli/internal/runtime/secrets` in the repo.

- **`index.go`:** additive fields `generation`, `seq`, entry `seq` and `deleted` (the journal keeps the newest 1000), plus the journal, expected-value and validation helpers.
- **`index_sequence_sidecar.go` (new):** the `index.seq` high-water mark (0600), the next-seq rule and the commit order.
- **`store.go`:** Set and Delete bump the seq, Set removes the ref from the journal, and Delete adds it.
- **`store_synced_writes.go` (new):** `ApplySynced`, `DeleteSynced`, `ApplySyncedBatch`, `ReadValues`, `IndexSnapshot`, `ErrSyncPreconditionFailed`, `ErrInvalidSyncedChange` and `ExpectSeqLessEntry`.
- **`agefile.go`:** `getMany` and `applyChanges`, so a batch costs one vault unlock and one decrypt/encrypt.
- **Tests:** `index_seq_test.go`, `index_legacy_rewrite_test.go` and `store_synced_writes_test.go`. The race test is there: a `Set` from a second Store between `IndexSnapshot` and `ApplySynced` gets `ErrSyncPreconditionFailed`, and the local value is kept.

## Where this departs from design rev 2 (P5 must follow these)

1. **Expected-seq tokens.**
   - `0` means "absent" only.
   - An entry written by an older binary has no seq (0 on disk). It needs `ExpectSeqLessEntry` (-1), which `IndexSnapshotEntry.ExpectEntrySeq()` returns.
   - `local_map.entry_seq`, `apply_pending.expect_entry_seq` and the restore-repair `ApplySynced` must store or pass `ExpectEntrySeq()`, never the raw `Seq`.
2. **Stamping.** Every current write gives each seq-less entry the new seq. As a result, expectations read before one batch may not match after it. Callers re-snapshot between batches.
3. **Sidecar order.** The sidecar is written before `index.json` (the design said after), so the mark is never behind the index.
4. **Next seq.** It is computed as max(doc seq, highest entry or journal seq, sidecar seq) + 1.
5. **`DeleteSynced` journals the delete** like a local Delete. Deleting an absent ref succeeds whatever seq was expected.
6. **`index.seq` self-heals** (owner decision).
   - **When:** the sidecar is missing beside an index that already has a generation (an empty file or one without a generation counts as missing); corrupt (unparsable, negative, or at or above `MaxInt64-1`); far ahead (above 2^62 and more than one write ahead of `index.json`); or names a different generation than the index.
   - **How:** the next Set, Delete or synced write rebuilds the mark from the highest seq anywhere in `index.json`, still raised to an in-bounds foreign-generation sidecar's seq (anti-rollback), and assigns one new generation. A seq moves backwards only together with a new generation.
   - **Snapshot:** `IndexSnapshot` reports `RegenerationPending` instead of refusing.
   - **Still failing closed:** I/O errors other than not-exist, a negative seq inside `index.json`, and `index.json` itself at `MaxInt64-1`. The error names the file and the reason, never its contents. No sidecar value can drive a write to that bound.
7. **No ref names in errors.** Errors on the synced paths never name a ref; backend errors are wrapped in a fixed message, and the cause is still reachable through `errors.Is`.

## Evidence (macOS arm64, go1.25.0)

| Check | Result |
|---|---|
| `go test -race -count=1 ./internal/runtime/secrets/` | ok (40.3s at `a92cb0fdb`) |
| `go build ./...` | ok |
| `go vet` (secrets, secretscmd, gui/api) | ok |
| `golangci-lint run ./internal/runtime/secrets/...` | 0 issues |
| `make lint-ascii` | ok |
| `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh` (pre-push, each push) | all gates passed; flagged OS risk, so the `os-specific` label was added |
| secretscmd and gui/api suites (`-race`, at `486b8c70c`) | secrets tests green; only the 2 unrelated failures, filed as #2324 and #2325 |

Through `6e04a6162`, CI was blocked because the organization's Actions budget was exhausted (jobs were not started). At `a92cb0fdb`, `test-os-specific` started: "Select native OS lanes" passed and the Go lanes were queued at the time of writing. The PR stays a draft until every lane is green.

The two unrelated failures, both on this macOS host:
- `gui/api TestPlansAPI_SaveUsesFullIdentityAndRepairsOldRow` also fails on a clean `origin/dev` checkout (`ddd1b947d`).
- `secretscmd TestInspectAdapterBinaryHashesResolvedPath` compares `/var` against `/private/var` paths.

## Review

Reviews were run with the code-reviewer agent, each in a fresh context with no implementation history.

- **Round 1:** no blockers and 4 should-fix items. Three were fixed in this PR: the ambiguous expect-0, ref names in backend errors, and the batch contract. The fourth belongs to the engine.
- **Round 2:** no blockers and no should-fix items. Its nits were fixed.
- **Round 3 (self-heal change only):** no blockers. Four should-fix items were fixed in `55e8263f6`: healing a sidecar from another generation, treating a generation-less sidecar as missing, a non-refusing snapshot, and more tests.
- **Round 4 (delta at `55e8263f6`):** fixed in `6e04a6162`. A sidecar at the bound heals; `index.json` at the bound fails closed and names the file; a fault-injection test checks the write order; a test pins "no generation = missing"; comments corrected.
- **Round 5 (`6e04a6162`):** no blockers. Should-fix: a sidecar just under the bound was carried into `index.json` and then refused every write. Fixed in `484d38456`: a sidecar above 2^62 that is more than one write ahead heals. The test hook is now restored with `t.Cleanup`.
- **Round 6 (`484d38456`):** no blockers. Mutation tests confirmed the condition. The should-fix test gaps (a same-generation far-ahead sidecar, the +1/+2 gap edge) and two stale comments were fixed in `a92cb0fdb`, which also rewrote the gap check so it cannot overflow. A `+2` mutation is now caught. `a92cb0fdb` has tests and comments only, plus that overflow-safe rewrite of the same comparison, and was not reviewed again.

## Follow-ups for the design (rev 3) and P5

- **Detection step 3.** Treat `e.Seq < row.entry_seq` as evidence of a restore. Otherwise a restore of `index.json` alone, followed by a local `Set`, is masked.
- **Replay order.** Replay `apply_pending` before running detection. Otherwise a crash after `ApplySyncedBatch` but before the `local_map` update gets pushed back as a spurious branch.
- **Precondition failure with an unchanged value.** Compare `value_mac` with `local_map`. If it is unchanged, re-apply with the current token instead of dropping the row (design 5.4). Otherwise the remote head is never applied.
- **Store the token.** Name `ExpectSeqLessEntry` in 4.4 and 5.4.
- **Pre-existing store issues (filed as `ai-handle`, linked in the PR).** #2326: Set and Delete errors in `store.go` include the ref. #2327: Set writes the backend before committing the index, so a crash between the two changes a value without bumping the seq. The engine should not assume a value change always comes with a seq bump until #2327 is fixed.
- **Guide (P10).** Document the deletion-journal privacy note (up to 1000 deleted ref names in `index.json`) and the remediation for a corrupt `index.seq`.

## Cleanup

- Removed: the worktree's `node_modules` (installed for commitlint and the pre-push hook), the temporary `origin/dev` baseline worktree, and the scratch logs.
- No preflight temp directories were left behind, and no servers were started.
- The worktree is left in place.

## Unresolved questions

- None blocking. Mark the PR ready once every CI lane, `pr-gates` included, is green at `a92cb0fdb` or a later head.
- Is 2^62 the right trusted limit for a sidecar jump? It is an implementation choice that leaves about 2^62 writes of headroom.
