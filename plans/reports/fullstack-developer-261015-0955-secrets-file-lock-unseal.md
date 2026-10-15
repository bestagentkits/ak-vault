# File vault: unseal before the vault lock (agentkit#2409, refs #2298)

**Status:** merged. PR https://github.com/bestagentkits/agentkit/pull/2424 was squash-merged to `dev` as `5ad4e671e`. Issue #2409 is closed and labelled `done`. Follow-up #2411 is filed (`ai-handle`).

## Root cause (confirmed)

`AgeFileBackend` ran `vaultIdentity`, the scrypt unseal of the vault key (about 450 ms at 2^18), inside `withLock`, the cross-process vault lock. Every vault operation did this, through `load` -> `decrypt` -> `vaultIdentity`.

A sync cycle calls `ReadValues` -> `getMany` and `ApplySyncedBatch` -> `applyChanges` -> `mutate`. Each call holds the vault lock for one full scrypt. `Store.Get` (resolve) takes no index lock, but it does take the vault lock, so it queued behind one or two scrypt runs.

The A/B probe below confirms this. Before the fix, busy p95 rises by about two scrypt durations (+930 ms) while p50 stays flat.

## Fix

The fix is in `apps/cli/internal/runtime/secrets/`.

- **`agefile_vault_key_unseal.go` (new):** `prepareUnlock` primes the passphrase, then calls `unsealEarly`, which runs scrypt with the cached passphrase only. It never prompts and never zeroes the cache, and any failure returns nil. Under the lock, `vaultIdentity` re-reads the key file and uses the early identity only if the bytes are identical. Otherwise it unseals under the lock as before, with the same `ErrPassphraseIncorrect`/`ErrPassphraseStale` and `ZeroIf` behaviour.
- **`agefile.go` and `recovery.go`:** the call sites pass a `vaultUnlock` value instead of the `fresh` bool, and `vaultIdentity` moved to the new file. There is also a test-only `beforeKeyUnseal` hook field.
- **`passphrase_cache.go`:** adds `peek()`, which returns the cached passphrase and never prompts.
- **What did not change:** the body read-modify-write, the rollback mark, the vault sequence and every Store path (`store*.go`, `index*.go`). Seq and generation, the expected-seq preconditions, a batch in one lock, crash ordering, and no lost update between `Set` and `ApplySynced` all hold.

## Evidence

The host is macOS arm64, an Apple M1 Pro with 8 cores, running go1.25.0. It was shared with other agents, at load averages of 5 to 60.

**Direct A/B probe.** This is a scratch test, not committed. Each build was run twice, alternating after/before/after/before at load average about 5 to 10. Setup:

- a warm `Store.Get` on a file vault at scrypt 2^18 with 2000 refs;
- the applier runs `ReadValues` plus a 5-ref `ApplySyncedBatch` every 1 s;
- 6 interleaved off/on rounds of 20 samples each, paced at 150 ms;
- the before build uses `go test -overlay` with the `origin/dev` `agefile.go` and `recovery.go`.

| build | off p95 | on p95 | overhead p95 |
|---|---|---|---|
| before | 454 / 461 ms | 1387 / 1382 ms | +933 / +922 ms |
| after | 469 / 469 ms | 490 / 507 ms | +20 / +38 ms |

**Full three-arm rig.** This is the P9 `resolve_sync_overhead_test.go`, copied read-only from `agentkit-wt-sync-p9` for measuring only and never committed. Settings: `AK_SECRETS_SYNC_OVERHEAD=1`, backend `file`, live=2000, journal=1000, 200 runs, 5 s interval, pace 150 ms, 5 changes per interval, scrypt 2^18.

**The gate does not have a valid pass on this host.** In 6 of the 7 runs, the rig's validity check failed: the off arm, measured first, came out slower than an arm with sync on. In the 7th run (before1, pre-fix), the off arm was slower than in the P9 clean run but not by enough to trip that check. The before builds (P9 clean run, before1, before3, before4) still show the breach. These are all the runs:

| run | load avg | off p95 | idle p95 (overhead) | busy p95 (overhead) | rig verdict |
|---|---|---|---|---|---|
| P9 reviewer run, pre-fix | n/a | 475 | 522 (+47) | 1420 (+945) | busy breach |
| before1 | ~30 | 1368 | 3082 (+1714) | 4005 (+2637) | breach |
| before3 | ~20-27 | 1850 | 2024 (+174) | 1434 (-416) | invalid |
| before4 | ~14-17 | 944 | 675 (-268) | 1686 (+742) | busy breach |
| after1 | ~13-65 | 5499 | 937 | 1419 | invalid |
| after3 | ~21-38 | 8875 | 3404 | 1324 | invalid |
| after4 | ~12-14 | 868 | 730 (-138) | 727 (-141) | invalid |

Comparing busy against idle within one run removes the inflated off arm. That gives +1010 ms before (before4) and -3 ms after (after4). Two runs never finished: after2 died with an earlier session, and a first pre-fix baseline was also disturbed.

**Checks at the merged head (`fd974be00`, after merging `origin/dev`):**
- `go test -race -count=1 ./internal/runtime/secrets/...`: ok (79s).
- `go test -race -count=1 ./internal/runtime/secretsync/`: ok (433s).
- `go vet`: clean.
- `golangci-lint ./internal/runtime/secrets/...`: 0 issues.
- `make lint-ascii`: ok.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed. It flagged OS risk, so the PR got the `os-specific` label.
- CI, one run: `required`, `os-required`, Go checks, kitcmd shards, vet and source policy all passed. The native OS lanes were skipped because of the repo-wide `CI_NATIVE_TESTS_PAUSED=true`.
- The dev `full-suite` run that the merge triggered (38708064981) was cancelled.

**Regression tests (`agefile_vault_key_unseal_test.go`):**
- `TestStoreGetDoesNotWaitForAnInFlightSyncedApplyUnseal`: a reader in a second process completes `Get` while the apply's unseal is held. It fails on the old behaviour (vault lock timeout).
- `TestAgeFileWriteDiscardsAnEarlyUnsealWhenTheVaultKeyChangesBeforeTheLock`: an `UnlockWithRecovery` that lands between the early unseal and the lock gives `ErrPassphraseStale`. The vault still opens with the new passphrase, and the refused write did not land. It fails if the bytes recheck is removed.
- `TestPrepareUnlockNeverPromptsForAnEarlyUnseal`.
- I confirmed these with mutation overlays, and the reviewer re-confirmed them independently, adding a `peek` -> `Value` mutation.

## Review

A fresh, isolated code-reviewer found no blockers.

- **SHOULD-FIX:** scrypt is no longer serialized across processes, so peak memory is now the number of concurrent opens times about 256 MiB. I took kongming's counsel. The old bound was incidental, not a guarantee. Restoring it would bring back the resolve wait, and a per-process cache does not help one-shot resolves. I documented the trade-off in the file header and the PR, and filed #2411: measure first, then consider a watcher identity cache together with a rig update, or a bounded semaphore.
- **NITs:** the doubled scrypt on the error path, and writers still waiting for each other under the index lock. Both are now in the header comment.

## Cleanup

- Removed the worktree `agentkit-wt-secrets-lock` and the local and remote branch `fix/secrets-file-lock-unseal`.
- The P9 rig copies were never committed and are deleted.
- Removed the scratch test binaries. No preflight temp dirs were left and no processes are running.
- The scratch logs (`rig-runs.log`, `probe-runs.log`) are kept in the session scratchpad.

## Unresolved questions

- The official rig gate needs a run on a quiet host, ideally with `AK_SECRETS_SYNC_OVERHEAD_BACKENDS=file` and nothing else running. On this shared host the off arm is always inflated, so the rig reports the run as invalid, and that is a property of the host, not of the fix.
- Should the P9 rig measure its off arm last, or interleave the arms, to resist drift? That is P9's file, so I did not change it.
