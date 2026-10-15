# Phase P6 report: hidden `ak secrets sync` CLI

## Phase Implementation Report

### Executed Phase
- Phase: P6, sync client CLI (`ak secrets sync enable|status|now|settle|disable`, plus an empty `devices` parent)
- Repo: bestagentkits/agentkit. Worktree `agentkit-wt-sync-p6` (now removed), branch `feat/secrets-sync-cli` from origin/dev.
- Status: completed. Merged as PR #2381, squash commit `9e06105b2057f33988c06e2092d6ae3774356cc6`.

### Files Modified
All files are under `apps/cli/internal/`.

- **New, CLI (`commands/secretscmd/`)**
  - Command files: `sync_cmd.go`, `sync_enable.go`, `sync_status.go`, `sync_now.go`, `sync_now_ndjson.go`, `sync_settle.go`, `sync_disable.go`.
  - Support: `sync_exit_codes.go`, `sync_render.go`, `devices_cmd.go`.
  - Tests: `sync_cmd_test.go`, `sync_locking_test.go`, `sync_exit_codes_test.go`, `sync_help_test.go`, `sync_support_test.go`.
  - Help goldens: `testdata/help/secrets_sync*.txt` and `secrets_devices.txt`.
- **Changed, CLI:** `commands/secretscmd/secretscmd.go` registers the `sync` and `devices` parents.
- **Shared files, minimal and additive** (all of them sit outside the P6 file list in design section 9):
  - `runtime/secretsync/engine_still_enabled.go` (new):
    - `stillEnabled` and `setupUnchanged`;
    - the sentinels `ErrConfigUnreadable` and `ErrCorruptState`.
  - `runtime/secretsync/engine.go` and `conflicts_settle.go`: each calls `stillEnabled` once after `lockCycle`.
  - `runtime/secretsync/enable_genesis.go`:
    - `ResolveAccount`;
    - a `setupUnchanged` call in `resumeEnable`;
    - `blankSyncState`, which lets a fresh enable start over a schema-only `sync.db`.
  - `runtime/secretsync/akvhttp/vault_token_source.go`: exported `CheckSession`.
  - `runtime/secretsync/synctest/fake_vault_server.go`: a test fake for use from other packages.
  - `render/json.go`: `SyncErrorInfo` adds a `sync` object to the error envelope.
  - `cmdtree/json_raw_emitter_guard_test.go`: an allowlist entry for the NDJSON writer.
  - `go-test-shards.json`.
  - Tests for the above: `engine_still_enabled_test.go`, `enable_resolve_account_test.go`, `check_session_test.go`, `json_sync_error_test.go`.

### Tasks Completed
- [x] Five hidden sync commands and a hidden, empty `devices` parent.
- [x] Exit codes from design section 2.2:
  - 0-7 keep their shared meanings; 10-14 are new.
  - Each error carries a stable reason and the server code in the JSON envelope.
  - Exit 5 maps to the JSON code `internal_error`.
- [x] Agent refusal: `settle` and `disable --purge` return exit 6 before touching anything.
- [x] Store-target check through `CheckStoreTarget`. `disable` and `purge` skip it, since a moved store is a reason to turn sync off.
- [x] Output:
  - JSON rendering throughout.
  - `now --json` always emits NDJSON.
  - `--watch` backs off on exit 11; it stops on 2, 5, 7, 10, 13 and 14.
  - A watch interrupted mid-cycle still emits that cycle's report, and an alarm that arrives with the interrupt still fails closed.
- [x] `disable --purge` removes:
  - the OS keystore entries, first;
  - all sync state, under the cycle lock, with `config.json` last.

  The lock files are kept: unlinking a held lock file lets a third process lock a new inode at the same path.
- [x] `disable`, purge and `enable --resume` re-read the config under the lock. The engine's resume does the same.
- [x] Sync off means zero HTTP. Tests cover a home where sync was never set up and a set-up but disabled home.
- [x] Tests cover:
  - exit codes, the agent refusal and the help goldens;
  - an enable, now, status round trip between two homes against akvfake;
  - lock interleavings for disable, purge and resume;
  - the watch backoff sequence.

### Tests Status
- `go test -race -count=1` on secretscmd, `secretsync/...`, render, `cmdtree/...` and `lint/...`: all ok. This was the last full run before the final two small edits; preflight reran the scoped suites after them.
- `go vet` is clean, and `golangci-lint` reports 0 issues on the touched packages.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh` passed every gate after the dev merge. Before that, biome and commitlint had failed because `node_modules` was missing (fixed by `pnpm install`), and commitlint had rejected a body line over 100 characters (fixed by amending before the push).
- PR CI ran once and was green:
  - Go checks, the three kitcmd shards and the shard union, Go vet on all platforms;
  - risk-selected contracts, source policy, `required` and `os-required`.
- Review: fresh isolated code-reviewer rounds 3 to 6 ran in this part of the session. Round 6 found no blockers or majors; the remaining minors are listed under Concerns.

### Issues Encountered
- **Native OS lanes did not run.** The `os-specific` label was applied because preflight reported Go OS risk. However, the repository variable `CI_NATIVE_TESTS_PAUSED=true` skipped every native OS lane; `os-required` passed and reported the pause. This was not caused by this PR.
- **Push went over SSH.** The worktree's `origin` is configured for SSH, so the single push used SSH rather than HTTPS.
- **Housekeeping after merge:**
  - The dev `full-suite` run for the merge commit (38595220534) was cancelled.
  - #2298 got a one-line comment with the PR and merge sha.
  - The worktree and the local and remote branches are removed, and no preflight temp dirs remain.
  - Deleting the remote branch set off the main checkout's pre-push preflight hook. It is read-only and passed, and nothing in the main checkout was edited.
- **Filed** agentkit#2379 (`ai-handle`): concurrent fresh enables on one home are not serialized.

### Next Steps
P7 (devices and recover) can fill the `devices` parent. Help text already points users at `ak secrets devices add` and `ak secrets devices remove`.

Status: DONE_WITH_CONCERNS

Summary: The hidden `ak secrets sync` CLI is merged to dev in #2381 (9e06105b2). It has exit codes, the agent refusal, NDJSON watch output, locking that re-reads config under the cycle lock, and zero-HTTP-when-off tests, with race, lint, preflight and CI green. The remaining concerns are recorded deviations from the design and minor edge cases, none of which is a blocker.

Concerns:
- **Deviations from design section 2.3:**
  - there is no `--pull-only`;
  - the status, now and settle JSON have fewer fields and identify items by `item_id` instead of `ref`;
  - settle's `resolved` list comes from a status diff read outside the lock.
- **Hints name commands that do not exist yet:** `ak secrets devices add` and `remove`, until P7 lands.
- **Disable and purge still resolve the current backend.** If the environment now selects `memory` or an unknown backend, they exit 2.
- **Purge refuses when `config.json` is missing,** even if leftover state remains.
- **Stale alarm after purge and re-enable:** `lockCycle` checks the stored alarm before re-checking the config. A long-running watch can therefore report exit 13 instead of 10.
- **Error codes for exits 1 and 14** fall back to the shared heuristic. `sync.reason` is the stable key.
- **A kit from a failed fresh enable is kept on purpose,** never deleted.
- **Keychain entries can be orphaned** if a fresh enable is interrupted. This is on the engine side.
- **Concurrent fresh enables** are tracked in #2379.
- **Test coverage gap:** the tests use the memory keystore only. There is no file-backend end-to-end test.
- **Design calls left open:** a second-vault guard, and the agent policy for `enable`.

## Unresolved questions
- Should `disable` and `purge` work when the environment now selects a backend that sync refuses? This is a product decision about users moving off a store.
- Should native OS validation be resumed (`CI_NATIVE_TESTS_PAUSED`) and run on dev, so this change gets the full-module Go matrix?
