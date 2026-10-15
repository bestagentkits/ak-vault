# Sync P7: devices and recovery (agentkit#2298)

PR: https://github.com/bestagentkits/agentkit/pull/2399 (branch `feat/secrets-sync-devices`, base `dev`).
Merge: squash `1457cd63f0f58d5befa4ff6de61f031cd48092ac` on dev. #2298 has a one-line comment with the PR and the sha.

## What shipped

Parts A and B ship together in one PR, which the coordinator allowed.

**Part A, the runtime** (`apps/cli/internal/runtime/secretsync/`):
- **Enrollment:** enroll codes, approver and joiner (`enroll_codes.go`, `enroll_approver.go`, `enroll_joiner.go`).
- **Removal:** the removal fence with rekey and recovery bundle reseal (`removal_fence.go`, `rekey.go`, `recovery_bundle_reseal.go`).
- **Recovery and rotation:** recover (`recover.go`), recovery rotate (`recovery_rotate.go`) and rotate device (`rotate_device.go`).
- **Shared membership helpers:** `device_membership.go`.
- **Tests:** they use akvfake and faultproxy and cover the crash and resume points.

**Part B, the commands** (`apps/cli/internal/commands/secretscmd/`):
- **New files:** `devices_list.go`, `devices_add.go`, `devices_approve.go`, `devices_remove.go`, `devices_rotate.go`, `sync_recover.go` and `sync_rotate_recovery.go`, plus the helper `sync_recovery_inputs.go`.
- **Registration:** in `devices_cmd.go`, and in `sync_cmd.go` for `recover` and `rotate-recovery`.
- **Help goldens:** under `testdata/help/`.

**Edits to shared and P6 files.** All are minimal and additive.
- `sync_enable.go`: a `kitFile.shown` flag.
- `sync_cmd.go`: registration, plus an `openSyncEngine` hook that repairs a stopped device rotation.
- `sync_exit_codes.go`: the device error mapping in `deviceExitFor`.
- `sync_exit_codes_test.go` and `sync_help_test.go`: new cases.
- `runtime/secretsync/open.go`: open refuses a home whose join or recovery has not finished its first verified cycle.

## Evidence (head 93ecb62a1)

- `go test -race -count=1 ./internal/runtime/secretsync/... ./internal/commands/secretscmd/...`: ok. secretsync took about 430s and secretscmd about 310s.
- `golangci-lint run --config ../../.golangci.yml ./internal/commands/secretscmd/... ./internal/runtime/secretsync/...`: 0 issues. `go vet` is clean.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed, including cmdtree and commitlint.
  - The first run caught a cmdtree help-contract violation: `devices add` had 4 examples and the limit is 3. It is fixed.
- `tools/ci/classify-pr-paths.sh`, run with NUL-delimited input as CI runs it: `os_risk=true`, because `secretsync/*` and `secretscmd/*` are OS-risky paths. The PR carries the `os-specific` label.
  - My earlier local result (`os_risk=false`) was wrong: I had fed the script newline-separated paths.
- **Reviews:** several isolated code-reviewer rounds against REVIEW.md and the design. All Majors were fixed. The final focused re-review of the recovery refusal found no Blockers or Majors.
- **CI:** one pr-gates run. Every required check passed except `required`, which failed only because the `os-specific` label was missing.
  - I added the label and reran that job once (`gh run rerun --failed`), and it passed. The merge state was CLEAN.
  - The native OS matrix lanes were skipped: the repo variable `CI_NATIVE_TESTS_PAUSED=true` has paused native tests since 2026-10-13, so there is no Windows or macOS evidence for this change.
- **Dev full-suite run** 38628677960 (triggered by the merge): it stayed queued after two cancel requests, so I force-cancelled it through the API. It now shows cancelled. I did not touch the merge-train or the auto-semver-release runs.

## Deviations

- **No deselection list for recover.** `sync recover` has no list for deselecting devices. Recovery removes every other device unless `--remove-others=false` or `--keep` is given.
- **List data shape.** `devices list` returns its JSON data as an array.
- **Extra flag.** `devices add` has a `--cancel` flag that deletes a pending join.
- **Recovery from a bundle behind the vault key.** Advised by kongming; this is option B.
  - **The conflict:** after merging P8 (the encrypted audit chain), the verifier needs the key of every audit entry epoch from the device's join epoch onward (spec §7). Spec §4, however, lets a recovery `device_add` carry only the epochs the bundle holds.
  - **The behaviour now:** recovery refuses, before posting anything, a bundle that lacks the current key (`ErrRecoveryBundleBehind`, exit 1). On a first attempt it keeps nothing: no device keys, no vault keys, no sync DB and no config.
  - **The fix for the user:** run `ak secrets devices remove --resume` on a device that still syncs. Recovery then succeeds; this is tested.
  - **Trade-off:** if no syncing device survives a removal that stopped between its rekey and its reseal, that bundle cannot recover the vault. The error text and the help say so.
  - **Removed code:** the earlier attempt to recover past the gap by rekeying was removed.

## Follow-up issues (ai-handle)

- bestagentkits/ak-vault#36: reconcile spec §4 with §7, and record the availability limit in the threat model. Spec changes need an ak-vault PR.
- bestagentkits/agentkit#2397: surface or finish a recovery bundle left behind the vault key during normal sync.

## Unresolved minors from earlier reviews

These were not fixed, and each is a candidate for follow-up.
- **m-B, m-C, m-D and nit 14:** recorded in earlier review rounds and judged non-blocking.
- **`devices add --offer` on resume:** the offer is not parsed again.
- **`refsOfItems`:** if it fails, an operation that succeeded is reported as an error.
- **`lastRemovedDevice`:** it ignores `member_remove` events.
- **`rotate-staging`:** the directory can leak after a failed run. It is cleaned only on success, or when the staging keystore holds no device keys.
- **`ErrRotationPending`:** a queued, unrelated removal bundle triggers it with a misleading message.
- **`RepairRotation`:** it runs outside the home lock.

Status: DONE_WITH_CONCERNS
Summary: Parts A and B are merged to dev as #2399 (1457cd63). The devices and recover commands now exist, with help goldens and crash and resume tests. Recovery refuses a bundle without the current vault key until a syncing device runs `ak secrets devices remove --resume`.
Concerns:
- If no syncing device survives a removal that stopped before its reseal, the bundle cannot recover the vault. This is tracked in ak-vault#36 and agentkit#2397.
- The native OS matrix is paused repo-wide, so this OS-risky change merged with Linux and macOS-local evidence only.
- The unresolved minors are listed above.
- Cleanup:
  - Done: the worktree, the local and remote branches, my wait loops, and my scratch files are removed.
  - Left in place: `/private/tmp/ak-pf.pDwtNk/agentkit-preflight-home.*` dates from 18:19 on Oct 14, before my preflight runs. It looks like another session's, so I left it.
