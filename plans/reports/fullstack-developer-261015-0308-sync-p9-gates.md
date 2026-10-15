# Phase P9 report: sync gates

## Outcome

The sync client gates merged to dev in [#2425](https://github.com/bestagentkits/agentkit/pull/2425) (0944157326c9a0e6a878714fb576962595bb783a), with auto-merge, at 11:58 UTC.

Earlier, the `Go vet (all platforms)` CI step had hit its 12-minute limit in 4 of 5 attempts. #2440 fixed it.

The follow-up [#2446](https://github.com/bestagentkits/agentkit/pull/2446) interleaves the overhead arms. It is open and ready for the batch train, with its preflight receipt in the body. The gate passes on both backends after #2424 (which fixed #2409).

I commented on agentkit#2298 with both PRs. Cleanup is done.

## Executed phase

- Phase: P9 (gates). Design: `plans/261013-1320-8-client-web-gates/agentkit-sync-client-design.md`, §7, §9 and §10.
- Worktree: `/Volumes/GOON/www/claudekit/agentkit-wt-sync-p9`, now removed. Branches: `feat/secrets-sync-gates` (merged and deleted) and `test/secrets-sync-overhead-interleave` (kept on the remote for #2446).
- Status: completed.

## Files (all under `apps/cli/internal/`)

| File | Change |
|---|---|
| `commands/secretscmd/sync_gates_test.go` | New. The sync-off sweep steps for every `sync` and `devices` leaf. A coverage check matches the exact command node a step runs; a negative test proves that same-named leaves cannot cover each other. Setup commands stay offline until their preconditions pass, and then reach only the vault origin. |
| `commands/secretscmd/sync_gates_offline_resolve_test.go` | New. Resolve with sync on is checked twice: against a hung origin while a watcher is stuck mid-request, and with a closed port behind the network guard. |
| `commands/secretscmd/sync_gates_structure_test.go` | New. Structural rules over the whole module:<br>- `runtime/secrets` never depends on sync;<br>- only the sync and devices commands import it;<br>- the akvhttp entry points are reached only from `sync_cmd.go`, with aliases resolved and dot imports refused;<br>- `secretsync` has no init function and no package-level client. |
| `commands/secretscmd/no_network_test.go` | Edited (the #2318 gate): appends the sync steps, checks the counting origins, and asserts leaf coverage. |
| `cmdtree/secrets_no_network_test.go` | Edited: `sync status`, `sync now` and `devices list` now go through the update trigger. |
| `runtime/secretsync/lock_across_http_test.go` | New. Faultproxy holds a cycle inside each request kind: all 8 on the memory backend, and 3 on the file backend, run one at a time. While it is held, the cycle lock must be busy, the index lock and vault lock free, and resolve and Set must finish within the bound. The file cases skip under `-race`. |
| `runtime/secretsync/resolve_sync_overhead_test.go` | New. The three-arm warm resolve overhead rig. It runs as a smoke test by default; `AK_SECRETS_SYNC_OVERHEAD=1` runs the full rig with the gate on. |
| `runtime/secrets/resolve_latency_bench_test.go` | Edited (the #2318 bench): uses the shared helpers. |
| `testhelp/latency_percentiles.go` | New. `Percentile`, `Millis` and `LatencyRig`. |

Ownership deviations:
- The edits to the #2318 files are minimal, so the existing gate is extended rather than duplicated.
- The bench lives in `runtime/secretsync` because `runtime/secrets` must not import sync.
- `testhelp` is shared by both rigs.
- I did not touch `docs/`, `runtime/secretsync/e2e/` or any production code.

## Tests and evidence

- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed. Preflight requires the `os-specific` matrix, and the PR is labelled.
- `go test -race -timeout 30m` passes on every touched package:
  - `secretscmd` took 416 s and `secretsync` 543 s.
  - Under a host load of about 70, both exceeded the default 10-minute timeout. That was slowness, not a hang: the running tests were each at about 20 s when the timeout fired.
- `-count=5 -cpu=2` stress of the overhead and lock gates: pass.
- `go vet` and `golangci-lint` on the touched packages: 0 issues.
- I re-ran the gate tests after each local merge of dev (#2424 and #2423 touch code these gates exercise).
- Mutation checks:
  - holding the index lock across HTTP fails the lock gate;
  - a mismatched or renamed sweep step fails the coverage check.
- Review: four rounds with fresh, isolated reviewers. All blockers, majors and the listed minors are fixed, including a real data race found by `-race` (a transport swap under an in-flight request) and two cleanup deadlocks.

## CI

- First run: Go vet hit the step timeout, and a kitcmd shard runner died. The one rerun was green.
- After merging dev locally twice: green.
- After update-branch (unrelated #2430): vet timed out twice, once on my rerun and once on the coordinator's.
- In the latest log, the test-compile phase took 3.4 minutes. The three cross-OS `go vet ./...` passes then ran more than 8.8 minutes before the kill. setup-go runs with `cache: false`.
- Other PRs ran the same job in 3 to 11 minutes during the same hour. Warm local vet of the touched packages for all 3 OSes takes 20 s.

## Warm resolve overhead (design §7.3)

Rig:
- Apple M1 Pro, 8 CPUs, darwin/arm64, go1.25.0.
- In-process warm resolver.
- 200 timed samples per arm after a discarded warm-up of 50.
- 5 s sync interval; 2000 live refs plus 1000 deletion-journal entries; 5 remote changes per interval.
- File backend scrypt cost 2^18. Overhead = p95(arm) - p95(off). The gate is < 50 ms.

### As merged in #2425: sequential arms, before the #2424 lock fix (load about 4 to 8)

| backend | arm | p50 ms | p95 ms | overhead ms | cycles / applied | overlap |
|---|---|---|---|---|---|---|
| memory | off | 16.99 | 23.59 | - | - | - |
| memory | idle | 16.49 | 24.36 | +0.77 | 6 / 0 | 8 |
| memory | busy | 15.47 | 25.20 | +1.61 | 6 / 5 | 9 |
| file | off | 452.70 | 474.66 | - | - | - |
| file | idle | 467.75 | 521.69 | +47.03 | 19 / 0 | 29 |
| file | busy | 469.31 | 1420.12 | **+945.47 BREACH** | 13 / 12 | 91 |

The file busy arm breached the gate on every run: +936, +920 and +945 ms. The cause was that the age file vault held its lock across the scrypt identity unseal, so a resolve that arrived during the watcher's apply waited for a whole unseal. #2424 fixed this (closing #2409).

### Follow-up #2446: interleaved arms, after #2424 (load about 7)

- Each arm runs on its own identically seeded home, and every round samples off, idle and busy in random order, so host noise lands on all three arms alike.
- The note about the known breach is removed.

| backend | arm | p50 ms | p95 ms | max ms | overhead ms | cycles / applied / pushes | overlap |
|---|---|---|---|---|---|---|---|
| memory | off | 8.94 | 16.16 | 27.58 | - | - | - |
| memory | idle | 9.71 | 17.95 | 36.53 | +1.79 | 6 / 0 / 0 | 8 |
| memory | busy | 9.64 | 17.35 | 138.11 | +1.19 | 6 / 5 / 6 | 9 |
| file | off | 454.76 | 474.88 | 537.67 | - | - | - |
| file | idle | 457.33 | 485.22 | 596.49 | +10.34 | 54 / 0 / 0 | 28 |
| file | busy | 456.59 | 478.65 | 525.04 | +3.78 | 44 / 43 / 51 | 55 |

The run was valid: no arm came out more than 10% below off. The gate passes on both backends.

Caveats:
- The keychain backend was not measured.
- The rig is in-process, not the design's release-build process per resolve.
- In the interleaved rig the sync loops' CPU is shared host load across all arms. The overhead therefore isolates contention on each home's own locks and files, not the cost of the extra CPU work on the machine.

## Follow-up and cleanup

- #2446 was opened from origin/dev under the new batch-train rules: preflight receipt pasted, PR ready, and no auto-merge, update-branch or CI wait. Preflight passed. It printed the os-specific advisory, and the train dispatches that matrix. I verified on macOS only.
- I commented on [#2298](https://github.com/bestagentkits/agentkit/issues/2298#issuecomment-6192228995) citing #2425 and #2446.
- I skipped the full-suite cancel, as instructed.
- Removed: the worktree, the local branches, the remote `feat/secrets-sync-gates`, and my scratch backups and logs. No preflight temp dirs or test processes were left.

Status: DONE_WITH_CONCERNS

Summary: The P9 gates are merged in #2425:
- zero HTTP while sync is off;
- offline resolve;
- no lock held across HTTP;
- structural rules;
- the three-arm overhead rig.

The interleaved rig follow-up #2446 awaits the train. After #2424, the 50 ms gate passes on both backends: file busy is +3.8 ms and idle +10.3 ms at p95.

Concerns:
- Whole-package race runs of `secretscmd` and `secretsync` take 7 to 9 minutes and exceed the default `go test` timeout on a loaded host.
- The keychain backend and a release-build, process-per-resolve run have not been measured.
- The design's §7.2 claim that sync holds no backend lock that blocks resolve held on the file backend only after #2424.

## Unresolved questions

None.
