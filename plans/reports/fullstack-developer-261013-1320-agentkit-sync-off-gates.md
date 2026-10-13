# agentkit: sync-off gates for ak-vault (#8, agentkit#2298)

Status: DONE_WITH_CONCERNS. PR: https://github.com/bestagentkits/agentkit/pull/2318 (into `dev`, label `os-specific`). Branch `feat/vault-sync-off-gates`, worktree `/Volumes/GOON/www/claudekit/agentkit-wt-vault-gates`.

## Changes
- `apps/cli/internal/runtime/autoupdate/trigger.go`: `secrets` added to `excludedTopLevel`, so no `ak secrets ...` command, including the hidden `secrets resolve`, can spawn the auto-update runner. No other top-level command is a secret surface. The other importers of `runtime/secrets` (diagnostics export, support report, update report bundle) only use the redactor. A unit test case was added in `trigger_test.go`.
- `apps/cli/internal/testhelp/network_guard.go` (+ test): `GuardNetwork(t)` fails and records every dial through `http.DefaultTransport` and `net.DefaultResolver`. It also points the proxy variables at a loopback listener that records connections. Its comment documents the limits.
- `apps/cli/internal/cmdtree/secrets_no_network_test.go`: runs the secrets commands through the real root with an overdue auto-update schedule. It asserts 0 spawns and 0 connections, then runs a positive control that must spawn. It fails if the exclusion is reverted (verified).
- `apps/cli/internal/commands/secretscmd/no_network_test.go`: runs the full command matrix on memory and file backends under the guard. The matrix covers set, get, get --reveal, list, rotate, the resolve approval path (exit 8), approve once, the resolve retry, grant, grants, resolve, audit, revoke, and delete. `TestResolveSucceedsWithTheNetworkUnreachable` locks offline resolve, and its comment says sync must keep it green.
- `apps/cli/internal/runtime/secrets/resolve_latency_bench_test.go`: `BenchmarkResolveLatency` (p50-ms/p95-ms metrics) plus the opt-in `TestResolveLatencyReport` (`AK_SECRETS_RESOLVE_LATENCY=1`). Both print the rig line.
- Docs: `docs/guides/secrets.md` ("Network use", "Resolve latency baseline"), `docs/specs/project-lifecycle-spec.md`, and the `ak:ak` SKILL.md auto-update exclusions. The contribution catalogs were regenerated.

## Numbers (M1 Pro, macOS 27.0.1, go1.25.0, N=100, scrypt 2^18)
| case | p50 ms | p95 ms |
|---|---|---|
| memory/warm | 3.12 | 3.68 |
| file/warm | 464.2 | 503.5 |
| file/cold | 460.8 | 510.1 |

## Evidence
- `make -C apps/cli lint`: ascii PASS, flags PASS, golangci 0 issues.
- Touched packages: `go test` all ok.
- The pre-push preflight (`PREFLIGHT_BASE=origin/dev`) passed every gate at the exact head, including `package-kits` TestProduction. An earlier run had one load flake (`TestSpawnDetachedReturnsBeforeChildExits`, 641ms against a 500ms budget) that passed on rerun.
- Full `make test` locally: the remaining failures also fail on a pristine `origin/dev` worktree here:
  - `/private` vs `/var` temp-path assertions in secretscmd trust, plancmd, and gui/api.
  - The pi security hooks test.
  - kitcmd hit the 10m timeout under the full run.

## Concerns
- **The file backend has no warm vault-identity cache.** It caches only the passphrase, so file/warm is about the same as file/cold (~460 ms, scrypt-bound). The "identity cached in process" warm state the gate assumed does not exist today. In addition, each `ak secrets resolve` is a fresh process. Only memory/warm (~3 ms) isolates the non-crypto path. The ak-vault <50 ms p95 target needs an agreed baseline: memory or keychain warm, or a future identity cache, which is a security design decision and out of scope here.
- The guard cannot see a raw dial to a literal IP made with a custom dialer. The proxy-env route is cached once per process by net/http. Both limits are documented in the guard.
- This machine's SSH push dropped during the ~20 min pre-push hook. The final push used SSH keepalive.

## Unresolved questions
- Which warm baseline should ak-vault #8 hold the <50 ms p95 sync budget against: memory, keychain, or a future in-process identity cache?

## Review fixes (PR #2318, review 261013-1633)

Commit `ba13200a9` (test(secrets): guard every secrets command and define the latency gate) on `feat/vault-sync-off-gates`. Not merged.

- **Coverage.** The guard is now installed before the first command, including `recovery init` on the file backend. The secretscmd matrix covers every registered `ak secrets` subcommand on memory and file:
  - recovery init/list/add/remove/accept-rollback (file only);
  - import-env, and export both metadata-only and `--include-values`;
  - trust (show) and `trust --refresh`. Refresh uses an executable fake adapter on PATH, and its `--version` runs under the guard. The test asserts the recorded version hint, which proves the exec happened. It is skipped on Windows.
  - The keychain backend is not exercised; the docs say so.
- **Exact codes in cmdtree.** `callerWalkExpectations` reads `secrets.ResolveCaller` once under the isolated home and maps each outcome to one exact code:
  - an agent above gives approve 6 and resolve 8;
  - a path or hash mismatch gives 6 and 6;
  - no agent above gives 0 and 6.
  - Locally, under Claude Code, the agent branch ran. A detached run (parent reparented to launchd) exercised the no-agent branch, and both passed. CI exercises the no-agent branch.
- **Guard limits.** The comment now states that a plain `net.Dial` to a literal IP or a hosts-file name such as `localhost` is not seen, and that sync must use an explicit dialer seam. The new `TestNetworkGuardDoesNotSeeDirectDials` pins this behaviour.
- **Latency.**
  - The header and docs define the gate as p95(sync on) − p95(sync off), on the same backend, process model and machine, held on memory, keychain and file, citing ak-vault PR #26.
  - memory/warm is labelled a synthetic floor.
  - Opt-in keychain/warm and keychain/cold cases sit behind `AGENTKIT_SECRETS_KEYCHAIN_E2E=1`, the variable the existing keychain e2e test already uses, so CI never sets it. They use a run-unique ref, and cleanup deletes it; I verified the keychain is clean afterwards.
  - The scrypt factor is printed per case, and the b.N=1 calibration pass no longer logs.
  - The docs list the exclusions: process start, the caller walk, resolveProject, the redaction manifest and the JSON render.
  - benchtime is 30x in both the header and the docs.
  - No key cache was added.
- **Nits.**
  - The trigger.go comment now says the exclusion covers the non-JSON commands and is only a backstop for resolve, which `--json` already skips.
  - The offline test comment says it proves no network is used, and that sync must add a hung-network test with a time bound.
  - The docs' "Three tests" count is fixed, and each test is named.
- **Built-binary check.** The docs state that in-process tests are sufficient for now and that there is no built-binary check.
- **Claims narrowed.** The ak-ak SKILL.md now says only that secrets commands never start the update runner. The catalogs were regenerated.

Keychain numbers (N=50). Keychain access was granted without a prompt, but the run was under heavy load (load average 55-100 on 8 CPUs), so the numbers are inflated:

| case | p50 ms | p95 ms |
|---|---|---|
| memory/warm | 5.000 | 14.176 |
| keychain/warm | 60.029 | 117.651 |
| keychain/cold | 45.516 | 79.621 |
| file/warm | 658.4 | 2000.5 |
| file/cold | 900.7 | 2241.8 |

The quieter N=100 memory and file numbers above still stand.

Evidence at `ba13200a9`:
- `make -C apps/cli lint`: ascii PASS, flags PASS, golangci 0 issues.
- `go test` on autoupdate, cmdtree, secretscmd, runtime/secrets, testhelp, skill-ref-gen, effectiveness-catalog-gen and effectiveness: all `ok`, except the pre-existing macOS `/var` failure `TestInspectAdapterBinaryHashesResolvedPath`. It fails on pristine origin/dev too. secretscmd with that test skipped is `ok` (32 s).
- The pre-push preflight passed all gates (`[OK] preflight: all gates passed`), and the push succeeded: `ddbe97b82..ba13200a9`.
- The PR body was updated (gate definition, coverage, keychain numbers, evidence).
- Follow-up commit `4e4cc771c` (test(testhelp): pin the localhost blind spot only where the hosts file answers). The CI run on `ba13200a9` passed every lane except `windows-shard-0`, where only the new `TestNetworkGuardDoesNotSeeDirectDials` failed. Windows ships `localhost` commented out in its hosts file, so the Go resolver queried DNS and the guard recorded the query. The fix makes the localhost half conditional on the hosts file answering, and the literal-IP half stays strict. The guard comment and the docs now say "localhost on most Unix hosts". At `4e4cc771c`: lint 0 issues, `go test ./internal/testhelp` ok, `GOOS=windows go vet ./internal/testhelp` ok, and the pre-push preflight passed all gates (push `ba13200a9..4e4cc771c`).

**New head:** `4e4cc771cf61a1d9e42c2b650ba7d1c2a21c6b9d`

**CI state:** CI could not run on `4e4cc771c`. GitHub refused the jobs ("The job was not started because an Actions budget is preventing further use"), and artifact uploads fail ("Artifact storage quota has been hit. Usage is recalculated every 6-12 hours"). This is an account billing and quota block, not a test result. On the previous head `ba13200a9`, every lane passed except the Windows guard-test failure that `4e4cc771c` fixes. Re-run CI once the budget clears. PR #2318 is open and not merged.

### Unresolved questions (review fixes)
- The Actions budget and artifact storage quota on bestagentkits/agentkit need an owner to raise them or clear old artifacts before CI can confirm `4e4cc771c`.
- The localhost behaviour on Windows is inferred from the failure: the CI summary listed only the failing test name, and the detailed log was in an artifact. The literal-IP assertion stays strict, so a re-run will show if the inference is wrong.
