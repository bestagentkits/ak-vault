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
