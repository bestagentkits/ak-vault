# Review: bestagentkits/agentkit#2318 (sync-off CLI gates for ak-vault#8)

Head `ddbe97b82` (3 commits on `feat/vault-sync-off-gates`, base `dev`). Fresh-context review, read-only.
Date 2026-10-13 (Asia/Saigon).

## Scope
- 12 files, +825/-5: trigger.go exclusion (+test), `testhelp.GuardNetwork` (+test), cmdtree and secretscmd no-network tests, resolve latency rig, docs (secrets guide, lifecycle spec, ak-ak SKILL.md), 2 regenerated contribution catalogs.
- Verified by: reading full files in worktree, tracing trigger wiring, secrets importers, inject hook, GUI APIs; running tests; a scratch probe of the guard's blind spots.

## Evidence (run at head, darwin/arm64, go1.25.0)
- `go test ./internal/testhelp ./internal/runtime/autoupdate`: ok.
- New tests `-v`: secretscmd matrix + offline resolve PASS (5.9 s), cmdtree test PASS (0.8 s).
- `-race` on the two secretscmd tests: PASS, 60.8 s (scrypt 2^18 under race). secretscmd is not in CI's declared race surfaces, so no current CI exposure.
- Full `secretscmd` package: only `TestInspectAdapterBinaryHashesResolvedPath` fails (`/private/var` vs `/var`); trust.go/trust_test.go untouched by this PR, fails alone, pre-existing.
- `go test ./cmd/effectiveness-catalog-gen` (`TestContributionCatalogFresh`): ok, so catalog bumps are required by the SKILL.md edit and in scope.
- Bench `-benchtime 20x`: memory/warm p95 6.4 ms, file/warm p95 636 ms, file/cold p95 806 ms. Reproduces the implementer's "no warm state on file backend" finding.
- Non-ASCII in added lines: none.
- PR CI: not green yet. `test-os-specific` run 38376695339 shows `cancelled` (superseded, not a code failure); the replacement lanes were still pending when checked.

## 1. Auto-update exclusion: correct and complete for the CLI
- Single call site: root `PersistentPreRunE` -> `runAutoUpdateTrigger` -> `ShouldTrigger` keyed on `CommandPath[1]` (cmdtree/auto_update_trigger.go:79, trigger.go:126-131). `secretscmd.NewCmd` has no aliases; Cobra `CommandPath()` uses canonical names anyway, so alias spellings would still map to `secrets`.
- `ak secrets resolve` requires `--json` (resolve.go:99-102), and `--json` already disables the trigger (trigger.go:123). The new exclusion is the effective fix for the non-JSON commands (set/get/list/rotate/grant/approve/...). Defense in depth for resolve is fine, but the comment at trigger.go:52-56 implies the exclusion is what protects resolve. That is inaccurate.
- Inject hook (kits/core/hooks/secrets-inject.cjs:477,493) execFileSyncs `ak secrets resolve ... --json` directly, with no intermediate `ak` command that could trigger.
- Other secret surfaces: GUI secrets/grants/approvals/audit APIs run in-process under `ak gui` / `ak-gui` (both already excluded) and contain no HTTP. Adapter `${secret:}` substitution (adapters/secretsubst.go) has no production substituter wired (no `secrets.NewSubstituter` caller outside tests), so `ak run`/adapters cannot resolve secrets today. Other importers of runtime/secrets (diagnostics, support report, update bundle, sessionredact, orchestrate, userenv) only use redactor/dotenv helpers. That matches the implementer's claim.
- Other startup network: `main()` -> registryurl.ConfigureForVersion (sets vars only), noderunner.HydrateProcessPath (fs), darwinhint (stderr). No telemetry or update check runs in the secrets path. Not network, but outside ak's control: `ak secrets trust` execs `<adapter> --version` (trust.go:246), a third-party binary.

## 2. Zero-network tests: do they bite?
- cmdtree test: the regression is real. With the exclusion reverted, `secrets set` (no `--json`) against an overdue home calls the recording spawner, so step 1 fails. The positive control (`projects list` must spawn once) blocks a vacuous pass. Good.
- Guard probe (scratch copy, not in repo):
  - hostname via a plain `net.Dialer` is caught at DNS (Go resolver honoured on darwin);
  - a pre-built `DefaultTransport.Clone()` is caught via the proxy listener;
  - **`net.Dial("tcp","localhost:PORT")` is NOT caught**: /etc/hosts resolves without DNS, so 0 attempts are recorded.

  So the stated limit "literal IP with a custom net.Dialer" is narrower than reality. Any dialer (including plain `net.Dial`) to a literal IP or a hosts-file name bypasses it. For current code (no network code in secrets) this does not matter. A future sync client would target a real DNS name through net/http, which is caught.
- The proxy-env caching limit is real but the dialer and resolver routes back it up. It matters only if a real proxy env was cached earlier in the test binary (unusual on CI).
- Async gap: `AssertNoAttempts` runs right after each step. Network started by a goroutine that outlives the command would be attributed to a later step or missed after the last step. Irrelevant today, relevant once sync adds background work.
- Coverage gap: the matrix omits `import-env`, `export`, `trust`, `recovery init/unlock/recipients`. On the file backend, `recovery init` runs in `newOfflineVault` **before** `GuardNetwork` is installed (no_network_test.go:99-100). The keychain backend (the production default) is not exercised either; that is understandable, since CI cannot use a real keychain.

## 3. Offline resolve test
- Valid as a sync-off regression lock: it seeds, installs the guard, resolves on memory and file, checks the value and 0 attempts.
- It does not model the realistic failure: the guard fails dials instantly. A blackholed network (SYN drop, DNS timeout) would make a future synchronous sync step hang, and this test would not see it. The comment "must never wait on or fail because of it" (no_network_test.go:158-161) claims more than the test checks. When sync lands, the "resolve never depends on network" gate needs a sync-enabled variant with a hanging dialer and a time bound. This PR cannot satisfy that half of the gate, and the comment acknowledges sync is absent.

## 4. Benchmark and docs
- Methodology is sound for what it measures: nearest-rank percentiles, setup untimed, per-case rig line, opt-in N, scrypt at the production factor, no CI cost (benchmarks are not run in CI; the report test is env-gated).
- Is "warm" honest? The docs (secrets.md:362-369) correctly say file/warm is about the same as cold. But:
  - **memory/warm is unreachable in production.** The env var and config cannot select memory (backend.go:25-31), and values are lost at process exit, so a per-process `ak secrets resolve` can never release from it. It is a synthetic floor.
  - **keychain, the default backend on every OS, is not measured.** The only sub-50 ms case is therefore non-production.
  - secrets.md:371-372 still asserts "sync may add less than 50 ms at p95 over the warm cases" as if the baseline were settled. The implementer's own unresolved question (which baseline) contradicts that.
- The rig also excludes `resolveProject`, `persistRedactionManifest` and JSON render (resolve.go:108,141). Only process start and the caller walk are disclosed (secrets.md:351). That is fine for a delta measurement, but the list should be complete.
- Catalog regeneration: legitimate. `TestContributionCatalogFresh` requires it after the SKILL.md edit.

## 5. Flakiness, cleanup, cross-platform
- No wall-clock budgets in the new tests. The guard self-test uses a 5 s WaitUntil on loopback. Low flake risk.
- Cleanup: t.TempDir / t.Setenv / t.Cleanup restore globals. `interactiveTTY` is restored. The memory-store ref is deleted at the end. Nothing leaks.
- macOS /private/var: the new tests pass. The existing failure is in trust_test (pre-existing).
- Windows: nothing path-specific in the new code; the result depends on the pending Windows lanes.
- File subtests cost ~4 s plain and ~60 s under -race. That is acceptable today but worth noting if secretscmd is ever added to the race surfaces.

## Findings

### Blocker
- None.

### Should-fix
1. docs/guides/secrets.md:328 and kits/core/skills/ak-ak/SKILL.md:265 claim "no `ak secrets` command uses the network". Two problems:
   - secrets.md:339 says the matrix runs "every operator and grant command", but `import-env`, `export`, `trust` and `recovery *` are not under the guard, and `recovery init` runs before the guard is installed (apps/cli/internal/commands/secretscmd/no_network_test.go:99-100).
   - `trust` execs a third-party adapter binary (trust.go:246).

   Fix: either add these commands to the matrix (stub adapter for trust) and install the guard before `newOfflineVault`, or narrow the claims to what the tests prove.
2. docs/guides/secrets.md:371-372 and resolve_latency_bench_test.go:9-10 present "<50 ms p95 over the warm cases" as the settled target. memory/warm cannot occur in production (backend.go:25-31, values die with the process), and keychain, the default backend, is unmeasured.

   Fix: state that the production baseline is undecided (pending the ak-vault#8 owner choice), label memory/warm as a synthetic floor, and/or add an opt-in keychain case.
3. apps/cli/internal/testhelp/network_guard.go:39-43: the limits comment understates the blind spots. A plain `net.Dial` to a literal IP or to any hosts-file name such as `localhost` bypasses the guard (verified). List it so a future sync test author does not over-trust the guard.

### Nit
- apps/cli/internal/runtime/autoupdate/trigger.go:52-56: resolve was already excluded by the `--json` rule (trigger.go:123; resolve.go:99). Say the exclusion covers the non-JSON commands and backs up resolve.
- apps/cli/internal/cmdtree/secrets_no_network_test.go:45,48: `wantCode: -1` on approve/resolve makes those steps outcome-agnostic. Resolve may stop at the caller walk without touching the vault. That is acceptable because set/get carry the regression, but the comment oversells it.
- apps/cli/internal/commands/secretscmd/no_network_test.go:158-161: "never wait on" is not tested (the guard fails fast, with no blackhole mode).
- resolve_latency_bench_test.go:14 says `-benchtime 200x` while secrets.md says `30x`. The rig string hard-codes `scrypt_work_factor=2^18` (line 223) for all cases, including memory, instead of reading the default. `b.Logf` prints a rig line with `iterations=1` on Go's calibration pass (line 245).
- docs/guides/secrets.md:332 says "Three tests" but lists two bullets. The offline resolve test sits inside the second file, so name it explicitly.
- docs/guides/secrets.md:351: also disclose that project resolution, the redaction-manifest write and render are excluded from the rig.

## Plan / gate status (ak-vault#8 "Offline and cold-start")
- "sync disabled 0 HTTP calls": met for `ak secrets` on memory/file backends via in-process tests, with the coverage gaps in should-fix 1.
- "resolve never depends on network": met only for sync-off. A sync-on, blackhole variant is needed when sync exists.
- "warm-cache p95 overhead < 50 ms on defined rig": the rig exists, but the production baseline is undefined (keychain unmeasured, no warm file cache). The gate needs an owner decision; it is not met.

## Unresolved questions
- Which backend and warm state is the #8 latency baseline: keychain, file plus a future identity cache, or something else? This needs an owner decision, not an agent one.
- Should `ak secrets trust`'s adapter `--version` exec count against the "no network" promise? It runs a third-party binary.
- Is a process-level black-box check (built binary, proxy env, unroutable DNS) wanted for the release gate, or is in-process coverage enough?

Status: DONE_WITH_CONCERNS
Summary: The auto-update exclusion is correct and complete for every current secrets path, and the cmdtree test genuinely fails on a regression. No blockers. The docs and test claims overstate coverage (several commands are unguarded; guard limits are understated), and the latency "baseline" omits the production-default keychain backend while its only fast case cannot occur in production.
