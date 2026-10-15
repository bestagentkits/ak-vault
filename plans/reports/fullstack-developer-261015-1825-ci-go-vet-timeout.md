# CI go vet timeout fix (bestagentkits/agentkit#2436)

**Status:** DONE_WITH_CONCERNS. PR https://github.com/bestagentkits/agentkit/pull/2440 is open and ready at head `6e81a0753`, with no auto-merge. It waits for the owner's `train:owner-ok` label and the hourly batch train.

## Change
- In `.github/workflows/pr-gates.yml`, `go_vet` is now a matrix with `fail-fast: false`: `linux/amd64` (which also runs `go test -run '^$' ./...`), `windows/amd64` and `darwin/arm64`. Compile and vet coverage is unchanged, and the vets now run in parallel.
- Bounds: the compile step is 12m (measured max 7.4m), the vet step 10m (one pass is about 1–3m, about 5m under contention), and the job 25m (12 + 10 + setup).
- `required` still gates on `needs.go_vet.result`, which fails closed if any leg fails. The rulesets and branch protection require only `required` and `os-required` (now `train-verified` on `dev`), so the per-leg check names are safe.
- `tools/redteam/tests/push_contract_gates_test.sh` pins the bounds, the three platforms, the single native compile leg, the include-only matrix, `fail-fast: false`, and the absence of `continue-on-error` and job env. Two negative mutations fail it as expected.
- `tools/ci/lane-metrics.sh` tracks the new lane names and keeps the pre-split name; the bench header width is fixed.
- `docs/system-architecture.md` gets one sentence.
- An external session pushed `fetch-depth: 1` for the vet legs plus a `dev` merge. I kept it.

## Evidence
- Before the change: across 80 pr-gates runs, the serial vet step had p50 6.7m, p95 11.2m and max 11.6m, with 5 kills at 12.2m. In 32 log splits, the test-binary compile took 0.5–7.4m and the three vet passes together took up to 8.9m.
- Probe run 38729051770, with the Go lane selected by a temporary probe commit that was later reverted: all three legs green.
  - linux/amd64: compile 39s, vet 9s.
  - windows/amd64: vet 73s.
  - darwin/arm64: vet 39s.
- At the final head: the contract test and actionlint pass, and the preflight receipt (fast, scoped) passed and is in the PR body.
- Review: an isolated reviewer subagent found no blockers. Both SHOULD-FIX items and the hardening nits are fixed.

## Concerns
- #2373 merged mid-task. It moved `dev` to a batch train: no per-PR CI, no auto-merge or update-branch, and `.github/workflows/` changes need the owner's `train:owner-ok` label. So the steps "squash-merge when green" and "cancel full-suite" no longer apply. pr-gates, and with it this job, now runs only on PRs into `main` and on dispatch.
- I ran `gh pr update-branch` (coordinator step 2) before I found the new rule.
- Push transport: the first push went over the configured SSH remote, not HTTPS. The later push used HTTPS, and the external commit made it non-fast-forward, so it was not applied.
- One vet job now takes three runner slots on a small self-hosted Linux pool (one slot was offline). Queue time, not leg time, dominated the probe run.

## Cleanup
The worktree and local branch are removed. The remote branch stays for the open PR. No preflight temp dirs remain. #2436 has the labels `done` and `ai-handle` and is assigned to @me.

## Unresolved questions
- The owner needs to add `train:owner-ok` to #2440.
