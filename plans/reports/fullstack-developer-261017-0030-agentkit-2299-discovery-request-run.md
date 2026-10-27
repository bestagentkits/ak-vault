# agentkit#2299: discovery, request, constrained run, synced policy on release

Delivered as four stacked PRs into agentkit `dev`, all rebased onto `dev` `f8e2da556`. None has landed: agentkit lands only through the train, and nothing was merged or released by this work.

## PRs

| PR | Scope | State | Head |
|---|---|---|---|
| bestagentkits/agentkit#2500 | Discovery, metadata-only describe/search, profile fields `{value, origin, by, at}`, token-shaped fingerprint scope | ready, MERGEABLE | `0cd8a4438` (my rebase `4ad1fb1b2` plus two commits pushed by someone else on 2026-10-19, see Concerns) |
| bestagentkits/agentkit#2511 | `ak secrets request` reusing pending/approve and never inheriting a grant | draft, stacked on #2500 | `564714238` |
| bestagentkits/agentkit#2512 | Constrained `ak secrets run`: no shell, argv[0]'s path and sha256 pinned, allowlisted env plus granted vars, value redaction | draft, stacked on #2511 | `78c05da3a` |
| bestagentkits/agentkit#2615 | Synced vault policy as a maximum on every grant release (resolve, run, request, skills exec); high sensitivity needs a fresh allow once; `grant --once`; upstream `akv1.VerifyChangeLog` at pseudo-version `90d4e72` replaces the kept-head port, with a #2507 coverage mapping; read-only sync state | draft, stacked on #2512 | `2348b26a2` |

Each PR body carries a preflight receipt for its head against `origin/dev` `f8e2da556`.

## Evidence (PR4 head)

- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh` passed all gates. The receipt for `2348b26a2` is in the #2615 body.
- Full `go test ./... -timeout 30m` in `apps/cli` ran at `4d86d1b33`; the only later commit records `go.work.sum`. 235 packages passed. Two failed, and neither is touched by the stack:
  - `codexruntime`: a flake under load; it passes alone with `-count=3`.
  - `kitcmd`: three tests fail the same way on clean `dev` `f8e2da556` (macOS `TMPDIR` behind the `/var` symlink). Filed as bestagentkits/agentkit#2613 (`ai-handle`).
- `tools/ci/verify-ui-bundles.sh` is clean after regenerating the stale entrypoints.
- Memory latency rig on an idle machine: p95 off 10.6 ms; idle 30.8 ms (+20.2); busy 30.8 ms (+20.2). The gate passes.
- File arms (from the earlier run): +485.6 / +479.5 ms. This breaches the gate and is tracked in bestagentkits/agentkit#2513.
- Isolated fresh-context review against REVIEW.md, round 4 after the rebase: no blockers. Both should-fix items are fixed:
  - The read-only test was ineffective. Its replacement holds a sync write transaction and is proven to fail against the writer `Open`.
  - The UI bundle entrypoints were stale and have been regenerated.
- The nit "open state before loading keys" was applied.
- PR2 and PR3 preflights passed at their new heads; their receipts and a rebase note are in the bodies.

## Issue bookkeeping

- #2299 labels are now `done` (plus `ai-handle`), with a stack summary comment.
- #2516: commented. #2615 closes it.
- #2517 had already landed `OpenReadOnly`, so no new read-only follow-up issue was needed.
- #2513 body now references #2615 and the rerun memory number.
- The ak-vault#7 comment lists what the client enforces and how to rerun scenario 13.

## Left for ak-vault#7

- Items 1 and 5 are enforced on the client in #2615 but are not on `dev` until the stack lands.
- Items 2 to 4 of the gap analysis are unchanged by this work.
- File-backend latency breaches the 50 ms gate (bestagentkits/agentkit#2513). The owner decides whether the gate means "warm cache" (passes) or "no key cache" (breaches) and whether it blocks #2615.
- The external review is still pending; nothing here is a sign-off.

## Scenario 13

Scenario 13 can be run now against the #2615 branch `feat/secrets-synced-policy`. Seed hostile `policy` and profile items, then check three things:
- a policy item narrows or refuses and never grants;
- high sensitivity needs a fresh allow once;
- an undecryptable record refuses with exit 15.

It cannot be run against `dev` until the four PRs land.

## Cleanup

The four worktrees and their local branches are removed (every remote head was verified first). The preflight temp homes under `/private/tmp/ak-pf.*` are removed and the Go test cache is cleared. No preflight, test or build processes are still running. `lucid-sammet-b484b1` was not touched.

Status: DONE_WITH_CONCERNS
Summary: All four #2299 PRs are open and rebased on `dev` `f8e2da556`: #2500 (ready), and #2511, #2512 and #2615 as drafts. Each has a fresh preflight receipt, PR4 passed its isolated review and the full suites, and none has landed. ak-vault#7 has the client-enforcement comment; scenario 13 can be run against the #2615 branch, not yet against `dev`.
Concerns:
- Someone else pushed two commits to #2500 on 2026-10-19 (`2cbdefa87`, `0cd8a4438`: fingerprints keyed with the manifest key). #2511 is based on my earlier head `4ad1fb1b2`, an ancestor of the new one. It still merges, but the stack may need a restack before the train picks it up, and #2511's receipt predates those commits.
- File-backend release latency breaches the gate by about 480 ms (#2513); the owner decides whether this blocks.
- `kitcmd` fails on `dev` on macOS (#2613), and the package exceeds 30 minutes under full-suite load.
- `Closes #2516` on a stacked PR only takes effect once the change reaches the default branch.
- PR URLs:
  - https://github.com/bestagentkits/agentkit/pull/2500
  - https://github.com/bestagentkits/agentkit/pull/2511
  - https://github.com/bestagentkits/agentkit/pull/2512
  - https://github.com/bestagentkits/agentkit/pull/2615
- Landed SHAs: none.
