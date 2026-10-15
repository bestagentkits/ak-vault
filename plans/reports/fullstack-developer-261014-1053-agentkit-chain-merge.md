# agentkit chain merge into dev (2026-10-14, Asia/Saigon)

Repo bestagentkits/agentkit. Merge method: squash (repo norm). Halfway through, the coordinator changed the plan: fold #2323, #2329 and #2330 into #2322 and land all of them with one CI run.

## #2318 fix(cli): keep ak secrets off the network with sync off…
- Merged: `fe6179d2964c88b0aa352c3beac32d48d9a34c7a`.
- Push problems:
  - The original SSH push exited 141 (SIGPIPE) after preflight passed. The SSH connection went idle during the ~25 min pre-push preflight.
  - Retried over HTTPS (`git push https://github.com/...`), which has no long-lived connection. The hook still ran and passed.
- dev moved twice while this happened:
  - #2344 touched secrets. Merged it locally and re-ran the local checks, then pushed `de7a6e81e`.
  - #2345 was test-only. Picked it up with `gh pr update-branch`, which gave head `944c811d7`.
- CI runs:
  - pr-gates 38512049483 (b9fa70a37): cancelled, stale.
  - pr-gates 38514201559 (de7a6e81e): cancelled, stale.
  - test-os-specific: passed on b9fa70a37, de7a6e81e and 944c811d7. Native lanes were skipped (paused repo-wide).
  - pr-gates 38514854833 (944c811d7): success. This is the merge evidence.
- Fixes: none to code. Merge-only.
- Local checks:
  - vet, `go test -race` and golangci-lint on secrets, testhelp, autoupdate, cmdtree and secretscmd.
  - One failure, `TestInspectAdapterBinaryHashesResolvedPath` (/var vs /private/var). It was pre-existing and dev fixed it in #2345.

## #2322 (now folds #2323, #2329, #2330)
- Merged: `b537ffbae656c48fffd88399374152a1c8d1905e`. Title: "feat(secrets): add the sync keystore, store groundwork, HTTP transport and state store".
- Branch `feat/secrets-sync-module-keystore` deleted after the merge. GitHub did not delete it on merge.
- #2329 and #2330 were merged into the #2322 branch with `gh pr merge --merge`:
  - #2329: `394b1e051`
  - #2330: `80ca1f80c`
  - Both show MERGED, both have a "landed via #2322" comment, and neither ran CI.
- #2323 was merged into the branch locally, then closed with a "Landed via #2322" comment.
- #2323 conflicts with dev, all resolved:
  - `Store.Delete` text conflict with #2344's name-free errors: kept the branch's sequence and journal logic and dev's error text.
  - Semantic break: dev #2332 removed `hasControlRune`. The synced creator check now uses `HasUnsafeTextRune`.
  - A fresh isolated code-reviewer found a should-fix: synced value writes still used `validateRef`. They now use `validateNewRef`, same as a local Set. Synced deletes keep `validateRef`, so legacy unsafe refs stay removable.
  - Tests added: creator with a bidi or line separator, ref with a bidi or control character, and a legacy unsafe ref (synced write refused, synced delete OK). Stale comments fixed too.
- `go-test-shards.json` auto-merged with all entries kept; JSON is valid. `go mod tidy` and catalog regeneration produced no diff.
- Local checks at the final head `a39568299`:
  - `go build ./...` passed.
  - vet, `go test -race -count=1` and golangci-lint all passed on secrets, secretsync (all subpackages), secretscmd and cmdtree.
  - The preflight hook passed.
- CI runs:
  - pr-gates 38518674401 (81bf1a0fe): cancelled when the plan changed.
  - pr-gates 38520057197 and test-os-specific 38520057163 (a39568299): success. This was the single CI run.
- The PR body now opens with a "Folded PRs" section. It lists the folded PRs, the fixes above and the local evidence. "Part of #2298" is kept.

## dev full-suite
- Cancelled as instructed: 38518405873 (fe6179d29) and 38522040348 (b537ffbae). merge-train and auto-semver-release on b537ffbae were still running when I finished.

## Issue #2298
- One comment per merge: #2318 → fe6179d29…, #2322 → b537ffbae… (folds #2323, #2329, #2330).

## Cleanup
- Removed the five worktrees (agentkit-wt-vault-gates, -sync-p1 through -p4) and their local branches.
- No preflight temp dirs left. No watcher or push processes left running. The main checkout was not touched.

## Unresolved / concerns
- Remote branches still exist: `feat/vault-sync-off-gates`, `feat/secrets-sync-akvhttp`, `feat/secrets-sync-state-store` and `feat/secrets-sync-store-groundwork`. Their content is all on dev. They were left alone because only the #2322 branch was in scope for deletion.
- The #2323 fix commit (`6bed5ca75`, validateNewRef for synced writes) was never pushed to #2323's own branch. It reached dev only through #2322.
- Native OS lanes were paused (`CI_NATIVE_TESTS_PAUSED`). For these os_risk PRs, a paused os-required pass is not native evidence. The owner decides on that pause.
- SSH pushes with the long pre-push preflight can die with SIGPIPE. HTTPS pushes avoid it.
