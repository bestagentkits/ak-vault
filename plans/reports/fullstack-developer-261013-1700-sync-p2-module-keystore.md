# Sync client: akv1 module pin and device keystore (agentkit#2298)

**Status:** done. PR https://github.com/bestagentkits/agentkit/pull/2322 is open against `dev` and not merged. Branch `feat/secrets-sync-module-keystore`, head ff9314adc. Labels `os-specific` and `done`.

## Delivered

- **Module pin:** `apps/cli/go.mod` and `go.sum` require `github.com/bestagentkits/ak-vault/go` v0.2.0 directly (tag go/v0.2.0, commit 1137bfd).
- **Vendored vectors:** the 18 akv1 vector files are byte-exact from 1137bfd. `SOURCE.json` records the tag, commit and per-file sha256. `doc.go` records the pin and the re-vendor steps.
- **Conformance test:**
  - It replays 354 vector cases and fails on an unknown file or an unconsumed key.
  - The pin check uses `modfile.Parse` on go.mod and on the go.work that `go env GOWORK` reports. It refuses a replace, or a workspace `use` of the module.
- **Keystore** (`secretsync/keystore`) with a pinned backend:
  - **keychain:** the index is written before the entry, with heal on save and settle-under-lock on load.
  - **file:** age scrypt `keys.age`, 0600 in a 0700 directory, atomic, with symlinks and swapped files refused and mismatch on a wrong passphrase.
  - **memory:** tests only.
  - All refusals fail closed.
- **Approved ownership deviations:** `apps/cli/go-test-shards.json` and `tools/ci/classify-pr-paths.sh` (os_risk). Both are recorded in the PR.

## Evidence

At ff9314adc, in apps/cli:
- `go vet` is clean.
- `go test -race` passes for both packages (keystore with `-count=5`).
- `GOWORK=off` conformance passes.
- `go build ./...` succeeds.
- golangci-lint reports 0 issues.

At the repo root:
- shard `--verify` passes.
- `pr_path_classifier_test.sh` passes.
- `preflight` passes all gates; the pre-push hook ran it on every push.

Mutation checks confirm the two lock tests fail when their fix is reverted. The full command list is in the PR body.

## Reviews

- **Review 1:** one blocker (ParseLax drops replace directives) and several should-fix items. All were fixed in 2db3593a7.
- **Review 2:** no blockers. Its should-fix items (a load reporting false corruption during an in-flight save; the passphrase contract) and its nits are fixed in 96be7e156 and ff9314adc.

## Follow-ups

- agentkit#2321 (`ai-handle`): re-seal `keys.age` on recovery unlock.
- There is no classifier test case for the secretsync path, because that test file is outside this change's ownership.

## Incident

The session scratchpad is shared with the parallel agent working on P1. The generic `pr-body.md` was overwritten by P1's body, and one `gh pr edit` briefly put that body on #2322. I restored the correct body within minutes. P1's file and P1's PR were not modified. Parallel agents should use uniquely named scratch files.

## Unresolved questions

- The file keystore runs a scrypt decrypt on every load. Will later phases need an in-process cache?
- A purge needs vault IDs from the sync state; keys for unknown vaults are orphaned. Does the sync-state phase need an orphan sweep?
