# Red-team scenarios 1-15: execution report

PR [#46](https://github.com/bestagentkits/ak-vault/pull/46) merged by squash auto-merge as `ee1d11c` after CI passed at head `2d4bcd5` (rebased on main `3dcec74`). Summary comment posted on [#8](https://github.com/bestagentkits/ak-vault/issues/8).

## Results

| Result | Scenarios |
|---|---|
| Pass | 1, 3, 4, 5, 7, 8, 9, 10, 12 |
| Pass with finding | 2 (#41), 11 (#42), 14 (#43, #44, #45, all hardening) |
| Limitation, reported as such and not claimed as detected | 6 |
| N/A: client policy and discovery not built (#7, agentkit#2299) | 13 |
| Pass locally; staging log scan left for the soak | 15 |

## Findings (all labelled ai-handle, no duplicates found)

- #41: refused proofs from a stolen token still spend the device's rate budget, so the real device gets 429. Availability only.
- #42: a machine device on the owner account can take the recovery-identity path into other vaults of that account and fetch their encrypted bundle and membership log. Open; fixing or accepting it is the owner's call. Cross-referenced on #6 and #24.
- #43: an org secret (an npm token) is visible to ak-vault workflows that never use it.
- #44: the main ruleset has no pull-request rule, although AGENTS.md says changes land through a PR. Follow-up comment there about the setting that lets workflows approve PRs.
- #45: SHA pinning of actions is a convention, not an enforced setting.

## Files (ak-vault, merged)

- `worker/test/red-team-token-and-proof.test.ts`
- `worker/test/red-team-tenant-and-role-isolation.test.ts`
- `worker/test/red-team-concurrency-and-retry.test.ts`
- `worker/test/red-team-removed-member.test.ts`
- `worker/test/red-team-disclosure-scan.test.ts`
- `worker/test/helpers/red-team-routes.ts`
- `packages/protocol/test/red-team-withheld-updates.test.ts`
- `docs/security/red-team-evidence.md` (new; scenario-to-evidence table)
- `docs/README.md`, `docs/security/release-gates.md` (links only; checkbox left unchecked)
- `docs/security/threat-model.md` (#42 stated as an open finding; C2 row linked)

No `src/` or removal-fence test was touched. agentkit was not edited.

## Evidence

- `pnpm typecheck`: pass. `pnpm test`: protocol 349/349, Worker 146/146. `go vet`, gofmt and `go test ./...`: pass. Vectors unchanged.
- CI at `2d4bcd5`: TypeScript, Go and Secret scan all passed (run 38750894155).
- Red-team Worker files were stable over 8 repeated runs in total.
- agentkit `dev` at `5a9a55a` was exported to a scratch directory:
  - The secretsync and secretscmd suites pass.
  - `make vault-e2e` against the branch's `wrangler dev` passed 9/9, and its log-redaction check passed.
  - A manual grep of that log found no names, values, JWTs, bearer or proof headers, idempotency keys, bundles or ciphertext.
- A fresh isolated reviewer checked the PR against REVIEW.md and raised 2 blockers and 8 non-blocking items. All were fixed in the second commit, as the coordinator asked.

## Cleanup

The worktree and local branch are removed. No `.wrangler/` directory remains, and no wrangler or workerd process is running. Port 8797 is free. The agentkit export and the e2e log in the scratchpad are deleted.

## Unresolved questions

- #42: whether to fix the machine recovery-path exposure (with a token claim, or by putting machine identities on a separate account) or to accept it is the owner's call.
- #44: whether to add a pull-request rule to the ruleset or correct AGENTS.md is the owner's call.
- Production deploy approval for `ee1d11c` is left to the coordinator.
