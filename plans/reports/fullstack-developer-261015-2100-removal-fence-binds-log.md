# Removal fence binds the change log (#21) and recovery epochs (#36)

## Outcome

- **PR [#48](https://github.com/bestagentkits/ak-vault/pull/48)** merged on main as 7dde6d2 and closes #21 and #36. It was squash auto-merged after CI went green.
- **Follow-up PR [#49](https://github.com/bestagentkits/ak-vault/pull/49)** merged; CI was green.
  - **Why it was needed:** #46 (red-team tests) merged while #48's auto-merge was pending. Two of its tests built removal bodies without the now-required `log_head`, so CI failed on main at 7dde6d2.
  - **What it changed:**
    - The two red-team tests now sign `log_head`.
    - A `fence()` fixture helper was added.
    - Row 10 of `docs/security/red-team-evidence.md` was updated.
- **Labels:** #21 and #36 are closed and labelled `done`, with `in progress` and `in review` removed. I did not set `shipped`; the coordinator decides that after deploy.

## What changed

**Head chain:**
- `log_head[n] = b64 sha256("akv1/log-head\n" || cjson({conflict_id, log_seq, prev, record}))`, with `log_head[0] = ""`.
- `device_remove` and `member_remove` sign `{log_fence, log_head}`, using the head the remover computed itself.

**`verifyChangeLog` / `VerifyChangeLog` (TS and Go):** replays the log against the signed fences.
- A removal fence below `from` needs the client's kept head (`keptHeads`).
- The client takes kind, revision and resolution from its own replay, never from feed fields.

**Worker:**
- A `log_heads` table, written in the same transaction as the record.
- `/changes` serves heads.
- A removal whose head does not match is refused (`bad_request`).
- The Durable Object constructor backfills missing heads, and a missing head fails closed (`internal`).

**#36:** every `device_add`, recovery included, must wrap at `event.key_epoch`. A stale recovery bundle is refused. The stranded-bundle limitation is recorded in the threat model.

**Docs:**
- spec §3.5, §4, §5, §7, §11 and the revision entry;
- threat model;
- data classification;
- key lifecycle;
- the public security page;
- red-team evidence.

`release-gates.md` is unchanged: its box is assessed on #8.

## Evidence

On the #48 head ef9c663 (local, then CI):
- `pnpm vectors -- --check`: 0 stale files.
- `pnpm typecheck`: clean.
- `pnpm test`: protocol 383/383, worker 137/137.
- `pnpm build`: done.
- `go test -count=1 ./...`: ok.
- CI: TypeScript, Go and the secret scan all passed.

On origin/main plus #49:
- `pnpm test`: protocol 385/385, worker 154/154.
- CI passed.

An isolated reviewer checked against REVIEW.md and found four issues, all fixed. Its re-review reported no blockers.

## Coordination

- **agentkit [#2450](https://github.com/bestagentkits/agentkit/issues/2450)** (`ai-handle`) lists the exact client changes:
  - sign `log_head`;
  - replay with `VerifyChangeLog` and `KeptHeads`;
  - store `LogHead`;
  - recovery at the current epoch;
  - bump the go module.
- I opened ak-vault [#47](https://github.com/bestagentkits/ak-vault/issues/47) (`ai-handle`) for the "Network connection lost" uncaught exception, which already happens on main.
- No go tag was cut.

## Cleanup

- Worktree `ak-vault-wt-fence` and its local branches are removed.
- No `.wrangler/` or coverage directories were present.
- No dev servers were started.

Status: DONE_WITH_CONCERNS
Summary: The fence now binds the change-log contents and recovery epochs are reconciled, merged via #48. #49 repaired the red-team tests that raced the merge.
Concerns/Blockers:
- main CI failed at 7dde6d2; after #49, CI on main 3f77991 passed.
- The Deploy run for 7dde6d2 was superseded (cancelled); the Deploy run for 3f77991 is pending, and production approval is left to the coordinator.
- The agentkit client cannot remove devices against the new Worker until #2450 lands, so do not deploy to staging environments used by the current client without resetting vaults that have removals.

Unresolved questions:
- Who cuts go/v0.3.0, and on which commit? I recommend the #49 merge commit.
- Should `shipped` be set on #21 and #36 at merge or at production deploy?
