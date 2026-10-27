# agentkit#2075 secrets metadata: stopped at the coordination check

Date: 2026-10-16 18:50 Asia/Saigon (11:43Z)

## Outcome

I did not implement anything. Another live Claude session started work on #2075 within the last 10 minutes. Following the coordination rule, I stopped instead of duplicating it. I made no worktree, branch, issue comment, commit or PR, and I left no processes or caches behind.

## Evidence of active work

- **Local worktree:** `/Volumes/GOON/www/claudekit/agentkit/.claude/worktrees/agent-a3fb4baa2d0c8ed7c` is on branch `feat/secrets-rich-metadata-search`.
  - It was created at 18:36 local (11:36Z), based on `dev` head `f2ee44601`.
  - It is locked with "claude agent agent-a3fb4baa2d0c8ed7c (pid 95197 start 11:21:57Z)".
  - It had no commits or file edits yet when I checked at 11:43Z, so the agent was most likely still reading.
- **Owning process:** pid 95197 is a live Claude Code session (`--model=claude-opus-5-5`, started 18:21:57 local). It is not my parent session (pid 92844).
- **Issue timeline:** #2075 was labelled `in progress` and assigned to `mrgoonie` at 11:40:43Z. That is 4 minutes after the worktree was created, which fits that session claiming the issue (agents use the owner's gh account).
- **Remote:** I found no open PR for #2075. `gh pr list --search 2075 --state all` returned nothing. No remote branch has a commit since 08:00Z that mentions metadata, search, dotenv, inventory or profile. Branch `feat/secrets-rich-metadata-search` has not been pushed.

## Context gathered for whoever implements this

- **What #2075 requires:** metadata fields (description, project, environment, provider, account, tags, source type/path), project-directory dotenv discovery with a conflict preview, and `ak secrets search` (metadata-only, `--json`, structured filters). Its acceptance criteria also include Desktop DTO/search parity, export inventory round-trip, v1 index backward compatibility, and docs/help. That is broader than CLI only.
- **Security notes on #2075:** the 2026-10-12 cross-repo alignment comment on #2075 adds tests to write: prompt injection stored in an imported profile, a malicious URL, names not visible in a cloud dump, old index migration, and no value leaks.
- **Approved #2299 schema (owner decision recorded 11:35Z):**
  - `Metadata.profile` is an object.
  - Each field is `{value, origin: local|import|sync, by, at}`.
  - A field with `origin != local` is untrusted.
  - Policy, grants and `run` never read profile fields.
  - `PayloadFromLocal` (`apps/cli/internal/runtime/secretsync/item_payload_mapping.go`) stops carrying unknown profile keys forward.
- **#2478 (closed, landed as `f2ee446`):** the engine test `TestHostileMemberPolicyAndProfileItemsStayInert` is the baseline any meta change must keep green.
- **Current state of `dev`:** `secrets.Metadata` is in `apps/cli/internal/runtime/secrets/metadata.go`, per the #2299 triage at `4aff198`.

## Status

- **Status:** BLOCKED
- **Summary:** #2075 is already being worked on by a live session (pid 95197, worktree `agent-a3fb4baa2d0c8ed7c`, branch `feat/secrets-rich-metadata-search`, created 11:36Z). The issue was claimed at 11:40Z. I stopped so the work is not duplicated.
- **Concerns:**
  - The other session has no pushed commits yet, so I can't tell whether its scope includes the approved #2299 profile schema.
  - The orchestrator should confirm with that session, or the owner, that it will make `Metadata` compatible with `{value, origin, by, at}` profile fields and stop `PayloadFromLocal` carrying profile keys forward.
  - If that session is a stale or abandoned run, tell me and I will take the issue over.
- **PR URL and merge commit:** none.
- **What #2299 can build on:** nothing new from this run. The current anchors are `apps/cli/internal/runtime/secrets/metadata.go` and `apps/cli/internal/runtime/secretsync/item_payload_mapping.go` on `dev` `f2ee44601`.

## Unresolved questions

1. Who launched session pid 95197, and is it delivering the whole of #2075 including Desktop parity and the #2299-compatible profile model?
2. Should I wait and review that session's PR, or take over if it stalls? If I take over, what is the cutoff?
