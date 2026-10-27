# Owner decisions 2026-10-16: deploy freeze, kill switch, gates

PR #60 merged at `d097c41`; #53 closed via PR. #42 and #8 still open (Refs only).

## Changes
- `.github/workflows/deploy.yml`: gate step reads `vars.DEPLOY_FREEZE`; unset/`false` pass, `true` fails with `::error::`, any other value refuses (fail closed). Production job re-checks after approval. Structure/permissions unchanged.
- `docs/operations/runbooks.md`: new "Emergency kill switch" (sync-off only, never enable, incident issue, freeze first, cancel in-flight/waiting Deploy runs, match live version to commit, `pnpm exec wrangler deploy --env="" --var VAULT_SYNC_ENABLED:false --message ...` from `worker/`, same-day wrangler.jsonc PR, unfreeze after merge then `gh workflow run deploy.yml`) and "Deploy freeze" (`gh variable set/delete/list`). Ground rules, kill switch and rollback sections link to them.
- `docs/security/threat-model.md`: Recovery bundle limitation names machine identities on owner account; #42 decision, ak-web#578 planned fix, prerequisite for #6. C2 row updated.
- `docs/security/red-team-evidence.md`: #11 note (owner decided fix), #15 note and platform-logs paragraph (no staging soak).
- `docs/security/release-gates.md`: soak section rewritten (Docker e2e replaces staging round trip + soak, decision comment linked, residual risk for external reviewer); disclosure gate notes platform logs need seeded deployed run or waiver; deploy control lists two emergency paths. Ticked: two-device/soak item (e2e at `a4f5656`, worker/packages/go/protocol/lockfile unchanged since) and removal fence (#48). External review not ticked.
- `AGENTS.md`: deploy rule names emergency exceptions. Ruleset wording already matched (PR rule, 0 approvals).

## Evidence
- actionlint exit 0; freeze `case` tested for "", false, true, TRUE, yes.
- Wrangler 4.149.0 source: `--var` splits on first `:`.
- `pnpm typecheck` green; doc links/anchors script: 0 broken.
- PR CI run 38846380052: TypeScript, Go, Secret scan pass. Main CI 38846517630 success.
- Isolated reviewer (REVIEW.md): 0 blockers, 4 should-fix fixed, re-review clean.

## Deploy
- Deploy run for `d097c41`: **38846591758**, `pending`. It is queued behind run 38842265403 (`9797a81`, PR #57), which is `waiting` for production approval and holds the `deploy` concurrency group. Coordinator decides: approve or reject 38842265403, then approve production on 38846591758.

## Follow-ups filed (ai-handle)
- #58 landing page + cost model still describe staging soak.
- #59 tag CI deploys with commit SHA (`--message`).

## Cleanup
Worktree removed, local branch deleted, watcher stopped. #53 labelled done/shipped.

## Unresolved questions
- Is there a copy of production Cloudflare credentials outside GitHub for the emergency path, and may an agent run it?
- Platform Workers Logs/traces disclosure scan: seeded deployed run or owner waiver on #8?
