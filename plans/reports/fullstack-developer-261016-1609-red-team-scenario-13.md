# Red-team scenario 13: hostile shared profile or policy text

Date: 2026-10-16 (Asia/Saigon). Owner approved the run in chat at 16:09.

## Outcome
Pass against what exists. No defect found. The attacked features are still not built
(#7 portable policy, agentkit#2299 discovery/profiles), so the scenario stays open in the
release gates and must run again when they land.

## What ran
- Protocol policy evaluator, TS `effectiveGrant` and Go `EffectiveGrant`. New tests
  `packages/protocol/test/red-team-hostile-policy.test.ts` and
  `go/akv1/red_team_hostile_policy_test.go`, same cases in both. 26 hostile policy texts
  parsed from raw JSON (duplicate keys, `__proto__`/`constructor`, lookalike fields,
  grant/exec/nested fields, bad numbers and types, lone surrogate, BOM, trailing data,
  text instead of an object) are refused with `bad_request`. Wildcards and shell text in
  the lists are treated as literals. Approval cannot be lifted, and an unknown sensitivity
  is refused. Instruction text comes back verbatim and leaves the grant unchanged. A
  randomized check (2,000 pairs per language, seed 13) found no widening.
- Sync client at agentkit `dev` `4aff1984b`, using an uncommitted engine-level probe in a
  scratch worktree. An enrolled member pushed `policy`, `profile`, `Policy` and `grant`
  items and a secret `SYNTH_SHELL_$(id)` carrying shell and instruction text. On the
  victim, the policy item was cached as ciphertext only. The other three kinds were
  reported `unapplied: unsupported_kind` and kept out of the Store. The secret was stored
  as inert data. No command ran and no grant, pending or trust file was written. The full
  `secretsync/...` and `secretscmd/...` suites were green.
- No lab Worker, no staging, no production. No ak-web sign-in needed.

## Evidence (PR head)
`pnpm typecheck` clean; `pnpm test` protocol 421 / worker 178 passed; `pnpm test:go` ok;
`pnpm build` ok; `pnpm vectors` no diff. PR CI green (TypeScript, Go cross-verification,
secret scan). An isolated reviewer checked it against REVIEW.md and found no blockers. Its
suggestions are applied.

## GitHub
- Issue: https://github.com/bestagentkits/ak-vault/issues/80 (assigned, closed, `shipped`)
- PR: https://github.com/bestagentkits/ak-vault/pull/83 (squash-merged `0eff6a8`)
- CI on main: https://github.com/bestagentkits/ak-vault/actions/runs/38880689526 (success)
- Deploy: https://github.com/bestagentkits/ak-vault/actions/runs/38880836635. It is
  pending in the `deploy` concurrency group behind run 38880189455 (`84f58f0`), which is
  waiting for production approval. Not approved by me.
- Evidence comment on #8: https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212644401
- Hardening: https://github.com/bestagentkits/agentkit/issues/2478 (`ai-handle`; commit the
  engine-level regression test, probe source attached, plus a design note). Cross-referenced
  on #7 and agentkit#2299.

## Docs
`docs/security/red-team-evidence.md`: row 13, a new section "Scenario 13: hostile policy and
profile text", and the "does not cover" bullet. `docs/security/release-gates.md`: only the
scenario-13 sentence of the red-team checklist item. The checkbox stays unchecked.

## Design note (recorded on agentkit#2478)
The client carries unknown meta keys forward on its next push under its own signature. Text a
hostile member put in meta is then re-signed by the next honest editor, so record authorship
cannot attribute profile text once profiles read from meta.

## Cleanup
Worktrees removed (ak-vault branch deleted locally, agentkit scratch worktree removed). No
`.wrangler/` was created and no processes were started.

## Unresolved questions
- Should the owner tick the "every scenario executed" gate now, or wait for the re-run after
  #7 / agentkit#2299? I left it unchecked.
- Deploy for `0eff6a8` waits behind the `84f58f0` run, which is waiting for owner production
  approval.
