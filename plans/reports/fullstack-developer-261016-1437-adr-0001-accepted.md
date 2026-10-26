# ADR 0001 accepted and DXUP provenance recorded

## Outcome
PR #72 (https://github.com/bestagentkits/ak-vault/pull/72) was squash-merged as `b49865c`. The Deploy run https://github.com/bestagentkits/ak-vault/actions/runs/38869160099 finished its gate and staging jobs successfully. Its production job is waiting for the owner's approval, which was not given by an agent.

## Owner decisions recorded (2026-10-16, 14:37)
- Comment on #8: https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210567772. It records the ADR approval, the DXUP provenance, and that #50 and #51 are not waived.

## Changes (docs-only)
- `docs/adr/0001-opt-in-zero-knowledge-sync.md`:
  - Status is now Accepted, dated 2026-10-16 and linked to the owner record.
  - The ADR states that acceptance is not the external review, which still blocks GA.
  - The kill-switch item no longer says sync "defaults to off in production". It now says production sync is live under the owner waiver and that each user still opts in.
  - "Open items before approval" is renamed "Open items", and restore reconciliation stays open.
- `docs/security/release-gates.md`:
  - The ADR P0 gate is ticked, with the owner record as evidence.
  - A new owner-waivers row covers accepting the ADR with restore reconciliation still open.
  - The production deploy control section records that the owner personally set ak-web production's `VAULT_*` values in DXUP. No values are written.
  - The staging restore (#51) and staging cost (#50) gates stay open.
- `docs/operations/runbooks.md`: the link now uses the renamed ADR anchor, and the JWKS row points to the provenance in release gates.
- `README.md` and `docs/protocol/v1/spec.md`: the status lines say the design is accepted by the owner and the external review is pending. The protocol status stays Proposed.

## Evidence
- Link and anchor check on the changed docs found 0 broken links. No references to the old anchor remain in the repo.
- `pnpm typecheck` passed for both protocol and worker.
- CI on the PR and on main passed: TypeScript, Go cross-verification and Secret scan.
- An isolated reviewer checked the change against REVIEW.md. The first pass found no blockers and 2 should-fixes, which were fixed. The re-review came back DONE.

## Follow-up
- #71 (labels `ai-handle` and `documentation`): `worker/public/security/index.{md,html}` still lists "ADR 0001 approved... open items resolved" as an open gate. That path was outside the files this task could modify.

## Cleanup
The worktree and the local and remote branch were removed. No servers were started.

## Unresolved questions
- The owner decided the ADR gate no longer requires restore reconciliation to be resolved. This is recorded as a waiver row. The owner may prefer to see it as part of the acceptance rather than as a waiver.
