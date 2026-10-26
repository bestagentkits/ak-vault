# JWKS separation confirmed (staging vs production)

Date: 2026-10-16 (Asia/Saigon). Refs #8.

## Outcome
The release-gates open item "staging and production JWKS share no key material" is recorded as confirmed. PR #85 squash-merged as `7cd04e0`. Staging deployed; production is waiting for owner approval (not approved by the agent).

## Check (counts only)
- Fetched both `/.well-known/jwks.json` endpoints (agentkit.best and staging.agentkit.best) with a browser User-Agent.
- Production 1 key, staging 1 key, both EC P-256. Shared `(crv, x, y)` 0, shared `x` 0, shared `kid` 0. No key was missing x/y.
- The isolated reviewer reproduced the same counts independently.

## Changes
- `docs/security/release-gates.md`: the intro and the Staging soak section now say the item was confirmed on 2026-10-16 by comparing `(crv, x, y)`, with a link to the evidence. The wording says it is a point-in-time check and that keeping keys separate across rotations stays ak-web's responsibility. No other doc listed the item as open; the wording of threat-model S4 already matches.
- #8 evidence comment: https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6213027838 (I edited it once to fix confusing timestamp wording).

## Evidence
- Link and anchor check over docs/, AGENTS.md, README.md and REVIEW.md: 209 relative links, 0 broken.
- Isolated code-reviewer against REVIEW.md: APPROVE, no blockers. I applied its line-wrap nit.
- CI on PR #85: TypeScript, Go cross-verification and secret scan all passed.
- Deploy run https://github.com/bestagentkits/ak-vault/actions/runs/38884949557: gate success, staging success, production waiting.

## Cleanup
Removed the worktree, the local branch and the remote branch, plus the scratch files.

## Unresolved questions
- Production deploy of `7cd04e0` needs owner approval (docs-only change).
- #8 labels were left unchanged (`blocked`). It is the umbrella issue with other gates still open.
