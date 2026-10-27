# ak-web vault PRs #587 and #586: review, merge, staging, production

Date: 2026-10-16 (Asia/Saigon), around 19:30 to 21:50. Repo: bestagentkits/ak-web.

## Status

Done. Both PRs were reviewed in isolated contexts, fixed, merged into `dev`, verified on staging, promoted to `main` and verified in production. #578 and #584 are closed and labelled `shipped`.

## Merged SHAs

| Change | `dev` (squash) | `main` |
|---|---|---|
| #587 fix(vault): sign first, bind under account and session locks (closes #584) | `b603f505f9265e4b5895d6830b4531215d6044ff` | via #598 merge `ade8658c5dc09ecda899c481a31a587c6449f5c2` |
| #586 feat(vault): `session_kind` claim (closes #578) | `de450c732c4fb7328a04403ec88639e2ae618c1c` | via #598 merge `ade8658c5dc09ecda899c481a31a587c6449f5c2` |
| Branch parity (main merged back into dev) | `af6ed3ea` | n/a |

## Pre-checks

- No agent was active on either PR. The last commits were at 10:36Z (#586) and 10:39Z (#587); work started around 12:26Z.
- Neither PR touches `db/`. No migrations were included in the promotion, so no backup was needed.

## Review findings and fixes

### #587

The first isolated review raised a blocker:
- **Sign-out race.** The PR committed the binding only after the session re-check. A sign-out that ran entirely in that gap found no committed device, so `insertRevocation` queued no `revoke_sids` for the user's first vault device, and the token stayed valid for up to 5 minutes.
- **Fix.** The mint now locks the session row `FOR SHARE` before binding, and every refusal throws so the transaction rolls back.

The second review raised two more:
- **GDPR self-delete** could miss a just-bound device in the same way.
- **Lock order.** The mint locked session then user, while merge and deletion lock user then session, so the two could deadlock.
- **Fix.** `lockLiveCliDeviceSession` locks `users` `FOR KEY SHARE` and then the session `FOR SHARE`, and GDPR delete locks `users FOR UPDATE` before reading devices.

The fixes were checked on a scratch PostgreSQL with two sessions at READ COMMITTED. All four scenarios behaved correctly: mint then sign-out, mint then delete, delete then mint, and a merge-style writer, with no deadlock.

The third review approved the merge. Its comment and type nits were fixed: the helper now requires a transaction type, and the lock-order invariant is documented.

### #586

The isolated review raised a blocker:
- **Wrong claim.** The PR emitted `sk: 'human'`. The ak-vault Worker (#87, spec §9.1, `worker/src/auth/jwt-verify.ts`) reads only `session_kind`, with values `email_otp | api_key_device | machine`. A future machine token minted that way would have been read as `email_otp`.
- **Fix.** The claim is now `session_kind`, and the route sends `email_otp`. `VAULT_SESSION_KINDS` is pinned to the Worker set, the signer throws on an unknown kind, and the docs and comments are corrected.

The second review traced an email-OTP token through the Worker verifier and approved the merge; its nits were fixed.

AI attribution: the squash subjects and bodies were written by hand with no `Co-Authored-By` or session links (checked by grep on both squash commits). The PR bodies were rewritten without attribution.

## Local evidence (each final head)

- `pnpm run type-check`, `pnpm run lint` and `pnpm run build` were clean on both heads.
- `pnpm exec jest` on the token route, CLI device sessions, GDPR delete, registry auth dispatch and `__tests__/lib/vault` suites passed: 135 of 135 on the rebased heads.
- PR CI was green on the merged heads: #587 at `9088df3a` and #586 at `0d2a6907`.

## Staging

- The `dev` runs for `b603f505` and `de450c73` stopped at "Verify exact branch tip". That is the designed guard: `dev` had advanced, partly through another session's #597.
- Staging converged on `bb45a5dc` (run 38911190979), which contains both commits. "Deploy with DXUP" and "Verify staging readiness" passed.
- **Cluster.** `claudekit-dev/claudekit-web` reached image `dx-deploy-dev-bb45a5dc…-651` with 1/1 ready and 0 restarts. It was later redeployed as `af6ed3ea` (the parity merge, identical tree), also 1/1.
- **Smoke test.** `POST /api/agentkit/vault/token` returned 401 `not_authenticated` with no auth, with a non-JSON body, with a forged `ak_cli_` bearer and with a non-CLI bearer. GET returned 405. 10 repeat requests gave 0 5xx responses, and `/api/readiness` returned 200 ready.
- **Logs.** No `[vault-token]`, fatal or migration errors.

## Production

- **Route.** Promoted with PR #598, whose head branch was pinned at `de450c73`, merged with a merge commit as for earlier releases (#576). A pinned `dev`→`main` merge was used rather than a cherry-pick. The four other commits that rode along were small, reviewed log-redaction, CI-test and operator-script changes from other sessions (#591, #590, #594, #596), with no migration, schema or env change. A cherry-pick would have forked `main` from `dev`. #597, merged later, was left on `dev`.
- **Deploy.** The CI run 38914886771 deploy job succeeded.
- **Cluster.** `claudekit-prod/claudekit-web` reached image `dx-deploy-prod-ade8658c…-652` with 2/2 ready and updated, 0 restarts, and the rollout status reported successful.
- **Smoke test.** The same cases as staging returned 401 `not_authenticated`, with 0 5xx across 10 repeats, and `/api/readiness` returned 200 ready.
- **Logs.** No `[vault-token]` or migration errors.
- No repair or revert was needed.

## Issues

- #584 and #578 were closed by the merge to `main`. Evidence comments are posted, and the labels are now `ai-handle, shipped` (`in review` and `done` were removed).
- Opened #588 (GDPR delete logged the deleted user's email) and #589 (real-PostgreSQL lock-ordering test). Another session has already resolved both through #591 and #590.

## Cleanup

- Removed worktrees `claudekit-web.worktrees/vault-pr-merge` and `vault-pr-586`, including their `.next` and `node_modules`.
- Deleted local branches, and the remote branches `claude/gracious-hamilton-zfpfbh`, `claude/gracious-hamilton-8kg7vu` and `fix/promote-vault-mint-to-main`.
- Removed the scratch Postgres clusters and temp files.
- No dev servers were started. The main checkout was never edited or switched.

## Concerns

- `dev` is ahead of `main` by #597 (log and return-value redaction in `lib/email.ts` and `lib/api-auth.ts`) and by whatever lands after it. That is for the owning session or the next release to promote.
- No API-key or machine vault mint path exists yet. When one is added, it must set its own `session_kind`; the comments in `lib/oauth/keys.ts` and `refreshCliDeviceSession` and the feature doc say so.
- `/api/agentkit/vault/token` was only smoke-tested without a valid session. A full mint with a real CLI session was not exercised in staging or production, because that needs a real account and session token.
