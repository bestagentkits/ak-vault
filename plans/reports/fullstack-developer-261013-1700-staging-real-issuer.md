# Staging trusts ak-web's real issuer (#27)

PR: https://github.com/bestagentkits/ak-vault/pull/28 (branch `fix/staging-real-issuer`, worktree `/Volumes/GOON/claude/ak-vault/staging-real-issuer-27`). Not merged.

## Changes
- `worker/wrangler.jsonc`, staging only:
  - `VAULT_ISSUER` is now `https://staging.agentkit.best` and `VAULT_JWKS_URL` is its JWKS URL.
  - The inline test JWKS is removed. Production is unchanged.
- `worker/scripts/staging-smoke.ts` mints device tokens through ak-web staging using an ak CLI session token (`AK_STAGING_SESSION_TOKEN_PATH`).
  - The vault account is the token `sub`.
  - The smoke checks that the Worker's `/v1/meta` issuer equals the token's `iss`.
  - On an ak-web failure it prints only the HTTP status and a snake_case error code.
- New `staging-smoke-ak-web-token.ts`: reads the session token, builds the request (`signDetached`, context `akv1/vault-token-request`), mints tokens and caches them.
- New `staging-smoke-device-state.ts`: two device seeds kept in a 0600 state file, reused across runs and bound to one account.
  - Default path is `~/.ak-vault/staging-smoke-devices.json`; `AK_STAGING_SMOKE_STATE_PATH` overrides it.
  - Writes are atomic and fsynced. Symlinks, special files, paths inside the repo and directories others can write are refused.
- Each run uses a fresh vault. The Worker has no per-account vault limit.
- `generate-staging-issuer-key.ts` is removed. Nothing referenced it and it had no npm script.
- New test in `auth-token.test.ts` pins each environment's issuer and JWKS URL and checks that no inline keys are configured. The `vitest.config.ts` change exposes those values to the test.
- Docs updated:
  - `runbooks.md`: staging smoke section.
  - `release-gates.md`: staging soak wording; key separation is now stated as ak-web's duty, with a pre-soak comparison of key material.
  - `threat-model.md`: S4 row.
- Small comment fixes in `env.ts`, `jwks.ts` and `protocol/device-keys.ts`.

## Evidence (head 49b064d)
- `pnpm typecheck` and `pnpm build` pass.
- `pnpm test`: protocol 347/347, worker 129/129.
  - One run under machine load had the vector-generator tests time out at 60 s. Four reruns passed.
- Go not run: no wire or vector change.
- Interop: ak-web's own `verifyVaultTokenRequest` (origin/dev) accepts the smoke's request and derives the same `did`. A wrong `sid` or `aud` gives `invalid_signature`.
- Smoke failure paths were exercised locally, including a forged session token against live ak-web staging, which returned `ak-web 401 not_authenticated`. Nothing sensitive was printed.
- Not run: the live smoke with a real session, and `/v1/meta` after deploy. There is no session token, and the change is not deployed yet.

## Review
Two rounds of isolated review against REVIEW.md found no blockers. All should-fixes and the second round's optional nits are addressed.

## Follow-ups
- #29 (`ai-handle`): the Worker's JWKS fetch should refuse redirects.
- A comment on #27 lists the post-deploy evidence still needed.

## Unresolved questions
- Who runs the live smoke and the revoked-session check after deploy? A staging CLI session is needed.
- `PR Closes #27` will close the issue on merge, before the post-deploy evidence exists. The user asked for it this way.
- Smoke vaults pile up on staging, which may skew the soak cost measurement.
