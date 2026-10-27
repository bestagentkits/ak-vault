# Staging API-key vault sync test: BLOCKED at step 1

Date: 2026-10-17, about 01:30 Asia/Saigon
Scope: staging only (https://staging.agentkit.best). No production request was made.

## Status

BLOCKED. The owner's staging API key is rejected by the staging device-session challenge endpoint with `401 invalid_api_key`. Per the test plan, the run stopped at step 1. The client build, sign-in, sync, recovery check and cleanup were not performed.

## Summary

The pre-check showed that the key the owner authorized (`AGENTKIT_API_KEY` in the ak-vault `.env`) is not accepted on staging. The server response does not distinguish an unknown key from a revoked, rotated or expired one. Either way, the owner must confirm the key exists on staging, or supply a valid staging key, before this test can run.

No temp directories, binaries, worktrees or recovery kits were created, so no cleanup was needed.

## Step results

| Step | Result | Evidence (status and codes only) |
|---|---|---|
| 1. Pre-check that the key works on staging | FAIL (blocked) | `POST /api/agentkit/auth/api-key-device-session/challenge` returned 401, `errorCode: invalid_api_key`. |
| 1a. Vault scope check or enablement | Not reached | The scope could not be read or changed without a valid key. The staging PATCH route needs a browser session (see Concerns). |
| 2. Build `ak` from PR #2499 head, fresh home, `login --api-key`, sync enable, sync now, status, recover | Not run | Skipped because step 1 stopped the run. |
| 3. Device list shows the api-key device | Not run | Skipped. |
| 4. Cleanup and post-revoke refusal | Not run | No session was created, so there is nothing to revoke. |
| 5. Evidence comments on agentkit#2475 and PR #2499 | Not posted | The test plan says to stop and report an unknown key. I held the comments so that nothing is posted to GitHub without your go-ahead. |

## Cleanup confirmation

Nothing to clean up. No temp home, binary, worktree or recovery kit was created. Two read-only `gh` calls and one challenge POST were made against staging.

## What the owner must do

1. Confirm that the account owning `AGENTKIT_API_KEY` exists on staging and that the key is still active. Staging and production use separate databases, so a key that works in production will not work here.
2. If the key was rotated or revoked, supply a current staging key, or reissue one on the staging API keys page.
3. Turn on the key's "Vault sync" switch on the staging API keys page. This is the prerequisite in the contract. A browser session is required, and the PATCH route described below is cookie-only.

Once a valid staging key is available, the run can resume at step 1.

## Concerns

- **The PATCH route could not be verified from source.** The test plan points to `app/api/keys`. In `/Volumes/GOON/www/claudekit/claudekit-web`, the local `dev` checkout (HEAD `ac0605d3`, 2026-10-05) has no `vaultScope` or device-session code. Its `app/api/keys/[id]/route.ts` defines only GET and DELETE, with no PATCH. The `origin/dev` ref there is at an older commit (2026-08-20), and the `ak-web-vault-tokens-568` worktree also has no `vaultScope` code. The shipped ak-web#601 code was therefore not available locally. The authentication claim rests on the contract comment and on `getCurrentUser()` in `lib/auth.ts`, which reads only the `session` cookie.
- **The 401 cannot be narrowed further.** The server returns the same `invalid_api_key` for missing, unknown, revoked, rotated-out and expired keys. The owner has to check the key on the staging side.
- **The contract comment says the device-session routes and the vault-scope PATCH shipped to staging.** This pre-check contradicts the assumption that the key is valid on staging. The owner should confirm which staging database the key was created in.

## Unresolved questions

1. Is `AGENTKIT_API_KEY` meant to be a staging key? Its prefix is `ck_live_`, and the test plan assumes it is valid on staging.
2. Should the blocked result be posted as comments on agentkit#2475 and PR #2499? I can post them once you confirm.
3. Is there a staging-side browser session that can turn on vault scope, so the run can resume without a new key?
