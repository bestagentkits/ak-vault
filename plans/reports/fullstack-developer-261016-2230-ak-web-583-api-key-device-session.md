# ak-web#583: API-key vault device sessions (shipped)

The work started on 2026-10-16 at about 22:30 Asia/Saigon. Production was verified on 2026-10-17 at about 00:45 Asia/Saigon.

## Outcome

ak-web#583 is on production. A personal API key can now enrol headless ak-vault devices. To do so, the owner must first turn on the key's vault scope; it is off by default, including for existing keys.

The device signs a server-issued nonce, the API key id and its own public key. That proof is exchanged for a revocable `api_key_device` CLI session, which can mint vault tokens only for that device key, with `session_kind=api_key_device`.

The issue is closed and carries only the `shipped` label.

## Delivered against the issue checkboxes

**Opt-in vault scope per key.**
- The scope is stored in `api_keys.vault_scope_granted_at`; null means off.
- Owners set it with a switch on each key card on the API keys page, or with `PATCH /api/keys/{id}` and `{"vaultScope": boolean}`. That route accepts browser session auth only.
- The scope can only be turned on for a key that is active and unexpired.

**Exchange endpoint.**
- `POST …/api-key-device-session/challenge` returns a nonce. The nonce is an HMAC under a key derived from the CLI session secret, is bound to the key id, lasts 120 s, and is compared in constant time.
- `POST …/api-key-device-session` takes an Ed25519 proof over `{api_key_id, nonce, sign_pub}`.
- The request body is limited to 2 KB.
- Each endpoint is rate limited per client address and per key, using the existing `checkAgentKitRateLimit` because #585 was not merged.
- The nonce is single use: its hash is recorded under the key's row lock.
- Every failure is refused (fail closed).

**Vault token route.**
- It accepts `email_otp` and `api_key_device` sessions.
- An `api_key_device` session mints only for its own device; any other device gets 403 `device_mismatch`.
- The email-OTP lock now checks the session kind stored in the database, not only the claim.
- Registry and feedback APIs refuse `api_key_device` sessions.

**Cascade revocation.**
- These key changes revoke every device session derived from the key and queue `revoke_sids` in the same transaction through the existing outbox: revoke, rotate, soft delete, hard delete, and scope removal.
- Key expiry and device revocation are enforced when the session refreshes or mints.

**Caps.**
- Each key holds at most 5 live devices. A device revoked in the account frees its slot.
- The cap of 50 devices per account still applies.

**Email notice.** The owner gets an email for each new API-key device. It contains only the key label and the time.

**Device listing.**
- `GET /api/account/vault/devices` returns `sessionKind` and `apiKeyLabel`.
- The device-list UI is left to #569, as noted in a comment on that issue.

**Tests.**
- New jest suites cover every refusal path. They also assert that no log line carries the API key, a token, a proof or an email.
- A new real-PostgreSQL proof, `verify:api-key-device-sessions`, runs in CI and makes 10 checks.

## Migration and backups

**Migration 0072 (`0072_demonic_raider`).**
- It adds three nullable, unconstrained columns: `api_keys.vault_scope_granted_at`, `agentkit_cli_sessions.api_key_id` and `agentkit_cli_sessions.api_key_nonce_hash`.
- It was authored with `pnpm db:generate`. The online-schema allowlist was extended for exactly these three statements.
- `db:verify-migrations` and `db:test-migration-contract` pass.

**Rollback safety.** The previous image can run against the migrated database:
- It ignores the new columns.
- It rejects `api_key_device` claims.
- It cannot look up `ak_kdrefresh_` refresh tokens, which use a separate hash domain.

**Backups.** Both were taken before the deploy that applied 0072, using a custom-format `pg_dump`. Each was streamed from a short-lived `postgres:16-alpine` client pod in the environment's namespace, which was deleted afterwards. Both files are in the operator's `claudekit-web/backups/` directory (gitignored).

| Environment | File | Size | SHA-256 | TOC entries | Server |
|---|---|---|---|---|---|
| Staging | `staging-claudekit-pre-0072-20261016T161913Z.dump` | 15,932,439 B | `1fd8744d8e9367930b547e1fd0b0fdc4e05c8e84e6a75092470eacf11fd20855` | 744 | PG 15.15 |
| Production | `production-claudekit-pre-0072-20261016T165700Z.dump` | 30,381,452 B | `c40957a3463aea6822d8d09de2665f2f796b970b0c28c8eeff0f691d1d27d0e4` | 734 | PG 15.15 |

## Evidence

Local checks at the PR head, `1059a96f`:
- `pnpm run type-check`: clean.
- `pnpm run lint`: no warnings or errors.
- `pnpm exec jest`: 509 suites and 4506 tests pass on a full run. The touched and related suites (107 suites, 883 tests) were re-run after the final fixes.
- `pnpm run build`: succeeds, and both new routes are listed.

The real-PostgreSQL proof ran on disposable PostgreSQL 16 and in CI:
- `verify:api-key-device-sessions` passes all 10 checks.
- As a control, removing the account-row lock from key retirement makes it fail with `deadlock detected`, which shows the race test detects the deadlock.
- `verify:vault-mint-lock-ordering` and `verify:vault-revocation-outbox` still pass.

Review:
- The first isolated review found one blocker. Key revoke, rotate, delete and scope-off locked `api_keys` before `agentkit_cli_sessions`, while an account merge locks users, then sessions, then `api_keys`, so the two could deadlock. The fix locks the account row first, retries if a merge moved the key, and adds the race to the PostgreSQL proof.
- The re-review in a fresh context found no blockers.
- These NITs were applied:
  - the key cache is invalidated before the Worker delivery;
  - the refresh end reason now distinguishes expired keys from keys that are no longer live;
  - the scope cannot be turned on for an expired key;
  - the rollback wording in the docs was corrected;
  - the nonce key is a derived sub-key;
  - a misleading comment was fixed.

CI and release:
- PR #601 CI was green, including the new proof.
- On the release, both the dev push run and the main run were green.

## Staging and production verification

**Staging, at `c18d135d` and again at `eb93d48a`:**
- The rollout completed. The ledger holds 73 migrations ending at 0072, and the three columns exist and are nullable. 0 of 1922 keys are scoped.
- Smoke tests:
  - 401 `invalid_api_key` with no bearer, a CLI-style bearer, an oversized key, or an unknown key, on both endpoints;
  - 405 for GET;
  - the vault token route returns 401 `not_authenticated` for a bogus session;
  - responses carry `no-store`;
  - the 11th call with one key returns 429;
  - readiness returns 200.

**Production, at `9dacc7d6`:**
- Both pods are on the new image with 0 restarts.
- The entrypoint logged "Database migrations applied; full ledger matches the committed migration chain".
- The ledger holds 73 migrations ending at 0072, and the columns are nullable. 0 of 3409 keys are scoped.
- The same refusal smoke tests pass (without the rate-limit probe).
- `/api/readiness`, `/api/health` and `/` return 200.
- There were no error logs in the 20 minutes after the rollout.

No rollback or forward repair was needed.

## PRs, SHAs and issues

- PR #601 (feature to `dev`): https://github.com/bestagentkits/ak-web/pull/601. Branch head `1059a96f`, squash-merged as `c18d135d0b27620b33f91ad05b3c26ed62028dd5`.
- PR #604 (release from `dev` to `main`): https://github.com/bestagentkits/ak-web/pull/604. Merge commit `9dacc7d6d76c1cf1d01b706033bcf5e4276d3497`.
  - It also shipped #597 (email log redaction) and #603 (API-key error logging). Both were already on `dev` and were verified on staging.
- Branch parity: `dev` was fast-forwarded to `9dacc7d6`.
- Comment on #569 leaving the device UI to it: https://github.com/bestagentkits/ak-web/issues/569#issuecomment-6219328833
- Contract posted on agentkit#2475: https://github.com/bestagentkits/agentkit/issues/2475#issuecomment-6221129767
- `ai-handle` issues opened from the review:
  - #599: the refund flows ignore a `false` from `revokeApiKey`.
  - #600: API-key handlers log raw database errors. #603, from another contributor, appears to resolve it; this is noted on #600.

## Docs impact

- `docs/features/build-with-ak-mcp-oauth.md` now covers:
  - API-key device sessions;
  - the revocation cascade;
  - support for both session kinds in the vault mint.
- `docs/deployment-guide.md` has a new "API-Key Vault Device Session Rollout (`0072`)" section covering backup, verification and rollback behaviour.

## Cleanup

All of the following were removed or stopped:
- the worktree;
- the local and remote feature branches;
- the disposable PostgreSQL container;
- the backup and ledger client pods.

No background processes are left running. The backup dumps are kept on purpose.

## Endpoint contract for the agentkit client

**Prerequisite.** The owner turns on vault sync for the key, either on the API keys page or with `PATCH /api/keys/{id}` and `{"vaultScope": true}` (browser session only). Otherwise the endpoints return 403 `vault_scope_missing`.

**1. Challenge**

`POST /api/agentkit/auth/api-key-device-session/challenge` with `Authorization: Bearer ck_live_…` and no body.

200 response:

```json
{ "apiKeyId": "<uuid>", "nonce": "<b64url, 75 chars>", "expiresAt": "<ISO-8601>", "expiresIn": 120 }
```

The nonce is single use and bound to the key. Fetch a new one for every attempt.

**2. Exchange**

`POST /api/agentkit/auth/api-key-device-session` with the same bearer and this body:

```json
{ "nonce": "…", "sign_pub": "<b64url 32B Ed25519>", "sig": "<b64url 64B>" }
```

- The body must have exactly these fields and be at most 2 KB.
- `sig = Ed25519(utf8("akv1/api-key-device-session") || 0x0A || cjson({api_key_id, nonce, sign_pub}))`, with the same canonical JSON as `akv1/vault-token-request`.

200 response (`no-store`):

```json
{
  "schemaVersion": 1,
  "token": "ak_cli_…",
  "accessToken": "ak_cli_…",
  "refreshToken": "ak_kdrefresh_…",
  "accessTokenExpiresAt": "…",
  "refreshTokenExpiresAt": "…",
  "sessionId": "<uuid>",
  "deviceId": "<did = kid(sign_pub)>",
  "authMethod": "api_key_device",
  "apiKeyId": "<uuid>",
  "user": { "id": "<uuid>" }
}
```

**Using the session**
- Refresh with the existing `POST /api/agentkit/auth/refresh` and `{refreshToken}`. Tokens rotate.
- Mint vault tokens with `POST /api/agentkit/vault/token`.
  - Only the session's own device key may be used; any other gets 403 `device_mismatch`.
  - The token carries `session_kind: api_key_device`, so the device stays off the recovery path. It can create a new vault, but joins an existing one only through a `device_add` signed by an owner device.
- The session cannot be used with the registry or feedback APIs.
- Enrolling the same device again replaces its session without using a new slot.

**Errors**

Error bodies are `{error, errorCode, message?}`. The 429 keeps the shared limiter's shape: `{status: "inactive", errorCode: "rate_limited"}`.

| Status | Codes |
|---|---|
| 404 | `not_found` (feature off) |
| 503 | `vault_unavailable` |
| 401 | `invalid_api_key` |
| 429 | `rate_limited` (10 per minute per address and per key, on each endpoint) |
| 403 | `vault_scope_missing`, `no_kit_entitlement` |
| 400 | `invalid_request` |
| 401 | `invalid_nonce`, `stale_request`, `invalid_signature`, `nonce_reused` |
| 409 | `api_key_device_limit` (5 per key), `device_limit` (50 per account) |
| 403 | `device_revoked` |
| 409 | `device_conflict` |
| 500 | `internal_error` |

Status: DONE
Summary: The API-key device-session exchange and the cascade-revoked, capped `api_key_device` sessions are shipped through #601 and release #604. Both databases were backed up before migration 0072, and staging and production were verified and smoke-tested.
Concerns:
- #599 is open: the refund flows can report success when the key revocation failed.
- The device-list UI (badge and key label) is left to #569.
- The distinct error for other logins on the vault token route is left to #582, and the mint rate limit to #585.
- Release #604 also shipped #597 and #603 from other contributors. Both were green on CI and verified on staging.
- A happy-path exchange was not run on staging or production because it needs a real customer key. The success path is covered by the jest suites and the PostgreSQL proof.
PR URLs: https://github.com/bestagentkits/ak-web/pull/601 and https://github.com/bestagentkits/ak-web/pull/604
Merged SHAs: `c18d135d0b27620b33f91ad05b3c26ed62028dd5` (dev) and `9dacc7d6d76c1cf1d01b706033bcf5e4276d3497` (main)
