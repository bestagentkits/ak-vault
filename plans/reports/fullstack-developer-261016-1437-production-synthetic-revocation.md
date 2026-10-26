# Production synthetic revocation test

**Status: DONE_WITH_CONCERNS.** On production, a CLI session sign-out in ak-web reached the ak-vault Worker by webhook, and the Worker refused the revoked vault token on the first poll. That poll came 260 ms after the sign-out response and 1075 ms after sign-out started. Evidence is posted at https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210676621, labelled as a synthetic test and not a review sign-off.

## Method

- **Session.** The owner signed in by email OTP (option 2 below) under a throwaway HOME, `/tmp/akv-synthetic-home`. I inspected only field names and types: `authMethod: email_otp`, a `sessionId` is present, and the CLI access token TTL is 900 s. The owner's real `~/.agentkit` was not touched.
- **Script.** A scratch script reused the repo's smoke helpers at `f356495`: `worker/scripts/staging-smoke-ak-web-token.ts` (mint) and `buildProof` from `@ak-vault/protocol`.
  - The Ed25519 device seed was random and held in memory only.
  - The vault ID was random and does not exist.
  - The script printed only steps, statuses, stable error codes and timings.
- **Revocation path.** `POST https://agentkit.best/api/agentkit/auth/sessions/current/revoke` with the synthetic session's own bearer token. ak-web enqueues `revoke_sids` in the sign-out transaction and delivers it before responding.

## Results (2026-10-16, 07:45 UTC / 14:45 Asia/Saigon)

| Step | Result |
|---|---|
| ak-web `POST /api/agentkit/vault/token` | 200, TTL 300 s |
| Worker `GET /v1/vaults/<synthetic>/changes`, token and proof | 404 `not_found`: token, proof and revocation checks passed |
| ak-web session sign-out | 200 in 814 ms |
| Worker, same token (297 s of life left) | 401 `unauthorized` on poll 1: 260 ms after the sign-out response, 1075 ms after sign-out start |
| Worker, three repeat reads | 401, 401, 401 |
| ak-web re-mint with the signed-out session | 401 `not_authenticated` |

The 401 is from revocation, not expiry: the same token was accepted just before and still had 297 s of life left.

## Preflight (unauthenticated)

- Worker `/healthz`: 200 with `sync_enabled: true`.
- Worker `/v1/meta`: 200.
- Worker read with no token: 401.
- Unsigned webhook: 401, not 503, so the secret is configured.
- ak-web mint with no bearer: 401 `not_authenticated`, so tokens are enabled and configured.

## Cleanup

- The scratch script and log were deleted. No token, key or proof was written to disk or printed.
- The synthetic CLI session is revoked.
- `/tmp/akv-synthetic-home` was left in place for the coordinator to remove, as instructed.
- **Left for the owner:** the throwaway device key bound in ak-web's vault devices list.
  - ak-web never received a label for it, so it shows up only by its created time: 2026-10-16 07:45:39 UTC (14:45:39 Asia/Saigon).
  - It is the most recent entry on the owner's account.
  - Its private key is gone, so it can never mint again, but it counts toward the 50-device cap until it is revoked in the ak-web dashboard.
  - No timing is needed for that step.

## Concerns

- Device revocation (`revoke_dids`) was not timed on production. Timing it would need a second live session and token, because the synthetic session is already revoked.
- The latency figure is an upper bound set by the first poll. The Worker may have applied the revocation before the sign-out response returned.

## Unresolved questions

- Does the owner want a `revoke_dids` timing run too? It needs another OTP sign-in.
