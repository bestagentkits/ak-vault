# Worker: device-sealed input requests (ADR 0004)

Status: DONE_WITH_CONCERNS. Typecheck clean; worker suite 46 files / 516 tests green
(29 new in `worker/test/input-request.test.ts`). Not committed.

## Evidence (current working tree)

- `pnpm -C worker typecheck` : pass.
- `pnpm -C worker exec vitest run test/input-request.test.ts` : 29/29 pass.
- `pnpm -C worker test` : 516/516 pass. The `Error: Network connection lost` uncaught
  line also appears with the new file excluded (487/487), so it predates this change.

## Files

Modified: `worker/src/{env.ts, http/errors.ts, auth/jwt-verify.ts, vault/vault-schema.ts,
vault/write-request-store.ts, vault/vault-request.ts, vault/vault-durable-object.ts,
relay/relay-rpc.ts, relay/account-relay-durable-object.ts, relay/relay-session.ts,
mcp/tools.ts, mcp/tool-dispatch.ts, mcp/mcp-entry.ts, mcp/write-request-tools.ts,
routes/api-handler.ts}`, `worker/test/mcp-transport-conformance.test.ts` (tool count 9 -> 10).
New: `worker/src/routes/input-request-routes.ts`, `worker/test/input-request.test.ts`.

## Contract

- Env: `VAULT_INPUT_REQUESTS_ENABLED`; `inputRequestsEnabled(env)` is true only for the
  exact string `"true"` with remote access on. Off: input routes 404, `?input_request=`
  400, `secrets_request_input` uses the dashboard flow only.
- Routes: `GET|POST /v1/vaults/:vid/input-requests/:rid` (no query; POST body exactly
  `{"sealed": <input seal>}`); item PUT `/v1/vaults/:vid/items/:id?input_request=:rid`
  answers `{..., input_request: {state: "completed", receipt}}`.
- Input token: ES256; `typ` required, `JWT` or `at+jwt`; `iss` = `VAULT_ISSUER`;
  `aud` = `<VAULT_AUDIENCE>/input` (single); claims exactly
  `iss aud sub sid session_kind jti iat nbf exp`; `session_kind` = `input`;
  `0 < exp - iat <= 600`; no `did`/`scope`; `sid` checked live for revocation.

## Error codes per outcome

| Outcome | HTTP | code | `error.state` |
|---|---|---|---|
| bad/missing token, revoked input sid | 401 | unauthorized | - |
| revocation lookup error | 503 | (existing) | - |
| unknown id, other account, dashboard row | 404 | not_found | - |
| malformed body / seal for another request | 400 | bad_request | - |
| unknown seal v/alg | 400 | unsupported_version | - |
| POST after expiry | 410 | expired | expired |
| POST on non-open row (second POST, cancelled) | 409 | conflict | current state |
| issuing device offline | 503 + Retry-After 5 | device_offline | pending_user |
| device busy | 429 + Retry-After 1 | rate_limited | pending_user |
| relay refused frame | 400 | bad_request | pending_user |
| device timeout | 504 | device_timeout | failed (timeout) |
| device not_found | 410 | expired | failed (device_lost) |
| device expired | 410 | expired | expired |
| device decrypt_failed | 400 | bad_request | failed (decrypt_failed) |
| device conflict | 409 | conflict | conflict (revision_conflict) |
| device invalid_args | 400 | bad_request | failed (bad_request) |
| device denied | 403 | forbidden | failed (denied) |
| device other / stored without matching PUT receipt | 500 | internal | failed (internal) |
| success | 200 | `{status:"stored", receipt}` | completed |

MCP `secrets_request_input` errors: `device_offline` (no online device and no dashboard
fallback: no seal key, or non-owner), `device_timeout`, `rate_limited`,
`too_many_requests` (cap checked before asking the device), `conflict`, `denied`,
`invalid_args` (incl. reader role), `internal` (device error or mismatched request_id).

## Concerns

- PUT response key `input_request` and the HTTP codes above (410 `expired`, 503
  `device_offline`, 504 `device_timeout`) are Worker choices; the spec/device authors
  should align `docs/protocol/v1/spec.md` with them.
- `docs/` (env var, routes, REVIEW.md route list) not touched per ownership; docs owner
  must record the new route and flag.
