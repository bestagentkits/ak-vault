# Code review: device-sealed input requests (ADR 0004)

Branch `feat/device-sealed-input-requests`, uncommitted worktree (`git diff HEAD` plus untracked
files). Reviewer had no implementation history. Checked against REVIEW.md hard rejection
criteria and the AGENTS.md security rules.

## Scope

- Protocol: `packages/protocol/src/input-seal.ts`, `relay-frames.ts`, `relay-tools.ts`, `index.ts`;
  `go/akv1/input_seal.go`, `relay_frames.go`, `relay_tools.go`, `vectors_input_seal_test.go`;
  vectors `input-seal.json`, `relay-frames.json`, plus their generators.
- Worker: `routes/input-request-routes.ts` (new), `routes/api-handler.ts`, `auth/jwt-verify.ts`, `env.ts`,
  `http/errors.ts`, `mcp/*`, `relay/*`, `vault/write-request-store.ts`, `vault-durable-object.ts`,
  `vault-schema.ts`, `vault-request.ts`; tests `input-request.test.ts`, `mcp-transport-conformance.test.ts`.
- Docs: spec §3.11 / §9 / §9.7 / §9.8 / changelog, REVIEW.md, AGENTS.md, threat model X15/X16, ADR 0004 notes.
- About 1.5k LOC changed plus about 1.4k LOC new.

## Evidence (run at the current worktree state)

| Check | Result |
|---|---|
| `pnpm typecheck` (all 4 projects) | pass |
| `pnpm --filter @ak-vault/protocol test` | 17 files, 969 tests pass |
| `cd go && go test ./...` | `ok akv1` |
| `worker: npx vitest run` | 46 files, 516 tests pass. The stderr shows `outputGateBroken` / point-in-time-restore exceptions; these look like what the restore tests are expected to print. |
| Vector freshness: ran `buildAllVectors()` in memory and compared with the committed files (nothing written) | 29 files, 0 stale |

## What holds up (where the risk is lowest)

- **Crypto.** TS and Go match each other and match the spec. HKDF uses `salt = epk || input_pub` and
  `info = "akv1/input-seal"`. The AAD `ctx` is distinct, and `purpose` is `null` when absent and the
  key is always present. The all-zero shared secret is refused inside the shared `x25519Shared`
  (TS and Go). Parse order is identical in both languages. The vectors cover each changed AAD field,
  write-intent `info`/`ctx` separation, a zero `epk`, every length check and `v`/`alg`.
- **Token isolation.** `verifyInputToken` takes an exact claim set, `aud = <origin>/input`, requires
  `typ` and allows a lifetime of at most 600 s. `verifyToken` and `verifyMcpToken` compare exact
  audiences, so the token cannot be used across routes. Tests cover the matrix in both directions.
- **Account binding and fail-closed behaviour.** Every store function filters on `flow = 'device'` and
  `account = sub`. Dashboard routes (`openRow`) now ignore device rows. A failed revocation lookup
  returns 503 (tested).
- **Single use.** The claim (`pending_user` -> `submitted`) is one `transactionSync`. Release and settle
  only move rows that are still `submitted`, so a completed or conflict row is never overwritten.
  Completion happens in the PUT transaction.
- **PUT binding.** It checks `flow`, `account = sub`, `device_id = did`, rejects `browser` and `machine`
  sessions, requires `submitted` and not expired, and checks the operation against the live item.
  Combining it with `?write_request` is refused.
- **Gate.** `inputRequestsEnabled` requires remote access as well. The routes, the PUT parameter and
  the MCP device flow all check it. `wrangler.jsonc` does not set the flag. MCP can never reach the
  `request_input` / `input_deliver` relay tools (`MCP_RELAY_TOOLS`).
- **Logging.** The only logger emits template, status, code, ms and a hashed vault. No path logs the
  name, the value or the ciphertext. The test captures `console.log` (the only sink) and dumps the
  `write_requests` table.

## Findings

### Blocker

None found.

### Major

**M1. Spec §3.10 still lists closed state and reason sets that the code now goes beyond.**
- Code: `worker/src/vault/write-request-store.ts:35` (new state `submitted`) and `:39-53` (new reasons
  `device_lost`, `decrypt_failed`, `bad_request`, `denied`, `internal`, `timeout`). `secrets_write_status`
  returns these to MCP clients.
- Spec: §3.10 "States" (`spec.md:659-670`) says the reason set is closed and lists six reasons.
  §3.11 says "states and receipts are those of §3.10". §9.8 describes `secrets_write_status` as "§3.10 states".
- Failure scenario: an MCP client or SDK written to the spec rejects or mishandles `submitted` or
  `reason: "timeout"`. The spec and the code disagree on a wire-visible closed set, which the
  AGENTS.md spec-change rule forbids.
- Fix: add `submitted` and each new reason, with its "when", to the §3.10 table (or a §3.11 table that
  §3.10 references). State that only device-flow rows use them.

**M2. Spec §10 error-code list and its "never an HTTP status of a /v1 route" sentence contradict the new routes.**
- Code: `worker/src/http/errors.ts:16`, `:34-36` (adds `expired` 410, `device_offline` 503 and
  `device_timeout` 504 as HTTP codes). They are returned by `routes/input-request-routes.ts:76-84,111,122`
  and by the PUT (`submittedInputRow` throws `expired`, `write-request-store.ts:316`).
- Spec: §10 (`spec.md:1749-1753`) lists the stable codes without these three. `spec.md:1777-1781` says
  `device_timeout` is "never the HTTP status of a `/v1` route".
- Failure scenario: a client that switches on the §10 set treats 410 `expired` and 503 `device_offline`
  as unknown errors. The spec contradicts itself.
- Fix: in §10, list `expired`, `device_offline` and `device_timeout` as `/v1` codes of the input routes
  and the `?input_request` PUT, and narrow the "never the HTTP status" sentence to the MCP-only codes.

**M3. The data classification and REVIEW.md's plaintext-transit list were not updated.**
- `docs/security/data-classification.md:43`: the write-request row does not list the new stored
  columns `flow`, `device_id` or `input_pub`. Nothing classifies the `input` session token, or the
  input-seal ciphertext passing through Worker memory and relay frames.
- `REVIEW.md:15-19` (product philosophy, D7 transit list) still names only the MCP `set` value, the D8
  name and purpose until sealed, and relayed metadata. It does not name the input-request name and
  purpose relayed to the device in `request_input` args and returned in `form_url`, or the sealed value
  relayed in `input_deliver`.
- The REVIEW checklist requires "New fields are classified in data classification".
- Fix: add these fields and the transit to both documents. Note that `input_pub` is a public key kept
  until the row is purged.

**M4. An accepted ADR decision (D1 order) was changed by an implementation note without a recorded owner decision.**
- `docs/adr/0004-device-sealed-input-requests.md` "Implementation notes / D1 order".
  `worker/src/mcp/write-request-tools.ts:228-270` tries the device flow first. ADR D1, as the owner
  approved it, uses the dashboard flow whenever a browser device and a seal key exist.
- This may well be the better choice (the key exposure is narrower than with `VK[e]`), and the stated
  reason may be right: the Worker cannot tell a browser device from others. Even so, it changes which
  flow an owner with a browser device gets. AGENTS.md says no agent may self-attest an owner decision.
- Fix: get the owner to confirm the reordering, recorded on #203, or implement D1 as written if a
  browser-device signal exists.

### Minor

**m1. Release after a thrown dispatch can let a stale PUT complete a later claim.** `input-request-routes.ts:103-107`.
- Scenario: the relay RPC throws after the frame was sent (the DO is reset or the connection is lost),
  so the request is released to `pending_user`. The user submits again, which claims it. The first
  delivery's delayed PUT then finds `submitted` and completes the request with the first value. The
  second delivery gets `not_found` and the settle is a no-op, so the POST answers 410 while the status
  says `completed`.
- No security impact (both values are the user's own), but the answer is confusing.
- Fix: put a claim generation or nonce into `submitted`, have the PUT name it (or have the device echo
  it), and only release when dispatch returned a pre-send outcome.

**m2. Spec route table does not cover relay pre-send refusals.** `input-request-routes.ts:115-119`
- The relay's own `invalid_args`/`denied` (oversize frame, caller scope) come back as `400 bad_request`
  with `pending_user` (released).
- The §3.11 table says "anything else → 500 internal, failed".
- Fix: add a row, or close the request as the table says.

**m3. §9.8 says "a device refusal answers its error.code", but the code maps several codes to `internal`.**
`write-request-tools.ts:217-220`
- `fromDeviceError` maps `expired`, `not_found`, `decrypt_failed`, `unsupported` and `pending_approval`
  to `internal`.
- Fix: align the spec text (for example "conflict, denied, invalid_args; otherwise internal") or pass
  the codes through.

**m4. `?input_request=` on any op other than `item.put` is silently ignored.** `api-handler.ts:106`
- Spec §3.11 says "only on PUT …/items/{id} … 400 bad_request otherwise". `?write_request=` already
  behaved this way before this change.
- Fix: return 400 when the parameter appears on any other op, or reword the spec.

**m5. The input routes have no rate budget.** `input-request-routes.ts:140-153`
- Each GET/POST does a revocation-registry lookup and one or two DO calls. The holder of a valid input
  token can call GET without limit. The sync routes have per-device budgets and MCP has per-account
  budgets.
- Fix: add a per-account window from `limits.ts`, published by `/v1/meta`.

**m6. The spec does not say where the `/input` page gets `account` for the AAD.** spec §3.11 "Flow" (`spec.md:760`) and the GET body.
- The fragment carries `r,v,k,n,p` and GET returns `device_id`, `operation` and `expires_at`. The
  `account` field of the AAD is not in either.
- The page presumably reads `sub` from its input token, but the spec should say so, or GET should
  return it, so that the page (not yet built) does not seal under a wrong account and burn the request
  with `decrypt_failed`.

**m7. Rolling back hurts device rows.**
- The previous revision's `prune` expires only `pending_user`. So after a rollback, `submitted` rows
  never close or purge and count against `write_requests_retained_per_account`.
- The old `openRow` does not filter on `flow`.
- This only matters if the flag was ever on. Add a note to the runbook's rollback section, or expire
  device rows when the flag is turned off.

**m8. Test gaps.**
- No negative test for a `machine` session on the `?input_request` PUT (only `browser` is tested).
- No GET/POST test after the account lost membership. The relay `deviceRole` check covers the POST;
  the GET would still return state.
- The storage dump checks only `write_requests`, not the relay DO audit tables.
- Threat model X16 cites "device tests (agentkit)" that are not in this repo. This is acceptable under
  the "before leaving staging" note, but it is a claim without in-repo proof.

**m9. Misleading error for a refused vault.** `write-request-tools.ts:238`: `writeRequestRoom` returns
false for a restore-pending or refused vault as well as for a full one, so the tool answers
`too_many_requests`. Similarly, a pending rekey is only found after the device has already issued a key
(`createInputRequest` returns `refused`, and the device keeps an orphan key until expiry).

**m10. `delete relayArgs['name']` (`write-request-tools.ts:260`) protects nothing.** The name stays in
`args` and in `form_url`. Remove it, or say why it is there.

**m11. Changelog.** `spec.md:1990`: `secrets_request_input` was added inside the existing
`2026-10 (issue #119)` entry. There is no entry for #203 covering §3.11, the `<origin>/input` audience,
the relay tool set going from 7 to 9 with the both-or-neither `hello` rule, or the two new relay error codes.

**m12. Changes outside the reviewed diff.** `git status` now shows
`M worker/public/app/index.html`, `D worker/public/app/assets/app.277553ad.js` and
`?? worker/public/app/assets/app.1fd4df07.js`, timestamped 2026-10-30 11:41:22. These were not in the
starting status. They are a rebuilt dashboard bundle, and I did not run a vault-app build. Keep them
out of this change unless they are intended (they are a deploy asset).

## Edge cases checked

- **Concurrent POSTs:** the second gets 409 `state: submitted` (tested).
- **Expiry between claim and PUT:** the PUT gets 410 with nothing written (tested).
- **Device offline while another device of the same account is online:** refused, and the value never
  reaches the other device (tested).
- **Timeout racing a completed PUT:** settle leaves `completed` alone, and the answer is 504 with
  `state: completed`.
- **Revoked MCP grant with the request `submitted`:** the PUT pipeline's grant check cancels it, and
  the PUT is then refused.
- **Largest seal:** about 87.4 KB of base64, which fits `relay_frame_max_bytes` (131072) and
  `request_body_max_bytes` (256 KiB).

## Unresolved questions

1. Has the owner accepted the D1 reordering (M4)?
2. Should membership loss be checked on the input routes, or is the relay device-role check at POST
   the intended enforcement?
3. Are the `worker/public/app` asset changes (m12) intended for this branch?

Status: DONE_WITH_CONCERNS
Summary: No blocker. Crypto, token isolation, single use, PUT binding and the flag gate are correct
and tested, and all suites are green with fresh vectors. Before landing, the spec closed sets
(§3.10 states and reasons, §10 codes), the data classification and REVIEW transit list, and owner
confirmation of the D1 reordering need fixing.
