# Code review: input form (browser side of ADR 0004)

Branch `feat/input-page`, uncommitted changes against `origin/main` (904260c). Reviewed
2026-10-30 (Asia/Saigon) against `REVIEW.md` and the `AGENTS.md` security rules. Read-only review.

## Scope

- Worker: `worker/src/index.ts` (`GET /input` redirect), `worker/test/input-form-redirect.test.ts`
- Browser: `packages/vault-app/src/input/{input-link,input-api,input-controller}.ts`,
  `src/ui/input-view.ts`, `src/main.ts`, `src/oauth/pkce-client.ts`, `src/ui/messages.ts`, `src/ui/views.ts`
- Tests: `packages/vault-app/test/input-form.test.ts`, `test/helpers/fake-input-world.ts`
- Docs: `docs/protocol/v1/spec.md` (Input form section), `docs/security/data-classification.md`,
  `REVIEW.md`, `AGENTS.md`, `packages/vault-app/README.md`
- Generated bundle `worker/public/app/` not read line by line; `test/build-staleness.test.ts`
  covers it (committed output equals a fresh build, SRI matches, no HTML sinks, `console.` or third-party URLs in the JS).

## Evidence (run at the current working tree)

| Command | Result |
|---|---|
| `pnpm -C packages/vault-app test` | 12 files, 282 tests passed (includes build-staleness) |
| `pnpm -C packages/vault-app typecheck` | clean |
| `pnpm -C worker test -- input-form-redirect` | the filter was not applied; the full suite ran: 47 files, 530 tests passed (the workerd "outputGateBroken" lines come from the existing operator-restore tests) |
| `pnpm -C worker typecheck` | clean |

## Verified (no finding)

- **The value is never shown, logged, stored or put in a URL or error.** The field is a password input with `NO_CAPTURE` and is cleared in the submit handler before `controller.submit`. The value goes only into `sealInput`. The `catch` around it drops the error, so no error text reaches the page. `src/` has no `console.` call, and the tests look for a sentinel value in the DOM, `sessionStorage`, every request and response, and every console call.
- **The seal's AAD matches spec §3.11.** `request_id`, `vault_id`, `name` and `purpose` (null when absent) come from the link; `device_id`, `operation` and `expires_at` (ms; the Worker stores ms) come from the GET; `account` is `session.claims.sub`. `refreshSession` pins `sub`/`sid` across a refresh. The test opens the seal with `openInput` under the device's recorded context and fails each changed field.
- **Fragment parsing fails closed.** Only the keys r/v/k/n/p are allowed, each at most once. IDs must be 22-char opaque IDs and `k` must decode to exactly 32 bytes. Name and purpose use `encodeURIComponent`/`decodeURIComponent`, symmetric with the Worker's `inputFormUrl`. The name check is `validItemName` and the purpose check is `validMetaText` with a length of 1..200, both matching the dashboard write flow. `isInputFragment` cannot match `#write=…&vault=…`.
- **Input token checks.** `iss`, `aud`=`<origin>/input`, `session_kind`=`input`, `sub` = the signed-in account, no `did`, and an integer `exp` are all required. The expiry is the earlier of `exp` and `expires_in`. The token is held only on the controller instance.
- **Pending sign-in.** The input form has its own key, `akv-input-signin`, and the dashboard path never reads it. `take()` deletes before parsing. `checkInputLink` checks the stored link again, with an exact key set. State, issuer and the 10-minute age are enforced by the existing `completeSignIn`. The callback goes to the input page only when the input key exists.
- **The dashboard is unchanged when there is no input link.** `isInputPage` is false for `/app/`, for a write link, and for a dashboard callback. The only additions to the dashboard path are removing the input key on a load that is not a callback, and the `hashchange` reload.
- **CSP and Trusted Types.** The page builds DOM only through `h()`/`replaceChildren`, which set text. The input-token endpoint is on the issuer origin, which `connect-src` already allows.
- **Grant revocation.** It runs on every terminal outcome, on a failed token check, on a sign-in that carried no input link, and on `pagehide` with keepalive. Tests cover it.
- **The redirect is gated and is not an open redirect.** `inputRequestsEnabled` requires both flags and only `GET`/`HEAD` are accepted. `Location` is the constant `/app/`, and the query and path are never reflected. The response has `no-store` and the shared security headers. Tests cover the flag matrix, other methods and nearby paths.

## Blocker

### B1. Docs promise the secret name stays in `sessionStorage` at most 10 minutes; the code only refuses it after 10 minutes

- `docs/protocol/v1/spec.md:903`: "the link waits in `sessionStorage` under its own key for at most 10 minutes and is deleted when the callback reads it".
- `docs/security/data-classification.md:84`: "(at most 10 minutes, deleted when the callback reads them)".
- Code: `packages/vault-app/src/oauth/pkce-client.ts:244` (`PENDING_MAX_AGE_MS`) is checked only in `completeSignIn` (line ~238). The entry is deleted only by `take()`: on a callback, on a fresh input link, or by `main.ts:190` when a dashboard page loads. Nothing deletes it when it expires.
- How it fails: someone opens an input link and presses "Sign in to continue", which stores the secret **name** and purpose. They then leave the authorization server tab open, or browse away to another site in the same tab, for an hour. The name stays in that origin's `sessionStorage` for that whole time, until the tab closes or the next `/app` load.
- Why it blocks: the docs state a data-retention guarantee that the code does not deliver. REVIEW.md lists "a doc widens a guarantee without vectors or tests" as a hard-rejection criterion. The new row in the data-classification table states it correctly: "refused after 10 minutes".
- Fix: narrow both sentences. For example: "kept in `sessionStorage` under its own key until the callback reads it, a dashboard page loads, or the tab closes, and refused after 10 minutes." The alternative is to enforce the limit and prove it with a test. One way is to have `mainInput`/`main` call a `take()` that drops entries older than 10 minutes on every `/app` load.

## Major

### M1. No test proves the claim that the input key is removed when a dashboard page loads

- Claim: `docs/security/data-classification.md` new table row ("removed when the callback reads it or a dashboard page loads") and `src/main.ts:189-190`.
- `main()` is not exported and no test runs it. `input-form.test.ts:134-148` only tests `isInputPage`.
- How it fails: a later refactor could reorder `main()`, for example move the `removeItem` behind the `isAuthorizationResponse` branch or delete it. That would silently keep secret names in storage after a dashboard visit, and CI would stay green. This contradicts REVIEW.md "no claims without proof", for a claim about secret names held in storage.
- Fix: move the dispatch-and-cleanup into a small exported function, for example `dispatchPage(url, storage) -> 'input' | 'dashboard'` that also does the removal. Test that a non-callback dashboard load deletes `akv-input-signin` and that a dashboard callback keeps it.

## Minor

### m1. After the 90 s submit timeout or a 503 during the relay, the form reopens even though the value may already have been written

- `src/input/input-controller.ts:346-348` (network or server error → `showForm(false, …)`) and `:126` (`503` that is not `device_offline` → `retry('server')`).
- How it fails: the device writes the item, but the POST aborts at `SUBMIT_TIMEOUT_MS` (`input-api.ts:65`). Or the Worker's relay call throws, settles the request as `failed` and answers 503 (`worker/src/routes/input-request-routes.ts` catch path). Either way the person sees "try again", types the secret a second time and posts it, only to get `409` → `input_closed`. Nothing leaks, because the 409 refuses the claim before any relay. But the person retypes a secret for a request that is already closed. The 'network' text also says nothing about the value possibly having been written.
- Fix: after a network error or a 503 on submit, run `GET` again (`load()`) instead of reopening the form. Or close when `outcome.state` is anything other than `pending_user`.

### m2. A `400` with no `error.state` is reported as "closed without writing"

- `src/input/input-controller.ts:120`: `state === 'pending_user' ? retry : closed('input_rejected')`.
- The Worker's shape refusals in `parseSubmission`, including `unsupported_version` and a `sealed.request_id` mismatch, answer 400 with no `state`, before any claim. The request is still `pending_user`.
- Effect: the page tells the person that the device refused and the request was closed, and it revokes the grant. The request actually stays open until it expires. This is fail-closed, so the only problem is that the message is wrong. Test row `input-form.test.ts:433` locks in this mapping.
- Fix: map `state === null` on a 400 to a separate "this page could not send the value" notice, or document this as intended.

### m3. The sign-in grant can stay alive in an open tab after the request expires

- `src/input/input-controller.ts`: there is no idle lock and no timer at `request.expiresAt`. Revocation runs only on submit or `pagehide`.
- How it fails: someone opens the form and leaves the tab open. The app session, and the refresh token held only in memory, stay live until the tab closes or the refresh token expires, even though the request expired long before. The dashboard has a 15-minute idle lock for this; the input page has none.
- Fix: when the form screen opens, schedule `finish({code:'input_expired'})` at `expiresAt`.

### m4. The "posted once" wording is broader than what the code does

- `docs/protocol/v1/spec.md:912`: "posted once as `{"sealed": …}`".
- The code posts the same seal again after a 401 (`withToken`, `input-controller.ts:243-254`). It also lets the person submit a newly sealed value after 503 `device_offline`, 429, or 400 with `pending_user`, which the Worker releases on purpose.
- Behaviour is correct per the Worker's outcome table. The sentence should say "each submission is one `{"sealed": …}` POST; the Worker accepts at most one claim".

### m5. The log template says `GET /input` for every method

- `worker/src/index.ts:432`: `info.template = 'GET /input'` is set before the method check, so a refused `POST /input` is logged as `GET /input` with status 404.
- Fix: use `${request.method} /input`, or set the template only for GET/HEAD.

### m6. The ADR's consequence still says `/input` is a static page

- `docs/adr/0004-device-sealed-input-requests.md:154-155`: "New static page `/input` under the `/app` CSP". The implementation is a 302 to the `/app/` bundle instead.
- The spec is updated, but the ADR's "Implementation notes" section, which records choices the ADR left open, does not mention this one. Add a one-line note there.

### m7. No test checks that the secret name never reaches a server

- The spec says "never sends it [the fragment] to a server". `expectNoValueAnywhere` checks only the typed value. `input-form.test.ts:234-235` checks the name only against the authorization URL.
- Fix: assert that `world.request.name`, `purpose` and `inputPub` appear in no `world.exchanges[].url` or `requestBody`. The request and vault IDs belong in the route path by design.

### m8. Pasting an input link into a busy dashboard tab reloads it and drops the in-flight work

- `src/main.ts:158-163, 198`: in dashboard mode, a `hashchange` to an input fragment calls `location.reload()` unconditionally. A write-request save in flight on that tab is aborted (`pagehide` revokes the grant).
- This is rare and fails closed, but it contradicts the dashboard's own rule at `app-controller.ts:229`: "A save or close in flight keeps its request". You could ignore the input link while the screen is busy, or say in the code comment that this is accepted.

## Observations (no action required)

- The browser cannot check `k` against the `input_pub` the Worker stores, because the GET does not return it (spec §3.11). If an attacker edits `k`, the browser seals to the attacker's key, but the ciphertext only ever goes Worker → recorded device, which fails `decrypt_failed`. The ADR residual risk (a live compromised Worker) is unchanged.
- Threat model X16 could add `packages/vault-app/test/input-form.test.ts` to its evidence column for the edited-fragment case.
- The new REVIEW.md and AGENTS.md wording adds `/input` as a public redirect. This stays within ADR 0004, which accepted an `/input` page.

## Plan follow-ups

- No plan file was provided. The work matches the brief (redirect, link parsing, sign-in, token, GET, seal, POST, revoke, docs) apart from B1/M1.

Status: DONE_WITH_CONCERNS
Summary: The input form is sound on value handling, the AAD, fail-closed parsing, key separation, CSP and redirect gating, and the focused suites are green. One blocker is doc-only: the spec and data classification overstate how long the secret name stays in `sessionStorage`.
Concerns/Blockers: B1 must be fixed before merge (narrow the claim, or enforce it with a test). M1 asks for a test of the dashboard-load cleanup. The Minor items are UX, log and doc accuracy.
