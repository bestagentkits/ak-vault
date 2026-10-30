# Input form (ADR 0004, browser side): implementation report

Status: done, not committed (the controller commits).

## What changed

- Worker: `GET`/`HEAD /input` answers `302 Location: /app/`, `Cache-Control: no-store`, with the default security headers, only when remote access and `VAULT_INPUT_REQUESTS_ENABLED` are both `true`. Otherwise, and for any other method, it is a JSON `404 not_found`. The change is in `worker/src/index.ts` and the tests are in `worker/test/input-form-redirect.test.ts`. `wrangler.jsonc` and `.github/` were not touched.
- vault-app:
  - `src/input/input-link.ts` parses the fragment exactly (`isInputFragment`, `parseInputLink`, `checkInputLink`).
  - `src/input/input-api.ts` mints the input token and checks its claims, then makes the GET and the POST.
  - `src/input/input-controller.ts` holds the flow and the outcome mapping.
  - `src/ui/input-view.ts` holds the screens.
  - `src/main.ts` dispatches between the dashboard and the input form (`isInputPage`).
  - `src/oauth/pkce-client.ts`: `sessionPendingStore(storage, key)`, `INPUT_PENDING_KEY = 'akv-input-signin'`, `PendingSignIn.inputLink`, and `beginSignIn`/`completeSignIn` now carry the input link.
  - `src/ui/messages.ts` has the new fixed texts, and `src/ui/views.ts` now exports `countdown`.
- The bundle was rebuilt (`worker/public/app/`).
- Docs:
  - spec §3.11 has a new "Input form (browser)" subsection and a changelog line.
  - `REVIEW.md` lists `GET /input` in the new-endpoint row.
  - `docs/security/data-classification.md` has a row for the pending input sign-in and a short paragraph.
  - `packages/vault-app/README.md` has a new "Input form" section.

## Decisions within the brief

- Some 400 and 503 answers leave the request in `pending_user`: a 400 the relay refused before sending, and a non-`device_offline` 503. In those cases the form stays open (I used `error.state`). Every other 400 is treated as terminal (`input_rejected`).
- A 409 with state `conflict` shows a conflict-branch message. Any other 409 shows "no longer open".
- A 401 from the Worker mints a new input token once, then retries.
- The POST waits up to 90 s, because the relay deadline is 60 s.
- When a dashboard page loads that is not a sign-in callback, it removes any stale pending input sign-in. When an input link's fragment arrives in a page that is already running (`hashchange`), the page reloads so the input form starts fresh.
- The input token's `iss` is also checked against the configured issuer.

## Verification (at the working tree)

- `pnpm -C D:/worktrees/ak-vault/sync-correctness-6a7ab8 typecheck`: protocol, vault-app and worker all pass.
- `pnpm -C .../packages/vault-app test`: 12 files, 282 tests pass. The new `input-form.test.ts` has 84 tests, and build-staleness passes.
- `pnpm -C .../worker test`: 47 files, 530 tests pass. The new `input-form-redirect.test.ts` has 14 tests.
- `pnpm -C .../packages/protocol test`: 17 files, 969 tests pass.

## Open questions

- AGENTS.md "Security rules" lists the only new remote-access routes and does not yet name `/input`. The brief did not include that file. Should the PR add it?
- The ak-web `input-token` endpoint is faked from the brief's contract (no body, `{access_token, token_type, expires_in}`). Its real error statuses should be confirmed once it ships.
