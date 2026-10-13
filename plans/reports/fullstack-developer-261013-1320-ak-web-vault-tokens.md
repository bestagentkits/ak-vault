# ak-web vault device tokens (ak-web#568)

**Status: DONE_WITH_CONCERNS.** PR: https://github.com/bestagentkits/ak-web/pull/571 into `dev` (it says "Refs #568"). Branch `feat/vault-device-tokens`, commit dfa54f99. The PR is not merged and nothing was deployed. No remote database was touched.

## Delivered
- **Mint route** `POST /api/agentkit/vault/token`:
  - Ed25519 request proof with strict encoding checks.
  - The did is bound to the account in `vault_device_keys` and capped at 50 live keys per account.
  - The session is checked again after binding.
  - Tokens are ES256 with typ at+jwt and a 300 s TTL, signed with the OAuth key.
  - Fails closed (503) when the audience or webhook is not configured.
- **Revocation outbox** `vault_revocation_events`, with four triggers: session revoke (`revoke_sids`), revoke-all (`min_iat`), device revoke (`revoke_dids`), and account merge (`min_iat` for the source user).
- **Delivery:**
  - Signed webhook.
  - Immediate send after commit, plus a per-minute cron.
  - Lease and fencing on claimed rows; 30-day prune of delivered rows; ops alert on failures.
- **Flag and env** in `lib/env.ts`: `VAULT_TOKENS_ENABLED` (off by default), `VAULT_TOKEN_AUDIENCE`, `VAULT_REVOCATION_WEBHOOK_URL` and `VAULT_REVOCATION_WEBHOOK_SECRET`. The docs and `.env.example` use the exact production and staging audiences.
- **Migration** `0070_fine_earthquake` adds two new, empty tables.

## Evidence
- Type-check, lint and `db:verify-migrations` pass, and the build exits 0.
- The vault, route, cron, session and merge suites pass. The vault suites also pass under Node 22.
- The full jest run on this machine (load average ~260) hit timeouts in unrelated UI and blog suites. Rerun in band, they pass, except `tailwind-tokens`, which has a hard-coded 10 s timeout. CI is the authority.
- The real ak-vault Worker code accepted a minted token and a signed webhook.

## Concerns
- **Merge moves device keys, but vault membership stays with the source.** Merge moves the keys to the target, while Worker vault membership is keyed by the source `sub`. After a merge, the target's tokens carry a different `sub`, so the user needs a vault re-share or recovery.
- **The staging Worker uses a test issuer.** Its config must point at the ak-web staging issuer and JWKS before end-to-end testing.
- **User deletion queues no revocation.** Device keys cascade-delete, but already-issued tokens live up to 5 minutes.
- **Mint does not check a kit entitlement.** It requires only an active CLI session.
- **`resourcePolicy` registration was skipped.** The issue comment asked to register the vault there, but the task said not to touch OAUTH_RESOURCES.
- **No sign-out-all button.** There is no account UI for it; this PR adds the route only.
- **`event_id` is a UUID**, which the Worker's pattern accepts.
- **The k8s CronJob manifest is not applied.** Applying it needs approval; until then the per-replica `cron-entrypoint.sh` runs delivery.

## Review fixes

New head: `ee55a41ad9f0e1fcbe2e0f6ed9d25e1245a15711`, pushed to `feat/vault-device-tokens`. The PR is not merged and its body is updated. The fixes follow `code-reviewer-261013-1538-ak-web-571-review.md`.

**Fixes**

1. **Account deletion revokes vault tokens.** `enqueueVaultAccountDeletionRevocation` queues `min_iat` = now+1 and `revoke_dids` for the account's live devices.
   - It runs inside the deleting transaction, before the user delete. The GDPR route now uses a transaction; admin orphan and claim-email already did.
   - The event is sent after commit.
   - The misleading comment in `account-merge-fk-coverage.ts` is fixed.
2. **Delivery statuses.** Only 400, 413 and 422 are terminal. Everything else retries, 401, 403 and 404 included, up to 20 sends; then the row is `failed`, and the log carries the event ID and status only.
   - The cron alert now also fires on 4xx responses that are still retrying (`rejected` count).
   - New requeue procedure: `scripts/requeue-failed-vault-revocations.ts` (`pnpm vault:requeue-revocations`, dry run by default). The steps are in `docs/deployment-guide.md` under "Scheduled work".
3. **Atomic enqueue.** Single-session revoke, `revokeSessionFamily` and revoke-all now enqueue in the session-update transaction, with no savepoint.
   - On failure the outbox logs, sends a Discord ops alert (rate-limited) and rethrows. The sign-out rolls back and the route answers 500.
4. **Queue without webhook config.** The outbox no longer checks the webhook config. Delivery leaves rows pending until the config exists; mint still fails closed. Docs and `.env.example` are updated.
5. **Real-Postgres coverage.** The repo has a real-database harness: `verify:*` tsx scripts that the CI `fk-coverage` job runs after `db:migrate` on a clean Postgres 16. I added `scripts/verify-vault-revocation-outbox.ts` and a CI step. It checks:
   - binding: a foreign or revoked did is refused, the owner's live key is refreshed;
   - two concurrent claims return disjoint rows, and a leased row cannot be claimed again;
   - fencing: an outcome recorded under a superseded lease changes nothing;
   - 422 marks the row failed, and requeue resets it;
   - the deletion event survives the cascade and carries the right dids and `min_iat`;
   - the status CHECK refuses an unknown status.

**Nits**

- Revoke-all also sends `revoke_sids`. Lists over 100 entries are split across events.
- Attempts are counted when an outcome is recorded, not when a row is claimed, so rows skipped by the run budget cost nothing.
- The comment about Worker event-id retention is fixed: 409 within 15 minutes, idempotent re-application after that.
- A status CHECK constraint is added. The unmerged 0070 was regenerated as `0070_sudden_dexter_bennett`; the migration contract is valid.
- Docs now record the account-merge decision (merged users must be re-added to their vaults or recover) and the no-tombstone rationale.

**Evidence (at ee55a41a)**

- `pnpm run type-check`: pass. `pnpm run lint`: clean.
- `pnpm db:verify-migrations`: valid, 71 migrations through 0070_sudden_dexter_bennett.
- Touched jest suites: 33 suites, 366 tests pass. Vault suites under Node 22: 109 tests pass.
- `pnpm run verify:vault-revocation-outbox` on a scratch local Postgres 16, after `db:migrate`: OK.
  - Mutation checks: removing the fencing predicate, or the bind `setWhere`, makes it fail.
  - The scratch cluster was removed afterwards.
- `pnpm run verify:vault-revocation-outbox` was not yet run in CI at the time of writing.
- `pnpm vault:requeue-revocations`: the dry run, `--apply --event-id` and the invalid-ID refusal were checked on the scratch DB.
- `pnpm run build`: exit 0.

**Remaining concerns**

- The first-bind vs refresh-reuse race (reviewer nit) is accepted, not fixed. It leaves at most one token of up to 5 minutes with no revocation event.
- Event IDs are still UUIDs. The ak-vault spec wording (§2 "b64 of 16 bytes" vs the webhook `event_id`) should be clarified on the ak-vault side.
- No shared cross-repo token vector exists yet.
