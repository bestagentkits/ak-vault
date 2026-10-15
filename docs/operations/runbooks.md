# Operations runbooks

How to respond to incidents and operate the sync Worker. Worker configuration
(bindings, variables, secret names, environments) is owned by the Wrangler config
in `worker/`; CI/CD by `.github/workflows/`. Check `wrangler <command> --help` for
current flags before running anything below.

Ground rules for every procedure:

- Never instruct users or clients to delete local caches or local vaults. Local
  AgentKit `resolve` keeps working while the service is down; that is the safe state.
- Never paste tokens, secret values, secret names or account identifiers into
  issues, chats, plans or reports. Reference them by store and name only.
- Production changes go through the protected `production` GitHub Environment,
  except the emergency rollback below, which is then recorded on the incident issue.

## Incident response

1. **Contain.** If ciphertext integrity, auth, revocation or disclosure is in doubt,
   set the [kill switch](#kill-switch) first. Clients fall back to local-only.
2. **Open an incident issue** (no sensitive values) and link it from
   [#8](https://github.com/bestagentkits/ak-vault/issues/8) while the gate is open.
3. **Assess** using the [threat model](../security/threat-model.md): which actor,
   which asset, which invariant failed.
4. **Respond** with the matching procedure: [rollback](#worker-rollback),
   [restore](#durable-object-backup-and-restore), [key rotation](#key-rotation),
   or the client-side flows in
   [key lifecycle](../security/key-lifecycle-and-recovery.md#compromise-response).
5. **Tell users what was exposed** in terms of the
   [data classification](../security/data-classification.md): metadata exposure is
   not value exposure, and value exposure means provider rotation.
6. **Close** with a regression test or vector that reproduces the failure.

## Kill switch

`VAULT_SYNC_ENABLED` controls the sync API. When it is `false`, sync routes refuse
with the `sync_disabled` error code; the landing page, `/healthz` and `/v1/meta`
stay up. Any value other than exactly `true` disables sync (fail closed). Exact
route behavior is owned by the Worker source and its tests.

- To disable: set the variable to `false` for the production environment in the
  Worker configuration and deploy through the gated workflow. That path is a pull
  request, CI on it and on the merge (about 1 minute each in October 2026), the
  staging deploy (about 30 s) and then the production reviewer's approval; plan
  for minutes, not seconds.
- To re-enable: only after the incident issue records the cause and fix, and the
  [release gates](../security/release-gates.md) relevant to the cause are green.
- Verify from outside: `GET /healthz` reports `sync_enabled`, and any `/v1/vaults/...`
  request answers `503 sync_disabled` instead of `401`. Edge propagation is not
  atomic: in the rehearsal, requests still reached the previous version up to 12 s
  after the deploy. Keep probing until several consecutive probes agree.
- The switch is a var baked into each Worker version. Every later deploy from
  `main` applies the value in the Wrangler config, and a [rollback](#worker-rollback)
  applies the value of the version it targets. Either can silently re-enable sync
  ([#53](https://github.com/bestagentkits/ak-vault/issues/53)).

**Staging rehearsal** (direct deploy, staging only; the production rule above still
applies). Find the commit staging runs from the latest successful Deploy workflow
run (CI deployments carry no Wrangler message), check it out clean and run
`pnpm install --frozen-lockfile`. Then:

```sh
pnpm --filter <worker package> exec wrangler deployments status --env staging   # note the current version ID
pnpm --filter <worker package> exec wrangler deploy --env staging --var VAULT_SYNC_ENABLED:false --message "<issue URL>"
# restore the prior value by rolling back to the version noted above
pnpm --filter <worker package> exec wrangler rollback <VERSION_ID> --name <staging worker name> --message "<issue URL>"
```

Before the rollback, run `deployments status` again. If anything other than your
kill-switch version was deployed since you noted the ID (for example a CI deploy),
do not roll back, which would downgrade the code; redeploy from the same clean
checkout without `--var` instead.

Evidence: [rehearsal log](./rehearsal-2026-10.md).

## Worker rollback

Use when a deploy introduced a fault and the previous version is known good.

```sh
pnpm --filter <worker package> exec wrangler deployments list --env=""   # production is the top-level Wrangler config; staging: --env staging
pnpm --filter <worker package> exec wrangler rollback <VERSION_ID> --name <production worker name> --message "<incident issue URL>"
```

The worker package name is in `worker/package.json`; the Worker names are in the
Wrangler config. Always pass `--name`: run from `worker/` without it, `wrangler
rollback` targets the top-level config, which is **production**. In a
non-interactive shell `wrangler rollback` does not prompt; it answers its own
confirmation with yes and deploys at once. Cloudflare allows rollback only to the
100 most recently published versions and refuses a rollback across a Durable Object class
migration ([Cloudflare rollbacks](https://developers.cloudflare.com/workers/configuration/versions-and-deployments/rollbacks/)).

- A rollback restores the target version's code **and its vars**, including the
  [kill switch](#kill-switch). Rolling back past a kill-switch deploy turns sync
  back on; check the target version's `VAULT_SYNC_ENABLED` first.
- Durable Object data is untouched, so a rollback past a storage schema change can
  fail at runtime. Prefer a forward fix when the schema moved. Vaults written
  under a newer protocol revision may not parse under older code.
- After every green push to `main` the Deploy workflow redeploys staging
  automatically and queues production for the reviewer. Either replaces a
  rollback: hold merges to `main` (or land the fix), and do not approve a pending
  production deploy, until the incident is resolved.
- Confirm with `wrangler deployments status` (it shows the rollback message) and
  the staging/production smoke. On staging the rollback was live within about 6 s.

**Staging smoke.** The `smoke:staging` script in `worker/package.json` runs the sync
flow against staging with real vault tokens. It does not sign in itself: it reads a
file holding a fresh ak CLI session token from an email sign-in against ak-web
staging, and asks ak-web staging to mint each device's token, the same path a client
uses. Inputs (session token file, optional ak-web origin and device state path) are
documented in the header of `worker/scripts/staging-smoke.ts`. It prints only step
names, HTTP statuses and stable error codes.

- Use a dedicated staging test account; the vault account is that session's account.
- The smoke's two device keys are kept in a local `0600` state file outside the
  repository and reused across runs, because ak-web binds a device key to one
  account and caps live device keys per account. Each run creates a new synthetic
  vault; the Worker has no per-account vault limit, and these vaults are abandoned.
- Write the session's access token (from an `ak login` email sign-in against ak-web
  staging) into a `0600` file outside the repository without echoing it, and delete
  the file after the run. On POSIX systems the smoke refuses secret files that are
  symlinks, inside the repository, or accessible to group or others.
- Do not run two smokes on the same state file at once.
- `device_revoked` or `device_conflict` from ak-web means the stored keys can no
  longer mint (revoked, or bound to another account). Delete the state file to bind
  new keys, and revoke the old ones in the ak-web account if they are still live.
  `device_limit` means the account holds too many live device keys; revoke unused
  ones there.
- A failure right after minting that the target does not trust ak-web's issuer
  means the Worker's issuer or JWKS settings do not match ak-web's staging
  deployment. Check the Wrangler config, and that no `VAULT_JWKS_JSON` secret is set
  on the environment (it would override the JWKS URL).
- Staging no longer uses a test-only issuer; delete any old staging test issuer
  private key left on operator machines.

**Protocol revisions without a version bump.** A revision listed under "Revisions" in
the [spec](../protocol/v1/spec.md#revisions) changes wire bodies, so a vault created
before it may no longer verify. Such vaults exist only on staging (production sync
is disabled until the [release gates](../security/release-gates.md) are met) and hold
synthetic data; abandon them and create fresh vaults rather than migrating. How a
stale vault shows up depends on the revision:

- Vaults from before the signed-wrap-set / removal-fence revision: the Worker
  refuses every request with `unsupported_version` ("vault predates the current
  protocol revision"), and their old `wraps` table is no longer read.
- Vaults from before the removal `log_head` revision (2026-10, #21): on its first
  start under the new code each vault backfills its change-log heads, and vaults
  without removals keep working. A vault whose membership log already holds a
  `device_remove` or `member_remove` is still **served** by the Worker (reads `200`,
  writes `409 rekey_required` until rekeyed), but clients refuse its chain with
  `bad_request` ("log_head is required"). Reset it: create a fresh vault. A backup
  taken after the removal is refused the same way, and restoring to before the
  removal would re-admit the removed device, so never do that. The Worker
  should refuse these too ([#52](https://github.com/bestagentkits/ak-vault/issues/52)).

Before deploying a revision that changes stored data, write the deploy time (UTC)
and the version ID it replaces on the issue. That is the backup: point-in-time
recovery can return any vault to a moment before the deploy for 30 days (see
below), and rolling back the Worker needs the version ID.

## Durable Object backup and restore

SQLite-backed Durable Objects support point-in-time recovery to any point in the
past 30 days through the storage API
([Cloudflare SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)).
It is not available in local development. The Worker exposes no restore or export
route (routing is in `worker/src/index.ts`), so a restore needs a reviewed code
change ([#51](https://github.com/bestagentkits/ak-vault/issues/51)); until one exists
the procedure below was rehearsed on a separate lab Worker (see the
[rehearsal log](./rehearsal-2026-10.md)).

**Backup.** History is kept automatically; nothing has to run beforehand. For a
planned change, also take `getCurrentBookmark()` on each affected vault object and
record it: it is exact, while a time lookup is not (below).

**Restore**, inside the vault's Durable Object, one vault at a time:

1. Get the bookmark: the one recorded before the change, or
   `getBookmarkForTime(t)`.
2. `onNextSessionRestoreBookmark(bookmark)`. It returns the **undo bookmark** (the
   moment just before the restore). Record it on the incident issue before going
   on; nothing else returns it.
3. `ctx.abort()` restarts the object (the call that aborts receives an error; that
   is expected). The next request sees the restored state; in the rehearsal that
   took 2 to 4 s.
4. Verify with a client pull: the membership chain and the change log verify, and
   the head matches the intended point.
5. To undo, repeat steps 2 and 3 with the undo bookmark.

What the rehearsal showed about `getBookmarkForTime`:

- It is approximate and resolved **earlier** than the requested time for recent
  points: exact for a point 5 minutes old, about 90 s early for a point 2 minutes
  old. Check the restored head before accepting a time-based restore.
- For a vault created minutes ago it fails ("This database has no history." or
  "Requested time is before this database existed.") even for times after its
  creation. Use a recorded bookmark for young vaults.

Restoring a vault is **an incident in itself**:

- Every client that witnessed a checkpoint newer than the restore point will refuse
  the restored state as a rollback. That is the protocol working, not a bug. A
  device that only witnessed older state cannot tell: the restore is invisible to it.
- The whole object is restored, including the checkpoint relay, idempotency records,
  proof `jti` replay entries and rate counters. Relayed checkpoints newer than the
  restore point are gone, and a device re-posting its newer checkpoint gets
  `400 bad_request` (ahead of the stored state). `jti` entries burned after the
  restore point are forgotten, so a captured token and proof could be replayed once
  within the `jti` window (`worker/src/limits.ts`) after the restore.
- Revocations live in the separate revocation registry object. Never restore that
  object to before a revocation: it would un-revoke sessions and devices.
- How clients re-converge after a deliberate restore is not yet specified
  ([ADR 0001 open items](../adr/0001-opt-in-zero-knowledge-sync.md#open-items-before-approval)).
  Until it is, restore only to recover from server-side corruption, one vault at a
  time, and expect the vault owner's devices to need manual reconciliation.

**Export.** A vault export is ciphertext plus visible metadata and is handled as
confidential ([data classification](../security/data-classification.md#handling-rules)).
An export procedure is owned by the Worker once implemented; R2 is not used for
backups until the [cost model](./cost-model.md) justifies it.

## Key rotation

| Key | Owner | Procedure |
|---|---|---|
| Token signing keys (JWKS) | ak-web ([ak-web#568](https://github.com/bestagentkits/ak-web/issues/568)) | ak-web publishes the new key, issues with it, then retires the old one. The Worker accepts only `kid`s present in the current JWKS. Its cache (`worker/src/auth/jwks.ts`) refreshes every 5 minutes, and an unknown `kid` forces a refetch at most every 30 s, so wait at least 5 minutes after publishing before issuing with the new key. |
| Revocation webhook HMAC secret | This repo + ak-web | Generate a new secret in the approved secret store, set it on the Worker with `wrangler secret put <NAME> --env <env>` (name from the Worker config), update the ak-web sender, then verify a test revocation is accepted. The Worker accepts a current and a previous secret (both names in `worker/src/env.ts`): set the old value as the previous secret and the new value as the current one, switch the sender, verify, then delete the previous secret. |
| Cloudflare API token used by CI | Repository admin | Rotate in Cloudflare, update the GitHub Environment secret, run the staging deploy. |
| Vault keys | Clients | Not an operator action; see [key lifecycle](../security/key-lifecycle-and-recovery.md). |

## Secret scanning

- Repository: GitHub secret scanning and push protection (see
  [release gates](../security/release-gates.md#production-deploy-control)).
- If a secret is committed: rotate it first, then remove it from history only if
  the owner decides to; removal does not un-leak it.
- Before sharing logs or dumps in an issue, scan them for tokens, values and
  names; prefer describing the error code and route.

## Process hygiene

Stop any local `wrangler dev` or test processes you started, and remove local
`.wrangler/` state you created, when a task ends.
