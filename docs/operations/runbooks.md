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
  except the [emergency kill switch](#emergency-kill-switch) and the emergency
  [rollback](#worker-rollback), which are then recorded on the incident issue.

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

Production runs with sync **on** (`"true"` in the top-level `vars` of the Worker
configuration) since the owner's 2026-10-16 decision on
[#8](https://github.com/bestagentkits/ak-vault/issues/8), so every deploy from `main`
ships sync enabled unless that value is changed. Turning it off is the first
containment step. Agents may run the [emergency kill switch](#emergency-kill-switch)
without asking first (owner decision on
[#53](https://github.com/bestagentkits/ak-vault/issues/53)); record it on the
incident issue and notify the owner at once.

- To disable: set the variable to `false` for the production environment in the
  Worker configuration and deploy through the gated workflow. That path is a pull
  request, CI on it and on the merge (about 1 minute each in October 2026), the
  staging deploy (about 30 s) and then the production reviewer's approval; plan
  for minutes, not seconds. When that is too slow, use the
  [emergency kill switch](#emergency-kill-switch).
- To re-enable: only after the incident issue records the cause and fix, and the
  [release gates](../security/release-gates.md) relevant to the cause are green,
  through a reviewed pull request that sets `"true"` again and the gated Deploy
  workflow, approved by the owner.
- Verify from outside: `GET /healthz` reports `sync_enabled`, and any `/v1/vaults/...`
  request answers `503 sync_disabled` instead of `401`. Edge propagation is not
  atomic: in the rehearsal, requests still reached the previous version up to 12 s
  after the deploy. Keep probing until several consecutive probes agree.
- The switch is a var baked into each Worker version. Every later deploy from
  `main` applies the value in the Wrangler config, and a [rollback](#worker-rollback)
  applies the value of the version it targets. Either can silently re-enable sync,
  which is why the emergency path sets the [deploy freeze](#deploy-freeze) first.

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

### Emergency kill switch

A direct production deploy that **only** sets `VAULT_SYNC_ENABLED=false`, skipping
the pull request and the production reviewer (owner decision on
[#53](https://github.com/bestagentkits/ak-vault/issues/53)). Use it when sync must
stop faster than the gated path allows. It needs an operator holding production
Cloudflare credentials outside GitHub: the GitHub Environment secrets used by CI
cannot be read back, so make sure such credentials exist before relying on this
path. Holder (owner decision on #53): the operator's local Cloudflare token outside
GitHub, which is the token staging and production shared during bootstrap. Since
2026-10-16 the production CI deploy uses its own production-only token, so the
local token is no longer used by production CI; staging CI still deploys with it,
an owner-accepted risk mitigated by code-owner review since 2026-10-16 (see the
[release gates](../security/release-gates.md#production-deploy-control)). Reading the production deployment status
(step 3) shows the token is live, not that it may deploy; its permissions should be
recorded on #53 by the owner, and a narrow kill-switch token is recommended. Replace
it before it is revoked: without it, turning sync off needs a pull request and the
owner's approval. Load them as `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` without
echoing them, and only after `pnpm install` (as CI does).

- **Never use this path to enable sync**, or to ship code or any other config
  change. `--var` takes only `VAULT_SYNC_ENABLED:false`. Sync comes back only
  through a reviewed pull request and the gated workflow.
- **Record it on an incident issue**: who, when (UTC), the version ID it replaced
  and the version ID it created.

1. Open the incident issue (no sensitive values).
2. **Set `DEPLOY_FREEZE=true` first** (see [deploy freeze](#deploy-freeze)), so no
   automatic or pending deploy replaces the kill-switch version. The freeze stops
   only jobs that have not started, so also clear Deploy runs already in flight:
   list them with
   `gh run list -R bestagentkits/ak-vault --workflow deploy.yml --status in_progress`
   (and again with `--status waiting`) and cancel each with `gh run cancel <run-id>`.
   If a production deploy step is already running, let it finish before step 4.
   Never approve a production deployment that is waiting for review.
3. Find the commit production runs: the latest Deploy workflow run whose
   `production` job succeeded. Its Deploy step log shows the version it created
   ("Current Version ID"). From `worker/` in the main checkout, run
   `pnpm exec wrangler deployments status --env=""` and compare. If the live version
   differs (a rollback or an earlier emergency deploy is in effect), stop: do not
   deploy a commit you cannot match to the live version; escalate on the incident
   issue. Otherwise check that commit out clean and run
   `pnpm install --frozen-lockfile`. Deploying it keeps the code and every other var
   unchanged: without `--keep-vars`, Wrangler replaces all vars with the
   checked-out config plus `--var`.
4. From `worker/` in that checkout, deploy, targeting production explicitly
   (`--env=""` selects the top-level Wrangler config, which is production):

   ```sh
   pnpm exec wrangler deploy --env="" --var VAULT_SYNC_ENABLED:false --message "<incident issue URL>"
   ```

5. Verify from outside as described [above](#kill-switch) until several
   consecutive probes agree, and record the result on the incident issue.
6. **The same day**, open a pull request that sets `VAULT_SYNC_ENABLED` to `"false"`
   in the top-level (production) `vars` of `worker/wrangler.jsonc`, linking the
   incident issue. If `main` already has `"false"` there, record that on the
   incident issue instead. Until that pull request merges, `main` still says
   `"true"`, so any deploy from `main` would turn sync back on; that is why the
   freeze stays set. A Deploy run after the merge refuses at the gate because of
   the freeze; that is expected.
7. **Unfreeze only after that pull request merges.** Repeat the in-flight check
   from step 2 and cancel any Deploy run still waiting for review (it carries an
   older commit), then delete the variable and run the Deploy workflow
   (`gh workflow run deploy.yml -R bestagentkits/ak-vault --ref main`) so production
   runs `main` again through the gated path, now with sync off in the config.

## Remote access

`VAULT_REMOTE_ACCESS_ENABLED` gates the vault dashboard (`/app`), remote MCP
(`/mcp` and its protected-resource metadata), the device relay (`/v1/relay`) and the
lookup, seal-key and sealed-queue routes. Any value other than exactly `true` turns
them off, and each then answers `404`. It is on for staging and off for production in
`worker/wrangler.jsonc`; remote access is staging only, pre-release, and not for
production credentials. The sync kill switch also stops it: with sync off, `/mcp`
answers `503 sync_disabled`. Route behavior is owned by `worker/src/index.ts`,
`worker/src/env.ts` and `worker/test/remote-access-flag.test.ts`; the design and its
plaintext-in-memory boundary by
[ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md) D7.

### Remote access off

Use when the dashboard, relay or MCP endpoint must stop but sync may stay on. When
the cause could touch sync itself, use the [kill switch](#kill-switch) instead.

1. Open the incident issue (no sensitive values).
2. Set `VAULT_REMOTE_ACCESS_ENABLED` to `"false"` in the `vars` of the affected
   environment in `worker/wrangler.jsonc` and land it through a pull request and the
   Deploy workflow. When staging must stop faster, deploy staging directly from a clean
   checkout of the commit it runs, as in the [staging rehearsal](#kill-switch), with
   `--var VAULT_REMOTE_ACCESS_ENABLED:false` instead of the sync variable; land the
   same change in `wrangler.jsonc` the same day, so the next deploy from `main` does
   not turn it back on. Production already runs with it off; turning it on there is
   a later owner decision, not an incident step.
3. Verify from outside until several consecutive probes agree: `/mcp`, `/app` and
   `/.well-known/oauth-protected-resource/mcp` answer `404`, and `GET /v1/meta` no
   longer lists the relay, sealed-queue and MCP limits.
4. Tell affected users: AI tools lose access, devices cannot open the relay, and
   the dashboard stops loading. Sealed operations already queued stay in the vault
   object, unserved, until they expire (`sealed_ttl_s` in
   [`worker/src/limits.ts`](../../worker/src/limits.ts)). Local `resolve` and sync are
   unaffected.
5. Turn it back on only through a reviewed pull request after the incident issue
   records the cause and fix.

### Relay incident triage

Relay and MCP log lines carry only stable codes, latency and hashed tags; they
never hold arguments, results, names, values or raw IDs
(`worker/src/http/operational-logger.ts`). Read them in the Worker's logs:

- `/mcp` lines: `tool`, `outcome` (a tool error code from spec §9.8 and §10, `ok` or
  `queued`), `ms`, hashed `client` and `account`, and whether an audit row was
  written.
- `relay` lines: `event` `close` with the close code the server sent and the hashed
  `account`. Close codes are defined in [spec §9.7](../protocol/v1/spec.md#97-relay).

A rise in `device_timeout` or `no_device_online` for one account is that account's
devices, not the service. A rise across accounts, `internal` outcomes, or `503`s from
`/mcp` point to the relay or vault objects or the revocation registry: check the
[registry capacity alert](#revocation-registry-capacity-alert) first. If a relay
result could be wrong or forged, or plaintext could reach a log, a store or an error,
turn [remote access off](#remote-access-off) before investigating.

### MCP client abuse

An MCP client acting against its user (a prompt-injected agent, a leaked grant):

1. Find it by the hashed `client` and `account` tags in the `/mcp` log lines. Never
   ask for or paste raw client IDs, grant IDs or account identifiers in the issue.
2. The account owner disconnects the app in ak-web (account, Connected Apps). ak-web
   then sends the grant ID in `revoke_sids` to the revocation webhook, and the next
   `/mcp` request with that grant is refused.
3. Per-client and per-account call budgets bound the damage meanwhile
   ([`worker/src/limits.ts`](../../worker/src/limits.ts)). Devices still apply their own
   grants and approvals, and `run` needs an `exec` grant pinned on the device.
4. Tell the user to rotate at the provider any secret a `run` command could have
   printed in transformed form, and to review what the client wrote: a write lands as a
   normal signed record with an audit entry.
5. If many accounts are affected or the client cannot be identified, turn
   [remote access off](#remote-access-off).

### Sealed queue full

`secrets_set` and `secrets_delete` answer `sealed_queue_full` when the vault already
holds `sealed_queue_max` sealed operations. Acknowledged operations keep their ID until
they expire, so a replay is refused, and they count toward the limit
([spec §10](../protocol/v1/spec.md#10-errors-and-limits); values in
[`worker/src/limits.ts`](../../worker/src/limits.ts)).

- Not an outage. Writes that reach an online device are relayed, not queued, so the
  user can keep a device online with relay support and write through it.
- Draining frees no slot at once: space returns as acknowledged and unclaimed
  operations reach `sealed_ttl_s`. Do not delete rows from the vault object by hand.
- A queue that refills quickly from one client is the [abuse](#mcp-client-abuse) case.

## Deploy freeze

The repository variable `DEPLOY_FREEZE` stops the
[Deploy workflow](../../.github/workflows/deploy.yml): while it is `true` the gate job
fails with an error and deploys neither staging nor production, and the production
job checks it again after the reviewer's approval. Unset or `false` means not
frozen; any other value also refuses. Use it during an incident whenever a deploy
from `main` could undo a kill switch or a rollback. Set it at the repository level,
not on an environment.

```sh
gh variable set DEPLOY_FREEZE --body true -R bestagentkits/ak-vault   # freeze
gh variable delete DEPLOY_FREEZE -R bestagentkits/ak-vault             # unfreeze
gh variable list -R bestagentkits/ak-vault                             # check
```

Record freezing and unfreezing on the incident issue. Merges to `main` still land
while frozen; their deploys fail at the gate and are not retried, so after
unfreezing run the Deploy workflow on `main` once.

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
  rollback: set the [deploy freeze](#deploy-freeze) (or land the fix), and do not
  approve a pending production deploy, until the incident is resolved.
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
was off until 2026-10-16, after every revision listed so far) and hold synthetic
data; abandon them and create fresh vaults rather than migrating. A future revision
that changes stored data also reaches production vaults, which hold real users'
data: plan a migration for it instead. How a
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
Local development has no history: there, bookmarks are placeholders and a restore
does nothing. The Worker reaches it through the operator restore route,
`POST /internal/v1/operator` (contract in the header of
`worker/src/routes/operator-restore.ts`), which acts on one vault object and never on
the revocation registry. The route answers 404 unless the environment has the
`VAULT_OPERATOR_SECRET` Worker secret. `worker/scripts/operator-restore.ts` signs and
sends its requests; its header documents the arguments.

**Backup.** History is kept automatically; nothing has to run beforehand. For a
planned change, also record each affected vault's current bookmark with the
operator script's `bookmark` action: it is exact, while a time lookup is not (below).

**Restore**, one vault at a time:

1. Open the incident issue first; for production, the owner decides on the restore
   there.
2. Enable the route: generate a random secret of at least 32 characters into a
   `0600` file outside the repository, and set it without echoing it:
   `wrangler secret put VAULT_OPERATOR_SECRET --env staging` from `worker/`, reading
   the file on standard input. For production, use the top-level environment, and
   only on the owner's decision. `secret put` and `secret delete` each deploy a new
   version of the current Worker code with the secret changed; no code deploy is needed.
3. Get the target bookmark: the one recorded before the change, or a `bookmark`
   with a time (unix ms).
4. Read the current bookmark (`bookmark` without a time), then run
   `restore <vault_id> <target> <current>` straight away. Every client request
   moves the bookmark, so a `409` means the vault changed in between: read it again.
   On a busy vault, turn sync off first with the [kill switch](#kill-switch). A
   time-based target on a young vault can land before its genesis: a `bookmark`
   read afterwards then shows `vault_exists: false`, and the undo still works.
5. The response holds the target and the **undo bookmark** (the moment just before
   the restore). Record both on the incident issue before going on; nothing else
   keeps them. From scheduling until the restart the vault refuses every request
   with `503` and `Retry-After`, so no write is acknowledged and then discarded.
   The route restarts the object and confirms it; the next request sees the
   restored state. `202` with `restart_confirmed: false` means the restart was not
   confirmed: send any operator request for that vault (a `bookmark` read), which
   restarts it first and answers `503` while it still cannot confirm the restart.
6. Verify with a client pull: the membership chain and the change log verify, and
   the head matches the intended point.
7. To undo, read the current bookmark and restore to the undo bookmark the same way.
8. Delete the secret (`wrangler secret delete VAULT_OPERATOR_SECRET` with the same
   environment; there is no `--force` flag, and a non-interactive shell confirms on
   its own) and the local file. Check that `wrangler secret list` no longer shows it
   and that the route answers 404 again.

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
- Membership is restored too. A restore to before a `device_remove`,
  `member_remove` or rekey makes the removed device a member again on the server
  and puts the key epoch back. Compare the membership head before and after; if a
  removal was undone, the owner removes the device again and rekeys at once.
  Revocations in the registry still hold.
- Revocations live in the separate revocation registry object, which the operator
  route cannot reach. Never restore it to before a revocation by any other means: it
  would un-revoke sessions and devices.
- Clients do not re-converge on their own (spec §6; a re-seed protocol is an
  [ADR 0001 open item](../adr/0001-opt-in-zero-knowledge-sync.md#open-items)).
  A device that witnessed newer state refuses the restored vault with `rollback`
  and stops syncing; its local vault and `resolve` keep working. Restore only to
  recover from server-side corruption, one vault at a time. To reconcile, either
  undo the restore, which returns those devices to what they witnessed (devices
  that wrote after the restore then refuse in turn), or have the vault owner move
  to a fresh vault from a device's local state (the client has no command for
  that yet; it is part of the re-seed open item). Never tell users to delete local
  vaults.

**Export.** A vault export is ciphertext plus visible metadata and is handled as
confidential ([data classification](../security/data-classification.md#handling-rules)).
An export procedure is owned by the Worker once implemented; R2 is not used for
backups until the [cost model](./cost-model.md) justifies it.

## Key rotation

| Key | Owner | Procedure |
|---|---|---|
| Token signing keys (JWKS) | ak-web ([ak-web#568](https://github.com/bestagentkits/ak-web/issues/568)); production config provenance in [production deploy control](../security/release-gates.md#production-deploy-control) | ak-web publishes the new key, issues with it, then retires the old one. The Worker accepts only `kid`s present in the current JWKS. Its cache (`worker/src/auth/jwks.ts`) refreshes every 5 minutes, and an unknown `kid` forces a refetch at most every 30 s, so wait at least 5 minutes after publishing before issuing with the new key. |
| Revocation webhook HMAC secret | This repo + ak-web | Generate a new secret in the approved secret store, set it on the Worker with `wrangler secret put <NAME> --env <env>` (name from the Worker config), update the ak-web sender, then verify a test revocation is accepted. The Worker accepts a current and a previous secret (both names in `worker/src/env.ts`): set the old value as the previous secret and the new value as the current one, switch the sender, verify, then delete the previous secret. |
| Cloudflare API token used by CI | Repository admin | Rotate in Cloudflare, update the GitHub Environment secret, run the staging deploy. |
| Vault keys | Clients | Not an operator action; see [key lifecycle](../security/key-lifecycle-and-recovery.md). |

## Revocation registry capacity alert

Every authenticated `/v1` request makes one call to the single `global` revocation
registry object, so its request rate is the service's capacity signal
([#65](https://github.com/bestagentkits/ak-vault/issues/65)). A lab ramp test put
its knee at about 1,000 checks a second
([cost model](./cost-model.md#revocation-registry-throughput),
[#91](https://github.com/bestagentkits/ak-vault/issues/91)). The earlier 8 to 10 a
second was derived from active time per check and was wrong. Past the knee, requests
queue and, on bursts, fail closed with `503`.

**Query (owner, read-only).** With a Cloudflare token that has analytics read access
(never paste it or the account or namespace identifiers anywhere), query the GraphQL
Analytics API for the registry namespace. Its namespace is the one bound as
`REVOCATIONS`; find the ID in the Durable Objects page of the production Worker; the query follows the shape of `USAGE_QUERY` in
`worker/scripts/cost-measurement/cost-analytics.ts`:

```graphql
query ($account: String!, $ns: String!, $from: Time!, $to: Time!) {
  viewer { accounts(filter: {accountTag: $account}) {
    durableObjectsInvocationsAdaptiveGroups(
      limit: 100
      filter: {namespaceId: $ns, datetime_geq: $from, datetime_lt: $to}
      orderBy: [datetimeFiveMinutes_ASC]
    ) {
      sum { requests errors }
      dimensions { datetimeFiveMinutes }
    }
  } }
}
```

Checks per second for a window is `sum.requests / 300` (revocation webhook writes are
included, but are negligible next to check traffic). Run it over the last hour
whenever sync usage grows, after a client release that changes the sync interval, and
on any report of `503` from sync. As a second signal, a sustained rate of `503`
responses with code `unauthorized` means the registry, or the JWKS fetch, is already
queueing or failing; check which before treating it as capacity. Read that rate from
Workers Logs, where the Worker logs status and code only, and not from `wrangler tail`,
which exposes request headers.

**Threshold.** Alert the owner when the registry sustains **500 checks a second for
15 minutes** (half the measured knee of about 1,000), and on any sustained
`503 unauthorized`. Re-run the [ramp test](../../worker/scripts/registry-load/README.md)
after any change to the registry or the request path before it, and set the threshold
to half the new knee here and in the [cost model](./cost-model.md). A scheduled check
in CI needs an analytics-read-only token, which is an owner decision; until then the
query above is the minimum and the owner runs it.

**Response.**

1. Short term: lower the client sync rate (a longer default interval in the next
   client release; adaptive polling is tracked on
   [#63](https://github.com/bestagentkits/ak-vault/issues/63)). If `503` is already
   widespread, use the [kill switch](#emergency-kill-switch) rather than let devices
   retry against a saturated registry.
2. Lasting: replicate the registry (write to all replicas, read from one, with
   `global` as coordinator) or shard it, so the guarantee that a revoked session or
   device is refused on its next request still holds. Do not add a TTL cache in front
   of the check: it weakens that guarantee to "within the TTL" and needs an owner
   decision and a spec change. The design analysis is on #65.

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
