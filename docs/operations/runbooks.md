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
  Worker configuration and deploy through the gated workflow.
- To re-enable: only after the incident issue records the cause and fix, and the
  [release gates](../security/release-gates.md) relevant to the cause are green.

## Worker rollback

Use when a deploy introduced a fault and the previous version is known good.

```sh
pnpm --filter <worker package> exec wrangler deployments list --env=""   # production is the top-level Wrangler config
pnpm --filter <worker package> exec wrangler rollback <VERSION_ID> --name <production worker name> --message "<incident issue URL>"
```

The worker package name is in `worker/package.json`; the production Worker name is
in the Wrangler config. `wrangler rollback` takes `--name`, not `--env`. Cloudflare
allows rollback only to the 100 most recently published versions and refuses a rollback across a Durable Object class
migration ([Cloudflare rollbacks](https://developers.cloudflare.com/workers/configuration/versions-and-deployments/rollbacks/)).
Rollback changes code only; Durable Object data is untouched, so a rollback past a
storage schema change can fail at runtime. Prefer a forward fix when the schema
moved. Confirm with `wrangler deployments status` and the staging/production smoke.
The staging smoke is `pnpm --filter ak-vault-worker smoke:staging`, with
`STAGING_ISSUER_PRIVATE_JWK_PATH` pointing at the test-only staging issuer key kept
outside the repository; it uses a throwaway vault and prints only step results.

**Protocol revisions without a version bump.** A revision listed under "Revisions" in
the [spec](../protocol/v1/spec.md#revisions) changes wire bodies, so a vault created
before it no longer verifies. The Worker refuses every request to it with
`unsupported_version` ("vault predates the current protocol revision"), and its old
`wraps` table is no longer read. Such vaults exist only on staging (production sync
is disabled until the [release gates](../security/release-gates.md) are met) and hold
synthetic data; abandon them and create fresh vaults rather than migrating.

## Durable Object backup and restore

SQLite-backed Durable Objects support point-in-time recovery to any point in the
past 30 days through the storage API (`getBookmarkForTime`,
`onNextSessionRestoreBookmark`, then `ctx.abort()` to restart)
([Cloudflare SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)).
It is not available in local development. The Worker exposes no restore or export
route (routing is in `worker/src/index.ts`), so a restore needs a reviewed code
change.

Restoring a vault is **an incident in itself**:

- Every client that witnessed a checkpoint newer than the restore point will refuse
  the restored state as a rollback. That is the protocol working, not a bug.
- `onNextSessionRestoreBookmark` returns a bookmark for the moment before the
  restore; keep it on the incident issue so the restore can be undone.
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
