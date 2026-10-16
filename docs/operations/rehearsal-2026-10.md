# Rehearsal log, October 2026

Evidence for two [release gates](../security/release-gates.md) on
[#8](https://github.com/bestagentkits/ak-vault/issues/8): backup/restore and rollback
rehearsed using the [runbooks](./runbooks.md), and cost measured and compared with
the [cost model](./cost-model.md). Production was not touched. Times are UTC.
Commands are shown without credentials; `wrangler` ran from
`worker/` with the Cloudflare token and account loaded from the environment.

Runbook corrections that came out of this rehearsal are already in the runbooks and
the cost model; gaps are tracked in
[#50](https://github.com/bestagentkits/ak-vault/issues/50),
[#51](https://github.com/bestagentkits/ak-vault/issues/51),
[#52](https://github.com/bestagentkits/ak-vault/issues/52) and
[#53](https://github.com/bestagentkits/ak-vault/issues/53).

## What ran where

| Part | Target | Commit | Why there |
|---|---|---|---|
| Worker rollback and roll-forward | staging (`ak-vault-staging`) | `3dcec74` (version `c2c18885`) ↔ `a94b1ba` (version `7d807d78`) | Real staging Worker; same Worker source in both versions, no migration between them |
| Kill switch off and restore | staging | `3dcec74` | Real staging Worker |
| Backup, restore, undo, client rollback detection | temporary lab Worker | `3dcec74` | Staging has no restore route and accepts only ak-web-minted tokens |
| Wire-change upgrade with backup | lab Worker | `3dcec74` → `3f77991` | Same reasons; mirrors the staging deploy of the removal `log_head` revision |
| Cost workload | lab Worker | `3f77991` | Authenticated workload needs tokens staging would not accept |
| Backup, restore, undo, client reconciliation (2026-10-16) | staging | `6851b0b` | Operator restore route and an owner `ak login` session now exist |

The **lab Worker** (`ak-vault-restore-drill`, on a `workers.dev` URL, deleted at
14:56) ran the real Worker entry and Durable Object classes from the commit above. It
trusted a synthetic ES256 issuer generated for the run (inline JWKS) and added
drill-only RPCs on the vault object (`getCurrentBookmark`, `getBookmarkForTime`,
`onNextSessionRestoreBookmark`, `ctx.abort()`, `sql.databaseSize`) behind a random
per-run secret. Clients were real: protocol-library device keys, signed membership
events, encrypted and signed records, AKV-Proof on every call, and full client-side
verification of pulls. All values were synthetic. The harness was temporary and is
not in the repository; [#51](https://github.com/bestagentkits/ak-vault/issues/51)
tracks a reviewed restore path.

**Needs the owner:** seeding synthetic vault data on staging itself, the staging
smoke, and an authenticated staging cost run all need a fresh ak CLI session from an
`ak login` email sign-in against ak-web staging (see the staging smoke in the
[runbooks](./runbooks.md#worker-rollback)). None was available to this rehearsal.

## Worker rollback (staging, 2026-10-15)

A probe recorded `/healthz` (`sync_enabled`), `/v1/meta`, the landing page and an
unauthenticated `GET /v1/vaults/<id>/changes` (`401` with sync on, `503 sync_disabled`
with it off).

| Time | Step | Result |
|---|---|---|
| 14:04:15 | CI deployed `3dcec74` to staging (version `c2c18885`) | Baseline 14:05:01: healthz ok, sync on, meta 200, landing 200, probe 401 |
| 14:05:14 | `wrangler rollback 7d807d78-… --name ak-vault-staging --message "staging rollback rehearsal (#8)"` | Live at 14:05:20 (about 6 s). Three probes to 14:05:56 all healthy. `deployments status` shows the version and message |
| 14:06:28 | `wrangler rollback c2c18885-… --name ak-vault-staging --message "staging roll-forward rehearsal (#8)"` | Live at 14:06:34, healthy |

The rollback ran without a prompt (non-interactive shells auto-confirm). Run from
`worker/` without `--name`, the same command would target production; the runbook
now says so.

## Kill switch (staging, 2026-10-15)

| Time | Step | Result |
|---|---|---|
| 14:07:03 | `wrangler deploy --env staging --var VAULT_SYNC_ENABLED:false --message "staging kill-switch rehearsal (#8)"` from a clean checkout of `3dcec74` | Version `5c6922af` at 14:07:24 |
| 14:07:24 → 14:09:37 | Probes | `sync_enabled=false`, probe `503 sync_disabled`, healthz/meta/landing up. One probe at 14:07:36 still saw `sync_enabled=true` (edge propagation) |
| 14:09:52 | `wrangler rollback c2c18885-… --name ak-vault-staging --message "staging kill-switch restore rehearsal (#8)"` | Prior value `true` restored with the rollback; the first probe at 14:09:58 still saw `false`, every probe from 14:10:25 to 14:12:15 saw sync on and `401` |

Findings, now in the runbook: stale responses up to 12 s after a deploy in each
direction (the next probes, 20 to 30 s later, all agreed);
a rollback restores the target version's vars, so rolling back past a kill-switch
deploy re-enables sync; and the next deploy from `main` re-applies the config value
([#53](https://github.com/bestagentkits/ak-vault/issues/53)). The gated production
path measured from recent runs: CI about 1 minute per run, staging deploy about
30 s, then the production approval.

Some probes returned `000`. These were connection failures between this operator
network and Cloudflare (TCP connect up to 4 s and TLS up to 14 s, the same against
production `/healthz`), not Worker errors: Worker analytics for 14:00 to 14:20 show
112 requests, 0 errors, CPU 0.9 ms p50 and wall time 1.7 ms p50.

Final state: staging was left on the CI-deployed version with sync on. CI then
deployed `7dde6d2` (14:27:15) and `3f77991` (14:34:28) as usual.

## Backup, restore and client rollback detection (lab, `3dcec74`)

Two-device synthetic vault (owner and laptop):

| Time | Step | Result |
|---|---|---|
| 14:19:49 → 14:19:53 | Genesis, `device_add`, items 1 and 2; both devices pull, verify and post checkpoints at `log_seq` 2 | All `201`/`200` |
| 14:19:56 | **Backup**: `getCurrentBookmark()` | Bookmark recorded |
| 14:20:00 → 14:20:02 | Laptop writes item 1 rev 2 and item 3; laptop pulls, verifies and checkpoints `log_seq` 4. The owner does not pull | `200`, `201` |
| 14:20:03 → 14:25:31 | `getBookmarkForTime(backup time)`, retried for 5.5 minutes | Failed: "This database has no history.", then "Requested time is before this database existed." |
| 14:25:33 | **Restore**: `onNextSessionRestoreBookmark(backup)`, then `ctx.abort()` | Undo bookmark returned; the aborting call gets an error, as expected |
| 14:25:36 | Laptop pull (first attempt, 3.3 s after scheduling) | `log_seq` 2; state digest equals the backup-point checkpoint; record digests at positions 1 and 2 equal the pre-restore ones; membership chain verifies and its head is unchanged |
| 14:25:36 | Client rollback check (spec §6) | **Laptop raises `rollback`** ("log_seq is behind the witnessed checkpoint"). The owner, which only witnessed `log_seq` 2, accepts the restored state: a restore is invisible to a device that never saw newer state |
| 14:25:36 | Server checkpoint relay | Back to both devices at `log_seq` 2. Re-posting the laptop's `log_seq` 4 checkpoint: `400 bad_request` (ahead of stored state) |
| 14:25:39 | **Undo**: restore to the undo bookmark, abort | 14:25:40: `log_seq` 4, state digest equals the laptop's checkpoint, no alarm, a new write succeeds |

**Time-based restore** (second vault, one write every 25 s for 12 writes, then
restores by time, each undone):

| Point age | Expected `log_seq` | Restored `log_seq` |
|---|---|---|
| 318 s | 2 | 2 |
| 206 s | 6 | 5 |
| 107 s | 10 | 7 |

`getBookmarkForTime` resolves approximately and, here, always earlier than the
requested point, by up to about 90 s for recent points. The runbook now asks for a
recorded bookmark before planned changes, and a head check before accepting a
time-based restore.

## Wire-change upgrade with backup (lab, `3dcec74` → `3f77991`)

This rehearses the staging deploy of the removal `log_head` revision (#48, #49),
which adds per-position change-log heads backfilled when each vault object starts.

| Time | Step | Result |
|---|---|---|
| 14:37:34 → 14:37:42 | Under `3dcec74`, with the old protocol library: vault N (3 writes) and vault R (3 writes, then `device_remove` signed with `log_fence` only); `getCurrentBookmark()` on both as the backup | All `201`/`200` |
| 14:37:47 → 14:38:01 | Lab Worker upgraded to `3f77991` | Deployed |
| 14:38:32 | N: new-wire client verifies membership and `verifyChangeLog` from position 0 | Backfilled heads served for every entry; client-computed head equals the served head |
| 14:38:33 | R: same | Client refuses the membership chain: `bad_request` "device_remove.body.log_head is required". Worker still serves R (all reads `200`, write `409 rekey_required`), unlike the earlier revision's `unsupported_version` ([#52](https://github.com/bestagentkits/ak-vault/issues/52)) |
| 14:38:36 → 14:38:40 | Restore N and R to their pre-upgrade backups under the new code | N: backfill runs again and the restored log verifies (`log_seq` 3). R: still refused; the reset is the only fix |

For staging this means:

- The backup is point-in-time history. The last staging state before the revision
  is the one before the CI deploy at 2026-10-15 14:27:15 UTC (replacing version
  `c2c18885`), recoverable by time until 2026-11-14.
- Staging vaults without removals keep working after the backfill.
- Staging vaults that already hold a removal must be reset. This is in the
  runbook's "Protocol revisions" paragraph.

## Cost measurement

Workload: lab Worker at `3f77991`, 14:39:43 → 14:44:49. Five vaults, two devices
each: genesis, `device_add`, 50 writes, 1,000 incremental change pulls (cursor at
the device's head, about 0.55 s apart per vault), then a full verified pull and a
checkpoint per device. 1,090 API calls, all `200`/`201`. Analytics for 14:39 to
14:46 (GraphQL `workersInvocationsAdaptive`, `durableObjectsInvocationsAdaptiveGroups`,
`durableObjectsPeriodicGroups`, `durableObjectsSqlStorageGroups`), read after
ingestion settled:

| Metric | Value |
|---|---|
| Worker requests (sampled) / errors | 1,072 / 0 |
| Worker CPU | 3.56 s total; 3.3 ms mean, 3.1 ms p50, 9.8 ms p99 |
| Worker wall time | 211 ms p50 |
| Vault DO requests / wall p50 / p99 | 1,070 / 17 ms / 358 ms |
| Revocation registry DO requests / wall p50 / p99 | 1,048 / 167 ms / 255 ms |
| Vault DO active time / duration | 54.3 s / 6.96 GB-s |
| Registry DO active time / duration | 115 s / 14.7 GB-s |
| Vault rows read / written | 7,480 / 5,184 |
| Vault database size (4 records) | 126,976 bytes |

Compared with the model's assumptions: Durable Object requests per call and active
time per request match. Worker CPU is 66 % higher. Rows read are lower. **Rows
written are 4.76 per call including pulls** (5,184 over the 1,090 calls made), where
the model assumed none for pulls. At 10,000 vaults with active polling this moves the
estimate from about $1,039 to about $7,109 a month, almost all of it rows written
([#50](https://github.com/bestagentkits/ak-vault/issues/50)). Registry latency is
reported on [#10](https://github.com/bestagentkits/ak-vault/issues/10): at about
110 ms active per check a single registry handles roughly 10 checks a second. The full
comparison and revised table are in the [cost model](./cost-model.md#measured-2026-10-15).
The client-side latency of this run (494 ms p50 per pull) is dominated by the
operator network noted above and is not a service measurement.

## Staging restore (2026-10-16)

The restore procedure in the [runbooks](./runbooks.md#durable-object-backup-and-restore)
ran end to end on staging ([#51](https://github.com/bestagentkits/ak-vault/issues/51)),
through the operator route merged in
[#73](https://github.com/bestagentkits/ak-vault/pull/73) (`6851b0b`, CI-deployed to
staging at 08:32:43 as version `7d959abc`). The clients were
`worker/scripts/staging-restore-rehearsal.ts` (its header lists what each pull
verifies): two synthetic device keys, owner and laptop, bound to the owner's staging
account through an `ak login` email sign-in, holding ak-web-minted vault tokens. The
vault and every record were synthetic. Bookmarks appear here only as their first 8
characters.

| Time | Step | Result |
|---|---|---|
| 08:33:27 | `wrangler secret put VAULT_OPERATOR_SECRET --env staging` from a `0600` file outside the repository | Version `18f179ce`; the route answers `401` to an unsigned probe |
| 08:35:57 → 08:36:01 | Storage mechanics on an empty random object id through the route | Two bookmark reads with no writes in between are identical. Restore `200`, restart confirmed; the bookmark afterwards sorts after the one before. Replay `409`. Undo `200`; its undo bookmark sorts before the current one, and the bookmark afterwards sorts after it. Replay of the first restore after the undo `409`. Time lookup 5 s back `400` |
| 08:42:20 → 08:42:27 | `tsx scripts/staging-restore-rehearsal.ts` step 1: genesis, `device_add`, two writes; both devices pull, verify and checkpoint `log_seq` 2 | All `201`/`200` |
| 08:42:27 | **Backup**: current bookmark | Recorded; a second read is identical. A time lookup 5 s back on this young vault: `400` |
| 08:42:28 → 08:42:31 | Laptop makes two writes (item A rev 2, item C) and checkpoints `log_seq` 4; the owner does not pull | `200`, `201` |
| 08:42:33 | **Restore** to the backup bookmark | `200` with the undo bookmark; replay `409`; serving `log_seq` 2 after 0.4 s; the bookmark afterwards sorts after the one before |
| 08:42:35 → 08:42:37 | Reconciliation | **Laptop (witnessed 4) refuses with `rollback`.** The owner (witnessed 2) accepts `log_seq` 2: the documented limitation. Re-posting the laptop's `log_seq` 4 checkpoint: `400`; the relay holds `[2, 2]` |
| 08:42:38 → 08:42:41 | The owner makes three writes (item D, item B rev 2, item D rev 2), so the restored history reaches `log_seq` 5 with different contents | **Laptop (witnessed 4) refuses the fork with `rollback`.** `checkRollback` alone passes it; the digest and head check at the witnessed position refuses it (below) |
| 08:42:44 | **Undo** to the undo bookmark | `200`; serving `log_seq` 4 after 0.3 s; replays of the restore and of the undo `409`. The laptop accepts `log_seq` 4 with the state digest of its pre-restore checkpoint. **The owner (witnessed the post-restore `log_seq` 5) refuses with `rollback`**: its writes after the restore are gone and are not accepted silently. A new write `200` |
| 08:42:51 → 08:42:54 | Restore to the bookmark read before genesis, then its undo | `200`; `vault_exists: false` and a client read `404`; the undo serves `log_seq` 5 with `vault_exists: true`, and the laptop accepts it |
| 08:43:49 | `wrangler secret delete VAULT_OPERATOR_SECRET --env staging` | Version `692a04b9`; `secret list` no longer shows it, and the route answers `404` |

Findings:

- A restore and its undo each move the current bookmark forward, and the
  compare-and-swap refused every replayed restore request on staging storage. The
  [threat model](../security/threat-model.md) (T8) now relies on that evidence.
- `checkRollback` compares digests only at an equal `log_seq`, so a vault restored
  and then grown past a device's witnessed position passes it. Spec §6 now spells
  out that such a log must be refused; the §5 head rule and the §6 digest rule
  already required it. No vector or CI test covered the case at the time
  ([#76](https://github.com/bestagentkits/ak-vault/issues/76)); protocol vectors and
  TS and Go tests now do (`removal-fence.json` `restored_regrown_*`), and the agentkit
  client test is still open there.
- `wrangler secret delete` has no `--force` flag (an unknown flag prints the help
  and deletes nothing). A non-interactive shell auto-confirms the prompt.

The staging CLI session was revoked afterwards (ak-web then refuses the session
token), and the two synthetic device keys were reported to the owner for
revocation.

## Not covered

- Restore on production: not exercised; this rehearsal ran on staging only.
- Authenticated traffic on staging and the two-device soak: need the owner's
  `ak login` session (above).
- The production kill switch path was timed from CI history, not exercised.
