# Cost measurement

## Why

The [cost model](../../../docs/operations/cost-model.md) needs per-operation usage as
Cloudflare bills it: Worker requests and CPU, Durable Object requests and duration,
SQLite rows read and written, and stored bytes. Staging accepts only tokens minted by
ak-web staging, and the owner decided that no authenticated staging session is used
([#8](https://github.com/bestagentkits/ak-vault/issues/8)), so this script measures on
a throwaway lab Worker built from the **staging configuration** and reads the staging
Worker's own analytics as the idle baseline. Staging and production are never
deployed to or sent traffic.

## What it does

[`run-cost-measurement.ts`](./run-cost-measurement.ts), in order:

1. Reads the staging Worker's analytics for the last 24 hours (read-only).
2. Deploys a lab Worker named `ak-vault-lab-cost-…` on `workers.dev` from the
   `staging` environment of [`wrangler.jsonc`](../../wrangler.jsonc): same entry
   (`src/index.ts`), compatibility date, observability, Durable Object classes and
   migrations. Only the name and routing, the issuer (synthetic, inline JWKS, private
   key in process memory only) and the revocation webhook secret (random per run)
   differ.
3. Runs [`cost-workload.ts`](./cost-workload.ts). Each phase starts in its own whole
   minute after at least 65 s without traffic, so the per-minute analytics split by
   operation. Pulls, writes and membership changes use separate vaults; removals
   follow the adds on the same vaults, and the revocation phase revokes the write
   vaults' second devices. Expired proof `jti`s are deleted lazily by the next request
   in a vault, so a phase's first request per vault also deletes the earlier phase's
   (at most a few rows per vault; noted with the results).

   | Phase | Operation counted | Requests per operation |
   |---|---|---|
   | `setup` | vault created | genesis, `device_add`, wrap fetch, 3 item writes, head pulls |
   | `pull` | no-op incremental pull (`GET /changes` at the head), every 5 s per device, 5 minutes | 1 |
   | `push` | item write (update) | 1 |
   | `device_add` | device enrolled | `device_add` + the new device's wrap fetch |
   | `device_remove` | device removed | fence pull + `device_remove` + `rekey` |
   | `revocation` | device revoked by webhook | 1 webhook; then each revoked device makes 10 refused requests |

4. Waits for analytics ingestion, then reads Worker invocations
   (`workersInvocationsAdaptive`), Durable Object invocations
   (`durableObjectsInvocationsAdaptiveGroups`), periodic usage
   (`durableObjectsPeriodicGroups`: active time, duration, rows read and written) and
   stored bytes (`durableObjectsSqlStorageGroups`) for each phase window, plus the
   pull phase from its fourth minute on (steady state: the proof `jti` TTL is 120 s,
   after which each request also deletes the expired `jti`s).
5. Deletes the lab and checks that it and its Durable Object namespaces are gone,
   also after a failure or an interrupt (`SIGINT`, `SIGTERM`).

[`cost-projection.ts`](./cost-projection.ts) turns per-operation inputs into the
monthly figures in the cost model; `worker/test/cost-projection.test.ts` pins it.

## How

From `worker/`, with a Cloudflare token allowed to deploy Workers and read analytics:

```sh
set -a; . ../.env; set +a      # CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
pnpm cost:measure -- --report /path/outside/repo/cost.json
```

Options: `--name ak-vault-lab-<suffix>`, `--baseline-only` (only step 1) and
`--baseline-hours N`. The report is refused inside the repository. A run takes about
30 minutes, about 16 of them traffic (about 1,100 requests). Output and report hold
aggregates only: no credential, account or namespace identifier, vault ID or
synthetic value; the report is written once the traffic ends (phase records) and again
after cleanup (results, problems, `labDeleted`). Exit status: 0 when every request got
its expected status and the lab was deleted; 1 otherwise; 2 when the run itself failed.
Cleanup runs in every case and the last line says whether the lab is gone.

## Limits

- The Worker name, route and issuer differ from staging. Billing metrics depend on
  the code and configuration, which are the staging ones, but edge routing, the
  cached JWKS URL fetch (`src/auth/jwks.ts`) and real staging registry contents are
  not exercised.
- The SQLite storage dataset may have no sample inside the run window; the output then
  says `not sampled`.
- The adaptive datasets (Worker and Durable Object invocations) are sampled; the
  periodic Durable Object usage is what billing uses. Per-operation figures divide
  by the operations the client counted.
- A device here polls every 5 s; the cost model's active client polls every 60 s. Rows
  per request do not depend on the interval in steady state, but Durable Object
  active time per request may (an object that stays warm between requests).
- Re-run after any change to the request path, and record the commit with the result.
