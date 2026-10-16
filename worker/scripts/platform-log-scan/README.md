# Platform log disclosure scan

## Why

The vitest suite and the [Docker e2e](../../../e2e/docker/README.md) scan what the
Worker writes locally: its Durable Object state, its console lines and its responses.
They cannot see what Cloudflare itself records for a deployed Worker: Workers Logs
and traces (Workers Observability), the `wrangler tail` stream and the analytics
behind the dashboard. The [disclosure-scan release gate](../../../docs/security/release-gates.md#p0-gates)
asks for those too. This scan produces that evidence on a throwaway lab Worker, so
staging and production are never touched.

## What it does

[`run-platform-log-scan.ts`](./run-platform-log-scan.ts), in order:

1. Deploys a lab Worker named `ak-vault-lab-…` on `workers.dev`. Its entry,
   [`lab-worker/lab-worker-entry.ts`](./lab-worker/lab-worker-entry.ts), serves every
   request with the real Worker and Durable Object classes and adds only a
   secret-gated dump route (a refused dump request is served by the real Worker). The config is generated from the production top level of
   [`wrangler.jsonc`](../../wrangler.jsonc) by
   [`lab-worker-lifecycle.ts`](./lab-worker-lifecycle.ts): same observability block,
   plus traces (off in production), with sync on and a synthetic issuer's inline JWKS.
   The report records the production and scanned observability settings.
2. Starts `wrangler tail --format json`, then runs [`lab-traffic.ts`](./lab-traffic.ts):
   two-device enroll, push, verified pull, checkpoints, conflict and tombstone,
   audit, recovery bundle, recovery of a lost device, removal and rekey, recovery-key
   rotation, a webhook revocation, and the error paths (bad, foreign and expired
   tokens, bad, foreign and replayed proofs, a revoked session, malformed and
   oversize bodies, a reused idempotency key, bad webhook calls, canaries in URLs
   and headers). Each step checks its status, so untested paths fail the run.
3. Dumps every row of the vault and revocation Durable Objects, pulls Workers
   Observability `events`, `traces` and `invocations` and the GraphQL Workers and
   Durable Object analytics for the run's window (polling until ingestion settles).
4. Searches every source, and every response, for every planted value with
   [`needle-scan.ts`](./needle-scan.ts) (plain, hex, base64 and base64url at all
   byte alignments), and prints hit counts per source and category.
5. Deletes the lab Worker and checks that it and its Durable Object namespaces are
   gone, also when an earlier step failed or the run is interrupted (`SIGINT`,
   `SIGTERM`); a second signal exits without cleaning up.

Gating categories (any hit fails): secret names and values, recovery material,
tokens, proofs, keys, idempotency keys, webhook material, and canaries in refused
bodies and headers. Reported for context only: opaque IDs and canaries in URLs,
because request URLs are platform request metadata
([data classification](../../../docs/security/data-classification.md#handling-rules)),
and the lab's own dump secret.

## How

From `worker/`, with a Cloudflare token allowed to deploy Workers and read Workers
Observability and analytics:

```sh
set -a; . ../.env; set +a      # CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
pnpm scan:platform-logs -- --report /path/outside/repo/report.json
```

Options: `--name ak-vault-lab-<suffix>` (default: a Saigon timestamp) and
`--keep-capture DIR`, which keeps the raw captures to locate a hit. The captures
hold the run's synthetic tokens and canaries; delete them afterwards. The report
and captures are refused inside the repository. Output redacts the token, account
id and workers.dev subdomain. A full run
takes about 10 to 20 minutes, most of it waiting for telemetry ingestion.

Exit status: 0 when no gating hit, every source non-empty and the lab deleted; 1
otherwise; 2 when the run itself failed (the lab is still deleted).

## Limits

- Traces are enabled on the lab only. Production keeps them off; the scan covers
  them so turning them on later does not need a new scan of its own.
- Invocation logs stay off as in production; the scan does not cover them turned on.
- Logpush, Tail Workers and other account-level sinks are not configured for this
  Worker and are not scanned.
- Needles match whole: as text, lowercase hex, or a base64/base64url run. A value
  logged truncated, upper-cased, percent-encoded or split across fields is not
  found. Tokens and proofs are also searched per dot-separated segment.
- Each telemetry view must fit in one query page (2,000 rows); a full page fails
  the run instead of paging.
- The traffic is the protocol library acting as a client, not the `ak` CLI; the
  Docker e2e covers the real CLI.
