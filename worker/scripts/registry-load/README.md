# Revocation registry ramp test

## Why

Every authenticated `/v1` request calls the single `global` revocation registry
Durable Object (`src/auth/revocation-check.ts`), so that object's throughput caps the
whole service. The earlier "about 10 checks a second" was derived as
`1 / active time per check`, not measured
([analysis on #65](https://github.com/bestagentkits/ak-vault/issues/65#issuecomment-6213539129)).
This script measures the knee on a throwaway lab Worker. The result (about 1,000
checks a second on 2026-10-16) and the alert threshold that follows from it are
recorded in the
[cost model](../../../docs/operations/cost-model.md#revocation-registry-throughput).

## What it does

[`run-registry-load.ts`](./run-registry-load.ts), in order:

1. Estimates the worst-case cost (no included amounts) and refuses to run above
   US$2 (`COST_CAP_USD` in [`registry-load-analysis.ts`](./registry-load-analysis.ts)).
2. Deploys a lab Worker named `ak-vault-lab-regload-…` on `workers.dev` from the
   `staging` environment of `wrangler.jsonc`, with a synthetic issuer (inline JWKS;
   the private key lives in process memory and is handed to the generator processes
   over IPC only) and a random webhook secret, the same way as
   the [cost measurement](../cost-measurement/README.md)
   ([`staging-lab-config.ts`](../cost-measurement/staging-lab-config.ts)).
3. Seeds the registry through the signed revocation webhook: 10,000 sids, dids and
   per-`sub` minimum `iat`s (100 batches of 100), so lookups run against a non-empty
   index. The seeded subs' minimum `iat` lies a day ahead.
4. Checks two controls: a properly proven, unrevoked device gets past the registry
   (any status but `401`/`503`), and one ramp-shape request is refused `401`.
5. Ramps an **open-loop** constant arrival rate (default 5, 10, 20, 40, 80, 160, 320,
   400, 600, 800 and 1,000 a second), 55 s per step, each from a whole minute. The schedule is
   interleaved over child processes of about 100 requests a second each
   ([`registry-load-generator.ts`](./registry-load-generator.ts)); one Node process
   could not hold 600 a second. Each request
   carries a fresh token for a seeded sub with a random sid and did, so the registry
   runs all three lookups (sid miss, did miss, `min_iat` hit) and the Worker refuses
   it `401` before any vault object is touched
   ([`registry-load-traffic.ts`](./registry-load-traffic.ts)). The ramp stops early
   once a step has more than 5% `503` or unanswered, or p99 above 10× the first step.
6. Reads Worker and Durable Object analytics per step window (from the step's
   minute to the first whole minute after its last answer: registry requests, wall
   p50/p99, CPU time, active time, rows read; vault requests should be 0) and applies
   the knee rule: the first step whose registry wall p99 (from analytics) or client
   p99 (answered requests) is above 2× the first step's, with more than 0.1% of
   requests answered `503`, or whose share without any
   answer (client timeout or connection failure) exceeds the first step's by more than
   1 point (the operator network loses some requests at any rate, 0.4% to 1.8% at
   5 a second in the 2026-10-16 runs). A step whose
   generator lag p99 exceeds 1 s arrived in bursts, so the verdict bounds the knee
   instead of locating it.
7. Deletes the lab and checks that it and its Durable Object namespaces are gone,
   also after a failure or an interrupt.

## How

From `worker/`, with a Cloudflare token allowed to deploy Workers and read analytics
(never staging or production; the name pattern refuses anything outside
`ak-vault-lab-…`):

```sh
set -a; . ../.env; set +a      # CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
pnpm registry:load -- --estimate-only
pnpm registry:load -- --report /path/outside/repo/regload.json
```

Options: `--name ak-vault-lab-<suffix>`, `--rates 5,10,…` (increasing, at most 1,000),
`--step-seconds N` (10 to 55), `--seed N` (entries per list). A default run takes
about 40 minutes and sends about 190,000 requests (worst-case estimate under US$0.50;
`--estimate-only` prints it). The generator forks up to one process per CPU core less
one; a machine with fewer than 8 cores may not hold 1,000 a second (the lag column
shows it). Output and report hold aggregates
only (counts, latencies, edge location codes). Exit status: 0 when the run completed,
every answer was `401` or `503`, the generator kept its schedule and the lab was
deleted; 1 otherwise (a stray `502` from the edge is enough); 2 when the run itself
failed.

## Limits

- Client latency includes the network path from the operator's machine to the
  Cloudflare edge. The knee rule compares steps of one run, so that offset cancels;
  the absolute latencies do not describe production clients.
- One client machine. Its requests reached several edge locations, but the registry
  object lives in one place. Production traffic arrives from many edges; the object's
  own limit is the same, but the network part of latency is not. The registry wall
  time from analytics is the signal free of that network.
- The generator lag column shows whether the client kept its schedule; a step where
  it sent less than 90% of its planned requests ends the verdict there.
- The refused-request shape isolates the registry. A real pull also calls the vault
  object, which the [cost measurement](../cost-measurement/README.md) covers.
- Re-run after any change to the registry, the check, or the request path before it,
  and record the commit with the result.
