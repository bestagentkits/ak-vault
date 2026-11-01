# Cost model

An estimate for the Worker + one SQLite-backed Durable Object per vault
([ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md)). The first table of
[assumptions](#assumptions) was written before any measurement; per-operation inputs
were then measured on defined workloads, most recently
[on the staging configuration](#measured-2026-10-16-staging-configuration), and
replace them where they differ. Device counts and pull rates are still assumptions,
so do not quote these figures as observed cost.

## Prices used

Cloudflare Workers Paid plan, read from the official pricing pages on 2026-10-13 and
unchanged on 2026-10-16. Recheck the pages before relying on any number here. The
same figures are in [`cost-projection.ts`](../../worker/scripts/cost-measurement/cost-projection.ts),
which computes the estimates below.

| Item | Included per month | Overage |
|---|---|---|
| Workers plan minimum | — | $5 / month per account |
| Worker requests | 10 million | $0.30 / million |
| Worker CPU time | 30 million CPU-ms | $0.02 / million CPU-ms |
| Static asset requests (landing page) | Free and unlimited when served without the Worker | — |
| Durable Object requests | 1 million | $0.15 / million |
| Durable Object duration | 400,000 GB-s | $12.50 / million GB-s |
| SQLite rows read | 25 billion | $0.001 / million |
| SQLite rows written | 50 million | $1.00 / million |
| SQLite stored data | 5 GB-month | $0.20 / GB-month |

Duration is billed on 128 MB per object for wall-clock time while it is active;
objects idle and eligible for hibernation are not billed for duration. The pricing
page states SQLite storage billing was scheduled to start no earlier than
2026-01-07; this model assumes it is active.

Sources: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).

## Assumptions

| Input | Value | Why it matters |
|---|---|---|
| Devices per vault | 3 | Pull volume scales with devices |
| Writes per vault per day | 20 | Sets, rotations, deletes, membership events |
| Pulls per device per day, **lazy** (CLI on demand) | 50 | Pull on invocation with a TTL |
| Pulls per device per day, **active** (sync service) | 1,440 | One poll per minute, 24 h, to meet the < 60 s target |
| Durable Object requests per API call | 2 | Vault object + one call to the single global revocation registry object |
| Durable Object active time per request | 50 ms | Conservative; must be measured |
| Worker CPU per API call | 2 ms | ES256 + Ed25519 verification; must be measured |
| Rows read per call / rows written per write | 10 / 5 | Record, change log, idempotency, index |
| Stored data per vault | 1 MB | Ciphertext, change log, tombstones, membership |
| Days per month | 30 | |

## Measured 2026-10-16 (staging configuration)

Method: [`pnpm cost:measure`](../../worker/scripts/cost-measurement/README.md) at
`b49865c`, the commit staging ran at the time (the next change to `worker/src`,
`6851b0b`, adds only an in-memory check to the sync request path). Staging accepts only ak-web staging tokens and the
owner decided no authenticated staging session is used
([#8](https://github.com/bestagentkits/ak-vault/issues/8)), so the workload ran on a
temporary lab Worker deployed from the `staging` environment of `wrangler.jsonc`
(same entry, compatibility date, observability, Durable Object classes and
migrations; only the name, the synthetic issuer and the webhook secret differ), deleted
afterwards. Each operation ran alone in its own minutes (08:17 to 08:33 UTC), with
its own synthetic vaults, and was read from the same GraphQL datasets as the
2026-10-15 run per phase window. 1,104 requests, all with the expected status except
2 of the 720 polls (`401`; cause not established, possibly the harness retrying an
identical request after a network timeout, which the Worker refuses as a proof
replay). Worker figures divide by the sampled Worker request count, Durable Object
figures by the operations the client made.

| Operation (requests) | Worker CPU | DO requests | DO duration (vault + registry) | Rows read | Rows written |
|---|---|---|---|---|---|
| No-op pull, steady state (1) | 1.9 ms | 2 | 0.0116 + 0.0150 GB-s | 6.6 | **4.74** |
| Item write (1) | 2.0 ms | 2 | 0.0085 + 0.0066 GB-s | 16.2 | 13.2 (up to 0.3 of it deletes setup `jti`s) |
| Device add: `device_add` + new device's wrap fetch (2) | 8.1 ms | 4 (3.3 sampled) | 0.028 GB-s | 24.8 | 17.8 |
| Device remove: fence pull + `device_remove` + `rekey` (3) | 7.0 ms | 6 | 0.028 GB-s | 48.4 | 30.1 |
| Revocation webhook (1) | — | 1 (registry) | — | 1 | 5 |
| Request from a revoked device, refused `401` (1) | 2.8 ms | 1 (registry only) | 0.003 GB-s | 1 | 0 |
| Vault creation: genesis, second device, 3 writes (about 7) | 28 ms | about 14 | 0.033 GB-s | 78 | 74 |

The steady-state pull row is the pull phase from its fourth minute on (295 polls),
after the 120 s proof `jti` lifetime, when each request also deletes the `jti`s that
expired. Over the whole pull phase (720 polls) it was 4.66 rows written and 6.9 rows
read per pull. The two revocation rows share one phase (4 webhooks, then 40 refused
requests): CPU and duration there are averages over all 44 requests, and the split
of the 20 registry rows written to the webhooks assumes a refused request writes none
(the registry only reads on a check). Stored bytes were not sampled within the run window; the 2026-10-15
figure (126,976 bytes for a vault with 4 records) is used below.

Compared with the 2026-10-15 lab run (production configuration, `3f77991`):

| Input | 2026-10-15 | 2026-10-16 | Note |
|---|---|---|---|
| Rows written per pull | 4.76 | 4.74 | Reproduced: the per-request rate counter and proof `jti` writes ([#50](https://github.com/bestagentkits/ak-vault/issues/50)) |
| Rows read per call | 6.9 | 6.6 per pull, 16.2 per write | |
| Worker CPU per call | 3.3 ms | 1.9 ms per pull, 2.0 ms per write | Lower than the earlier run; about the 2 ms assumption |
| DO active time per pull | vault 50 ms; registry about 110 ms | vault 90 ms; registry 117 ms | In this run both objects answered pulls more slowly (Worker wall time 229 ms p50) than writes (37 ms p50); not explained. Duration per pull doubles to 0.027 GB-s |
| Registry checks per second one object can serve | about 10 | about 8.5 (1 / 117 ms) | Derived, not measured, and wrong: the [ramp test](#revocation-registry-throughput) put the knee at about 1,000 a second |

Staging itself, read-only from its analytics: in the 7 days to 2026-10-16 08:12 UTC
1,779 Worker requests (0 errors, CPU 0.70 ms p50), 19 vault and 21 registry Durable
Object requests, 179 vault rows written, and 245,760 bytes stored in the vault namespace
(45,056 in the registry); in the last 24 h of that, 141 Worker requests and no
Durable Object requests. There is no sustained sync on staging, so this is a
baseline only.

## Measured 2026-10-15

Workload: Worker code at commit `3f77991`, deployed as a temporary lab Worker with a
synthetic token issuer (staging only accepts tokens minted by ak-web staging; see
the [rehearsal log](./rehearsal-2026-10.md#cost-measurement)). Five vaults with two
devices each: genesis, `device_add`, 50 item writes, 1,000 incremental change
pulls (the steady-state poll), then a full verified pull and one checkpoint per
device, 1,090 API calls over 5 minutes. Figures are from the Cloudflare GraphQL
Analytics API (`workersInvocationsAdaptive`, `durableObjectsInvocationsAdaptiveGroups`,
`durableObjectsPeriodicGroups`). The request datasets sample and reported 1,072
Worker requests, so request and CPU figures divide by 1,072; the periodic Durable
Object figures (active time, duration, rows) divide by the 1,090 calls the client made.

| Input | Assumed | Measured | Delta |
|---|---|---|---|
| Durable Object requests per API call | 2 | 1.98 (vault 1,070, revocation registry 1,048) | as assumed |
| Durable Object active time per request (vault) | 50 ms | 50 ms (54.3 s / 1,090) | as assumed |
| Durable Object duration per call | 0.0125 GB-s | vault 0.0064 GB-s; registry 0.0135 GB-s, but one global object is capped at about 324,000 GB-s a month | lower at scale |
| Worker CPU per API call | 2 ms | 3.3 ms mean (p50 3.1 ms, p99 9.8 ms) | +66 % |
| Rows read per call | 10 | 6.9 | lower |
| Rows written | 5 per write, 0 per pull | **4.76 per call, pulls included** | every pull writes |
| Stored data per vault | 1 MB | 124 KiB for a vault holding 4 records (`sql.databaseSize`) | lower for small vaults |

Every authenticated request, pulls included, writes SQLite rows in the vault
object: the per-device rate counter, the proof `jti` replay entry and the deletion
of expired `jti` entries, with their index updates (`worker/src/vault/request-guard.ts`).
A request refused at authorization writes a second per-device counter instead of
the first; one refused because the device's authorized budget is spent writes
neither.
A device's first request of each rate window also deletes the counter rows of
earlier windows, so those tables stay bounded; the rows-written figure above
predates that change and has not been re-measured.
The model counted rows written only for item writes.

The revocation check read no rows in this run (the registry was empty), yet its
Durable Object wall time was 167 ms at p50 against 17 ms for the vault object, and
its active time about 110 ms per check. It made Worker wall time 211 ms at p50 in
this run ([#10](https://github.com/bestagentkits/ak-vault/issues/10)).

Staging itself, 2026-10-08 to 2026-10-15 14:00 UTC (smoke runs, landing page and
probes, no sustained sync): 1,640 Worker requests, 0.83 ms mean CPU, 19 vault and 21
registry Durable Object requests, and 245,760 bytes stored in the vault namespace
(45,056 in the registry). That traffic is too small to size anything; it is
recorded as the baseline.

## Revocation registry throughput

Measured 2026-10-16 with [`pnpm registry:load`](../../worker/scripts/registry-load/README.md)
on temporary lab Workers built from the `staging` environment of `wrangler.jsonc`.
The Worker code was at `121c9b3`; since then, nothing on the measured path (token
verification and the registry) has changed. Every lab was deleted afterwards. The registry was
first seeded through the signed webhook with 10,000 revoked sids, 10,000 revoked dids
and 10,000 per-`sub` minimum `iat`s. Each request then carried a fresh token for a
seeded `sub` with a random sid and did. The registry therefore ran all three lookups
(two misses and the `min_iat` hit; 1 row read per check in the analytics), and the
Worker refused the request with `401` without touching a vault object (0 vault
requests in every step). The arrival rate was open loop: a request left on schedule
whether or not earlier ones had answered. Each step sent for 55 s from the start of a
whole minute.

Client latency is measured from one operator machine and includes its network path
to the edge. It compares steps, but does not describe production clients. Requests
that got no HTTP answer at all (a client timeout or connection failure) are counted
apart. The registry's own wall time comes from Durable Object analytics, so it does
not include that network.

The main run (12:35 to 12:47 UTC) spread the schedule over up to 7 generator
processes. Each step's analytics window runs to the first whole minute after its last
answer. Every step kept its schedule: generator lag p99 was at most 60 ms.

| Arrival rate (/s) | Sent | `401` | `503` | No answer | Client p50 / p99 | Registry wall p50 / p99 | Registry CPU per check |
|---|---|---|---|---|---|---|---|
| 5 | 275 | 270 | 0 | 5 | 393 / 3,695 ms | 74 / 240 ms | 0.29 ms |
| 400 | 22,000 | 21,804 | 0 | 196 | 155 / 1,801 ms | 10 / 179 ms | 0.20 ms |
| 500 | 27,500 | 27,227 | 0 | 273 | 174 / 2,245 ms | 37 / 177 ms | 0.20 ms |
| 600 | 33,000 | 32,910 | 0 | 90 | 180 / 2,316 ms | 13 / 199 ms | 0.20 ms |
| 800 | 44,000 | 43,853 | 0 | 146 | 239 / 2,369 ms | 49 / 314 ms | 0.21 ms |
| 1,000 | 55,000 | 54,378 | 0 | 622 | **448** / 3,100 ms | **172 / 1,241 ms** | 0.23 ms |

One `502` at 800 a second is not counted above. Registry wall time is from the
sampled `durableObjectsInvocationsAdaptiveGroups`. CPU per check is
`durableObjectsPeriodicGroups` CPU time divided by rows read (one per check). The
registry reported 1 error, at 1,000 a second.

Two earlier runs used a single generator process:
- **First run** (11:31 to 11:40 UTC, steps 5, 10, 20, 40, 80, 160, 320 and 400 a second):
  0 `503`, registry wall p99 110 to 234 ms, CPU 0.23 to 0.32 ms per check.
- **Second run** (11:46 to 11:50 UTC): 400 a second was clean again. At 600 a second
  the generator fell behind (lag p99 13 s) and sent in bursts, and the Worker answered
  96 `503`s. The main run's clean 600 a second is consistent with the bursts or the
  single generator process, not the rate, being the cause.

What the runs show:
- **Knee: about 1,000 checks a second** (the 1,000 step). There, registry wall p99
  rose to 1.2 s from about 180 to 200 ms at 400 to 600 a second. Registry wall p50
  rose to 172 ms and client p50 to 448 ms. CPU per check did not change, so this is
  queueing in the one object, not costlier checks. 800 a second ran without that rise (wall p99 314 ms). No client saw a `503`
  at any rate in the main run. The knee sits at Cloudflare's documented soft limit of
  about 1,000 requests a second per object.
- **The derived figure was wrong by about 100×.** CPU per check is 0.2 to 0.3 ms.
  Registry active time stops growing with load from about 160 a second on, so
  `1 / active time per check` measured how long the object stays awake, not what a
  check costs.
- **Alert threshold: 500 checks a second** sustained over 15 minutes (half the knee),
  plus any sustained `503 unauthorized`. The query and response are in the
  [runbook](./runbooks.md#revocation-registry-capacity-alert); a scheduled check is
  not configured yet (it needs an analytics-read-only token, an owner decision).
- **In devices, at one request per sync:** the knee is about 15,000 devices polling
  every 15 s, 60,000 polling every 60 s, or 300,000 polling every 5 minutes. The alert
  threshold is half of each. A sync that makes several requests divides these figures.
- **One object is still a single point.** Whatever the throughput, it is one location
  and one dependency for every request
  ([#10](https://github.com/bestagentkits/ak-vault/issues/10)).

## Estimates (USD per month, including the $5 minimum)

Same device count, write rate and pull rates as the [assumptions](#assumptions), with
the 2026-10-16 per-operation inputs (steady-state pull and item write rows above) and
126,976 stored bytes per vault, computed by
[`cost-projection.ts`](../../worker/scripts/cost-measurement/cost-projection.ts).
Registry duration is not capped at one object. The single registry's
[knee is about 1,000 checks a second](#revocation-registry-throughput), roughly 20,000
vaults of 3 devices polling every 60 s. The 10,000-vault active row is about 500 checks
a second, half the knee. The 100,000-vault active row (about 5,000 a second) assumes a
replicated or sharded registry
([#10](https://github.com/bestagentkits/ak-vault/issues/10)); without one it does not
run at all. The registry duration in every row is an upper bound: it bills the measured
registry active time per pull, but one object bills at most 0.125 GB-s a second (about
324,000 GB-s, roughly $4, a month), so below the knee the registry line is smaller.

| Vaults | Lazy pulls (50 a device-day) | per vault | Active polling every 60 s | per vault | per device |
|---|---|---|---|---|---|
| 100 | ≈ $5 | $0.05 | ≈ $22 | $0.22 | $0.07 |
| 1,000 | ≈ $6 | $0.006 | ≈ $694 | $0.69 | $0.23 |
| 10,000 | ≈ $287 | $0.03 | ≈ $7,426 | $0.74 | $0.25 |
| 100,000 | ≈ $3,354 | $0.03 | ≈ $74,803 | $0.75 | $0.25 |

At 10,000 vaults with active polling, **rows written dominate**: about 6.2 billion a
month (≈ $6,166), then Durable Object duration (≈ $427), Durable Object requests
(≈ $390), Worker requests (≈ $388) and CPU (≈ $49). Rows read stay inside the included
25 billion and storage is minor. The fixed floor is the $5 plan minimum; 1,000 lazy
vaults cost about $6.

## Levers ([#63](https://github.com/bestagentkits/ak-vault/issues/63))

Projected with the same inputs, changing only what each lever removes. These are
projections, not measurements; each lever is re-measured when it lands.

| Change | 10,000 vaults active | 100,000 vaults active |
|---|---|---|
| None (above) | ≈ $7,426 | ≈ $74,803 |
| Pulls write no rows | ≈ $1,288 | ≈ $13,430 |
| … and no registry Durable Object call per request (cached) | ≈ $850 | ≈ $9,043 |
| Poll every 5 min instead of 60 s, nothing else | ≈ $1,509 | ≈ $15,577 |
| All three | ≈ $193 | ≈ $2,414 |

## What this means

- **Rows written per pull are the cost driver**, followed by polling frequency;
  storage is not. A pull that wrote no rows would bring the 10,000-vault active
  case to about $1,300 ([levers](#levers-63)). Reducing them is a Worker design decision
  ([#63](https://github.com/bestagentkits/ak-vault/issues/63)).
- **Polling frequency multiplies everything.** Before GA, measure
  whether longer intervals, conditional pulls, or WebSocket hibernation (incoming
  messages billed at 20:1, idle hibernated objects not billed for duration) meet
  the < 60 s target more cheaply. Any change is a client/Worker design decision,
  recorded where it is made.
- Revocation checks double Durable Object requests, and they all go to one global
  registry object (`worker/src/revocation/`). One object's throughput therefore
  caps total API throughput. A lab ramp test
  [put the knee at about 1,000 checks a second](#revocation-registry-throughput).
  Past it, requests queue, and on bursts they fail closed with `503`. The earlier
  figure of 8 to 10 a second was derived from active time per check and was wrong.
  Production sync is live, so watch the registry's request rate (query, threshold of
  500 checks a second, half the knee, and response in the
  [runbook](./runbooks.md#revocation-registry-capacity-alert)), and replicate or shard
  revocation state before demand nears the knee
  ([#10](https://github.com/bestagentkits/ak-vault/issues/10)).
- The Worker runs before static assets (`run_worker_first` in the Wrangler config)
  so the landing page gets the same security headers. Landing traffic is therefore
  billed as Worker requests, not free asset requests; this is small next to API
  polling.
- Storage does not justify R2. Add R2 only if measured blobs or snapshots exceed
  what the per-vault SQLite store handles well, and record the measurement here.
- Quotas and rate limits (published by `GET /v1/meta`, owned by
  `worker/src/limits.ts`) bound the worst case per vault.

## Remote access (staging only, not measured)

Remote access ([ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md)) is on
for staging only and is not in the estimates above. Its cost line, from the request
path rather than a measurement: a relayed MCP tool call adds a second
revocation-registry hop (the Worker checks the MCP grant, then the account's relay
object checks the device before it hands over the call), several calls to that
relay object (rate budget, dispatch, audit row) and two vault-object lookups (account
role, device role). The relay object holds each device's connection through the
WebSocket hibernation API, so an idle connection bills no duration; each device
re-authenticates at least once per sync-token lifetime. Owners:
`worker/src/mcp/tool-dispatch.ts`, `worker/src/relay/account-relay-durable-object.ts`,
and the limits in [`worker/src/limits.ts`](../../worker/src/limits.ts). The
`pnpm cost:measure` harness does not drive `/mcp` or the relay yet; measure this line
before remote access is considered for production.

## Replacing estimates with measurements

Per-operation inputs are measured above; re-run
[`pnpm cost:measure`](../../worker/scripts/cost-measurement/README.md) after any change
to the request path and record the commit. Still open: devices per vault, writes per
vault-day and the pull rate a real sync service uses. The owner replaced the
two-device staging soak with the [Docker two-device e2e](../../e2e/docker/README.md)
([release gates](../security/release-gates.md#staging-soak)), which runs the real
sync service under `wrangler dev` and so has no Cloudflare analytics. Measure these
inputs from the production Worker's analytics datasets above (vault and registry
namespaces), by route, now that ak-web production issues vault tokens, as real
clients sync, and note the date and workload. Re-measure the per-call inputs after any
change to the request path.
