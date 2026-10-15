# Cost model

An estimate for the Worker + one SQLite-backed Durable Object per vault
([ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md)). The first table of
[assumptions](#assumptions) was written before any measurement; per-call inputs were
then [measured](#measured-2026-10-15) on a defined workload and replace them where
they differ. Device counts and pull rates are still assumptions, so do not quote
these figures as observed cost.

## Prices used

Cloudflare Workers Paid plan, read from the official pricing pages on 2026-10-13.
Recheck the pages before relying on any number here.

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

## Estimates (USD per month, including the $5 minimum)

Same device count and pull rates as the assumptions, with the measured per-call
inputs (rows written 4.76 per call, CPU 3.3 ms, duration as measured with the
registry capped). The active-polling rows at 1,000 and 10,000 vaults (about 50 and
500 requests a second) also assume a sharded or cached revocation registry: at the
measured active time a single registry object handles roughly 10 checks a second, so
without one those configurations do not run at all
([#10](https://github.com/bestagentkits/ak-vault/issues/10)).

| Vaults | Lazy pulls (assumed → measured) | Active polling every 60 s (assumed → measured) |
|---|---|---|
| 100 | ≈ $5 → ≈ $5 | ≈ $10 → ≈ $22 |
| 1,000 | ≈ $7 → ≈ $6 | ≈ $101 → ≈ $666 |
| 10,000 | ≈ $38 → ≈ $231 | ≈ $1,039 → ≈ $7,109 |

At 10,000 vaults with active polling, **rows written dominate**: about 6.3 billion a
month (≈ $6,142), then about 1.3 billion Worker requests (≈ $388), 2.6 billion
Durable Object requests (≈ $386), duration (≈ $103) and CPU (≈ $86). Rows read stay
inside the included 25 billion and storage is minor.

## What this means

- **Rows written per pull are the cost driver**, followed by polling frequency;
  storage is not. A pull that wrote no rows would bring the 10,000-vault active
  case back to about $1,000 (assuming about 15 rows per item write). Reducing them is a Worker design decision
  ([#50](https://github.com/bestagentkits/ak-vault/issues/50)).
- **Polling frequency multiplies everything.** Before GA, measure
  whether longer intervals, conditional pulls, or WebSocket hibernation (incoming
  messages billed at 20:1, idle hibernated objects not billed for duration) meet
  the < 60 s target more cheaply. Any change is a client/Worker design decision,
  recorded where it is made.
- Revocation checks double Durable Object requests, and they all go to one global
  registry object (`worker/src/revocation/`). One object's throughput therefore
  caps total API throughput; measure it in the soak and cache or shard revocation
  state before that ceiling matters.
- The Worker runs before static assets (`run_worker_first` in the Wrangler config)
  so the landing page gets the same security headers. Landing traffic is therefore
  billed as Worker requests, not free asset requests; this is small next to API
  polling.
- Storage does not justify R2. Add R2 only if measured blobs or snapshots exceed
  what the per-vault SQLite store handles well, and record the measurement here.
- Quotas and rate limits (published by `GET /v1/meta`, owned by
  `worker/src/limits.ts`) bound the worst case per vault.

## Replacing estimates with measurements

Per-call inputs are measured above. Still open: devices per vault, writes per
vault-day and the pull rate a real sync service uses. Measure those during a
two-device staging soak with real clients, by route, from the analytics datasets
above (vault and registry namespaces of the staging Worker), and note the date and
workload. Re-measure the per-call inputs after any change to the request path.
