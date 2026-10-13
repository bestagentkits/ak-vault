# Cost model

An **estimate before measurement** for the Worker + one SQLite-backed Durable
Object per vault ([ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md)). Every
input below is an assumption to be replaced by staging measurements as part of the
[release gates](../security/release-gates.md). Do not quote these figures as
observed cost.

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

## Estimates (USD per month, including the $5 minimum)

| Vaults | Lazy pulls | Active polling every 60 s |
|---|---|---|
| 100 | ≈ $5 | ≈ $10 |
| 1,000 | ≈ $7 | ≈ $101 |
| 10,000 | ≈ $38 | ≈ $1,039 |

At 10,000 vaults with active polling, requests dominate: about 1.3 billion Worker
requests (≈ $388), 2.6 billion Durable Object requests (≈ $390), duration
(≈ $203) and CPU (≈ $51). Rows read stay inside the included 25 billion; rows
written and storage are minor.

## What this means

- **Polling frequency is the cost driver**, not storage. Before GA, measure
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

During the staging soak, record per vault-day: API calls by route, Durable Object
requests, duration, rows read and written, and stored bytes, from the Cloudflare
dashboard or analytics. Replace the assumption table with those figures and note
the date and workload.
