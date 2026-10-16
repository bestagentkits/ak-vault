# Two-device sync end-to-end run in Docker

## Why

The Worker's vitest suite and agentkit's in-process e2e each test one side of the
wire. This stack runs both sides as they run for a user: the real `ak` CLI on two
separate devices, each with its own home, its own file-backend vault and its own
background sync service, talking HTTP to this checkout's Worker under
`wrangler dev`. ak-web is replaced by `fake-akweb`, which implements the parts of
its contract sync uses, so no real account, `ak login` or Cloudflare credential is
involved. Anyone can repeat the run, which makes it usable as soak and red-team
evidence for the [release gates](../../docs/security/release-gates.md), including
the propagation gate (a set on A is visible on B in under 60 s with both
services running).

## What runs

| Service | Contents |
|---|---|
| `vault` | This checkout's `worker/` under `wrangler dev --env staging`, sync enabled, local Durable Objects persisted to a volume. It trusts fake-akweb's ephemeral JWKS and webhook secret. It refuses to start with Cloudflare variables or a `.dev.vars`/`.env` file. |
| `fake-akweb` | [`fake-akweb/`](./fake-akweb/) (Go, using this repo's `go/` module): email OTP sign-in, refresh, sign-out, the §9 vault token mint (ES256 `at+jwt` with `iss`/`aud`/`sub`/`sid`/`did`/`scope`, bound to a device-key signature), JWKS, and the signed revocation webhook to the Worker. Keys are ephemeral, accounts are synthetic (`@example.invalid` only). Test hooks under `/__e2e/` stand in for reading the OTP email and for the account page's revoke button. |
| `device-a`, `device-b` | `ak` built from agentkit `apps/cli` at a pinned commit (multi-stage build), file backend with a synthetic passphrase on tmpfs, signed in to fake-akweb, running `ak secrets sync now --watch` under a supervisor. |

The network is `internal`: nothing in the stack can reach the internet, a real
ak-web, a real vault or Cloudflare. The CLI accepts plain http only for loopback
origins, so each device reaches the vault and fake-akweb through local forwarders
on `127.0.0.1:8787` and `:8788`. The Worker runs with `--local-upstream` set to the
same origin, so request proofs are checked against the URL the CLI signed.

Interactive CLI steps are driven by
[`device/bin/ak-pty-driver.py`](./device/bin/ak-pty-driver.py), which plays the
person at the keyboard on a pseudo-terminal. Those steps are the file-backend
passphrase prompt, the OTP prompt, `get --reveal` confirmation, and
`devices approve`'s code comparison. It does not change CLI behaviour.
Enrollment uses the CLI's own SAS flags (`devices add --offer … --confirm-sas`),
so no test hook in agentkit is needed.

## How

```sh
e2e/docker/run.sh                                  # agentkit origin/dev from ../agentkit
e2e/docker/run.sh --agentkit-ref <branch|sha>      # any fetched agentkit ref
e2e/docker/run.sh --agentkit-dir /path/to/agentkit
e2e/docker/run.sh --scenarios propagation,tombstone
e2e/docker/run.sh --soak 30m                       # adds a soak loop on the healthy pair
e2e/docker/run.sh --keep                           # leave the stack up for inspection
```

The runner needs Docker with Compose v2, git and python3, and runs on the macOS
system bash. Runs are one at a time per host: the compose project name is fixed,
and a run replaces the previous agentkit export. The images build on linux/arm64 and linux/amd64. The agentkit checkout
is read only: the runner resolves the ref to a commit and `git archive`s `apps/cli`
into `.cache/`, keeping only the latest export. That commit is the device image's
build argument and tag. The vault image is labelled with this checkout's commit
(suffixed `-dirty` when `worker/`, `packages/protocol/` or the vault or scanner
files have uncommitted changes), and the runner checks the label after the build.

Each run writes `.results/<Asia/Saigon timestamp>/`, which is git-ignored. It
holds `meta.tsv` (commits, Docker), `results.tsv`, `latency.tsv`, `soak.tsv`,
`disclosure.json`, `summary.txt` and every service's log. The runner prints a
pass/fail table with timings, tears the stack down with
`docker compose down -v --remove-orphans` (unless `--keep`), checks that no
container, volume or network of the project is left, and exits non-zero when any
check failed.

## Scenarios

The owner of each assertion is its function in [`lib/`](./lib/).

| Scenario | Checks |
|---|---|
| setup | Both devices sign in, open file vaults; A enables sync (genesis); B joins by SAS, approved on A; B receives A's existing secret. |
| `propagation` | N sets on A timed until B holds the value, plus one B→A. Every A→B sample must be under 60 s. |
| `concurrent_writes` | Parallel writes to different refs merge. The same ref edited on both devices before either syncs is a preserved conflict (B exit 12, each keeps its value, both list it). `settle --keep local` on B converges both. |
| `tombstone` | A delete propagates (timed). A stale edit made before the delete was seen is reported `discarded_deleted_remotely` and is not resurrected. |
| `offline_catch_up` | B is disconnected from the network (its cycle exits 11). A sets three and deletes one, and B writes one. After reconnecting, both catch up (timed). |
| `kill_switch` | The vault restarts with `VAULT_SYNC_ENABLED=false`. Local writes still work, cycles exit 11 `server_disabled` and nothing propagates. After switching back on, the held write arrives, and neither device's background service stopped. |
| `session_revocation` | fake-akweb posts the signed revocation webhook for B's session but keeps the session valid itself (`webhook_only`). So B can only be refused by the Worker: its service stops with exit 14 on the Worker's `unauthorized`. Nothing reaches B, and it catches up after signing in again. |
| `device_removal` | A removes B: the key epoch advances, secrets are flagged for rotation, and B's service stops with exit 14. Nothing crosses in either direction afterwards. |
| `recovery` | B purges its state and runs `sync recover` with the recovery kit and password, keeping A. B comes back as a new device and gets the secrets, including one written after its removal. The recovery key rotates, A reports `recovery_enrollment`, the members are A and the new B, and propagation works both ways. |
| `soak` (`--soak`) | Alternating timed writes and deletes for the duration. It reports error rate, gate breaches and p50/p95/max latency per direction. |
| `disclosure` | The Worker is stopped, then a scan covers its Durable Object state (raw bytes and a row dump of every SQLite table), its log and wrangler's debug log. The needles are every synthetic name and value, each device's file-backend passphrase and file-vault recovery key, the vault passwords, the sync recovery keys, the revocation webhook secret, and ak-web token markers. Each is searched as plain text, hex and base64/base64url at all byte alignments ([`scanner/`](./scanner/disclosure-scan.mjs)). Every source must contribute a needle, and any hit fails. |

`device_removal` and `recovery` use the removal fence (spec §5). An agentkit
commit that does not sign `log_head` cannot remove a device against this Worker.
Those two scenarios fail on such a commit, which is the expected result.

## Limits

- One account on one host. Device clocks come from the same kernel, so latency is
  measured across containers without clock skew.
- Latency includes the 250 ms polling of the observing device and the CLI's
  5 s sync interval (`E2E_SYNC_INTERVAL`).
- `wrangler dev` runs workerd locally. It does not exercise Cloudflare's network,
  Durable Object placement or rate limits.
- `refuseAgent` sees only the container's process tree, so the CLI does not detect
  the AI agent that started the run on the host.
- fake-akweb implements the contract sync uses, not all of ak-web.

## Security

The stack never handles real credentials. Every key, token, password and secret
is generated per run and is synthetic. The runner drops `CLOUDFLARE_*`/`CF_*`
variables, and both the vault and device entrypoints refuse to start if one
reaches them. Docker build contexts are allow-lists that exclude `.env*` and
`.dev.vars*`. Runner output names scenarios, codes and timings, never secret names
or values.
