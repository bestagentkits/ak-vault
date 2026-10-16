# Release gates

The go/no-go contract for issue
[#8](https://github.com/bestagentkits/ak-vault/issues/8). Sync becomes GA, and
recommended for real credentials, only after every gate below is satisfied **at the
exact commit being released** and the evidence is linked on #8. A checked box without linked
evidence does not count.

**Production sync is live before this list is complete.** On 2026-10-16 the owner
waived the external-review gate for turning `VAULT_SYNC_ENABLED` on in production and
decided that production sync is fully live, with ak-web production minting vault
tokens ([owner waivers](#owner-waivers)). Any logged-in user running the preview
`ak secrets sync` commands can sync to production. That is an owner waiver, not a
review sign-off: production sync is pre-release, not externally reviewed and not yet
recommended for production credentials. It was enabled while these remain open:
ADR 0001 approval, every red-team scenario executed (scenario 13), the staging
restore, the staging cost measurement and the external review. Also open while
production is live: confirming that the staging and production JWKS share no key
material ([staging soak](#staging-soak)), and the owner confirming on #8 that
Workers Tail access on production is limited, the complement to the tail waiver;
and retiring the formerly shared Cloudflare token, which staging still holds
([below](#production-deploy-control)). The owner's decisions on #8 enabled
production sync with these items open; they still gate GA. The waivers recorded on
#8 are listed [below](#owner-waivers); nothing else is waived, and sync is not GA.

**Released client lags the Worker.** The latest agentkit release with the preview
sync commands, `v3.0.0-beta.30`, predates the removal-fence client (agentkit `dev`
`67ff8e6`). Against the production Worker its device and member removals fail closed
(`400 bad_request`, no signed `log_head`), recovery is blocked as well (the pre-fence
client in the [Docker e2e run on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6206840562)
showed both), and it does not verify change-log contents against removal fences. A release that includes the fence client is tracked in
[agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469). Until then,
a beta.30 user who loses a device revokes it in the ak-web account, which the Worker
enforces on the device's next request.

**Capacity.** Every authenticated request checks the single revocation registry,
which the lab measurement puts at roughly 10 checks a second for the whole service
([cost model](../operations/cost-model.md)). Beyond that, requests queue and then
fail closed with `503`. With the client's 15 s default sync interval that is a few
dozen active devices. Watch the registry's request rate in the Durable Object
analytics ([#65](https://github.com/bestagentkits/ak-vault/issues/65)), and cache or
shard revocation state before it nears that ceiling.

CI evidence cited below is the `main` run at `b25c2bb`
([CI run](https://github.com/bestagentkits/ak-vault/actions/runs/38858206218)); the
change that enabled production sync touched only Worker configuration, the landing
page and docs, and its own CI run is linked from its pull request.

## P0 gates

- [ ] [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md) approved by the owner,
      including resolution of its open items. **Open:** the ADR is still Proposed.
- [x] Go and TypeScript reproduce every vector in `protocol/v1/vectors/` byte for
      byte, including every rejection vector (tamper, wrong AAD, duplicate nonce,
      invalid signature, injected recipient, replay, rollback, unsupported version).
      Evidence: the CI TypeScript and Go cross-verification jobs (above) over
      [`protocol/v1/vectors/`](../../protocol/v1/vectors/).
- [x] Worker integration suite in `worker/test/` green: CAS and preserved `409`
      branches, tombstones, idempotency, cross-tenant denial, wrong `iss`/`aud`/`alg`,
      replayed proof, revoked device and session, stale membership, injected
      recipient, reader and machine write denial.
      Evidence: the CI TypeScript job (above) runs [`worker/test/`](../../worker/test/)
      in workerd; the cases are mapped in the [red-team evidence](./red-team-evidence.md).
- [x] Disclosure scan, **ticked by owner waiver for live tail; the waiver's complement (Workers Tail access limited) is open**: a full Durable Object dump, Worker logs, traces, metrics and
      every error response from a run seeded with known plaintext values and names
      contain none of them ([data classification](./data-classification.md)).
      Platform logs, traces and analytics were scanned with seeded traffic on a
      deployed lab Worker on 2026-10-16, Worker source as `main` at `d097c41`
      ([platform log scan](./red-team-evidence.md#platform-log-scan);
      [run on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6208699925)):
      zero hits everywhere except `wrangler tail`, which shows `AKV-Proof` and
      `AKV-Webhook-Signature` header values
      ([#61](https://github.com/bestagentkits/ak-vault/issues/61)). The Durable
      Object dump, Worker console lines and every response are scanned in workerd by
      red-team scenario 15. The owner waived the tail exposure on 2026-10-16
      ([owner waivers](#owner-waivers)); it is recorded as an exception in
      [data classification](./data-classification.md#handling-rules). #61 stays open
      as later hardening (rename the headers).
- [x] Revocation: a revoked session or device is refused on its next request even
      with an unexpired token; revocation-registry failure returns `503`.
      Evidence: [`revocation.test.ts`](../../worker/test/revocation.test.ts) in the
      CI run above (red-team scenario 3), and the Docker e2e's session revocation.
- [x] Sync-off regression (agentkit#2298): zero HTTP requests; vault v1 behavior
      unchanged. Evidence: agentkit
      [#2425](https://github.com/bestagentkits/agentkit/pull/2425) (merged to `dev`
      at `0944157`): the sync-off sweep over every `ak secrets` leaf in
      `apps/cli/internal/commands/secretscmd/sync_gates_test.go` and
      `apps/cli/internal/commands/secretscmd/no_network_test.go`.
- [x] `resolve` keeps working with the Worker unreachable (agentkit#2298).
      Evidence: agentkit [#2425](https://github.com/bestagentkits/agentkit/pull/2425):
      `apps/cli/internal/commands/secretscmd/sync_gates_offline_resolve_test.go`
      (hung origin, closed port) and
      `apps/cli/internal/runtime/secretsync/lock_across_http_test.go`.
- [ ] Every scenario in the [red-team list](#red-team-scenarios) executed, findings
      triaged on GitHub.
      Latest run: [red-team evidence](./red-team-evidence.md) (PR
      [#46](https://github.com/bestagentkits/ak-vault/pull/46), signed removal
      `log_head` in [#49](https://github.com/bestagentkits/ak-vault/pull/49)):
      scenarios 1 to 12, 14 and 15 executed, findings filed as issues (open
      include [#41](https://github.com/bestagentkits/ak-vault/issues/41) and
      [#42](https://github.com/bestagentkits/ak-vault/issues/42)). **Open:**
      scenario 13 has not run because the attacked feature is not built; run it when
      [#7](https://github.com/bestagentkits/ak-vault/issues/7) or agentkit#2299 lands.
- [x] Two-device round trip and soak (below): replaced by the
      [Docker two-device e2e](../../e2e/docker/README.md)
      ([#55](https://github.com/bestagentkits/ak-vault/pull/55)) by owner decision
      on 2026-10-16. Evidence: the
      [run on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6206840562)
      at `a4f5656`. `worker/`, `packages/`, `go/`, `protocol/` and `pnpm-lock.yaml`
      were unchanged from that commit to the change that ticked this box; re-run it
      if any of them changes before the release commit. Residual risk stated below.
      Re-run at `26a5cdd`, the change that enabled production sync, since `worker/`
      had changed: 11/11 with a 10-minute soak, agentkit `dev` with the fence client
      ([run on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209513849)).
      Later commits of that change touched only `worker/public/` and docs.
- [ ] Backup/restore and rollback rehearsed on staging using the
      [runbooks](../operations/runbooks.md).
      Latest run: [rehearsal log](../operations/rehearsal-2026-10.md) (rollback and
      kill switch on staging; restore on a lab Worker until
      [#51](https://github.com/bestagentkits/ak-vault/issues/51)). **Open:** the
      restore has not run on staging.
- [ ] Cost measured on staging and compared with the
      [cost model](../operations/cost-model.md).
      Latest run: [rehearsal log](../operations/rehearsal-2026-10.md#cost-measurement).
      **Open:** measured on a lab Worker workload plus the staging idle baseline, not
      on staging traffic; the dominant cost at scale is
      [#50](https://github.com/bestagentkits/ak-vault/issues/50).
- [ ] External review signed off (below). **Not signed off.** Production sync was
      enabled before it under the owner waiver of 2026-10-16
      ([owner waivers](#owner-waivers)).
- [x] The removal fence binds the change-log contents, not only a position
      ([#21](https://github.com/bestagentkits/ak-vault/issues/21)): a device that
      first reads the log after a removal can detect a record substituted at or
      below the fence, with vectors in TypeScript and Go and a Worker test.
      Evidence: [#48](https://github.com/bestagentkits/ak-vault/pull/48),
      `protocol/v1/vectors/removal-fence.json` and
      `worker/test/removal-fence-binds-log.test.ts`.

## Staging soak

The owner decided on 2026-10-16
([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6207406980))
that the [Docker two-device e2e](../../e2e/docker/README.md) replaces both the staging
two-device round trip and the staging soak; no authenticated staging session is used.
It runs the real `ak` on two devices with active sync services against this
repository's Worker under `wrangler dev`, with a fake ak-web, and records error rates,
propagation latency and a disclosure scan. Its results are on #8; the e2e README owns
how to repeat it. This supersedes the 2026-10-14 decision to skip only the multi-day
soak.

**Residual risk, for the external reviewer to weigh.** The integration with ak-web
staging's real issuer and JWKS, the delivery of its revocation webhook and the
Cloudflare edge are verified by configuration and by the lab Worker rehearsal
([#54](https://github.com/bestagentkits/ak-vault/pull/54),
[rehearsal log](../operations/rehearsal-2026-10.md)), not by authenticated staging
traffic. Platform logs, traces and analytics were scanned with seeded traffic on a
lab Worker instead (disclosure-scan gate above). Staging trusts ak-web staging's
issuer and JWKS; keeping staging's signing keys separate from production's is
ak-web's responsibility; production sync is live, so confirm as soon as both
endpoints answer that the two JWKS share no key material (compare the keys' `x`/`y`
coordinates, not only their `kid`s).

## Owner waivers

Recorded on #8 by the owner. A waiver accepts a stated risk; it is not evidence and
does not satisfy the external review.

| Date | Waiver | Record |
|---|---|---|
| 2026-10-16 | Live `wrangler tail` shows `AKV-Proof` and `AKV-Webhook-Signature` values to account members with tail access. Accepted as account-operator access: proofs are single-use, bound to token hash, method, URL and body within a ±60 s window; webhook signatures cover one timestamped body with a single-use `event_id`. Complement: restrict Workers Tail permission on production. The header rename stays open as hardening. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248), [#61](https://github.com/bestagentkits/ak-vault/issues/61#issuecomment-6209133562); scan evidence [#62](https://github.com/bestagentkits/ak-vault/pull/62) |
| 2026-10-16 | The Docker two-device e2e replaces the staging two-device round trip and the staging soak; no authenticated staging session is used. Residual risk is stated under [staging soak](#staging-soak). | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6207406980) |
| 2026-10-16 | The external-review gate is waived for enabling `VAULT_SYNC_ENABLED=true` on the production Worker. The external review stays open on #8. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248) |
| 2026-10-16 | Production sync is fully live: ak-web production mints vault tokens together with the Worker flag, so any logged-in user running the preview `ak secrets sync` commands can sync to production before the external review. Docs say it is pre-release, not externally reviewed and not yet recommended for production credentials. This supersedes the earlier statement that minting stays off. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209425010) |
| 2026-10-16 | The owner approves the deploy that enables production sync while the shared-Cloudflare-token bootstrap exception stays an open item ([production deploy control](#production-deploy-control)). | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209176887) |

## Feature flag and kill switch

`VAULT_SYNC_ENABLED` gates the sync API. It is `true` in production since the
2026-10-16 owner decisions above, while the open gates stay open. Returning it to
`false` is the first incident response step: the
[emergency kill switch](../operations/runbooks.md#emergency-kill-switch) when
minutes matter, otherwise the [gated path](../operations/runbooks.md#kill-switch).
Landing page and health endpoints are not affected by the flag.

## Production deploy control

- Production deploys run only through a GitHub Environment with a required human
  reviewer; only the owner approves it, never an agent. Two emergency paths bypass it,
  each recorded on an incident issue: the
  [Worker rollback](../operations/runbooks.md#worker-rollback), and the
  [emergency kill switch](../operations/runbooks.md#emergency-kill-switch), a
  direct deploy that may only set `VAULT_SYNC_ENABLED=false`, under a
  [deploy freeze](../operations/runbooks.md#deploy-freeze) and followed the same
  day by a reviewed pull request (owner decision on
  [#53](https://github.com/bestagentkits/ak-vault/issues/53)).
- The deploy workflow runs only for `main`, only after CI passed on the same commit,
  and both environments allow deployments from `main` only. Cloudflare credentials
  are scoped to the deploy step; actions are pinned by commit SHA. Missing
  credentials fail the job rather than skipping it.
- Production and staging use separate Worker secrets and distinct token audiences,
  so neither accepts the other's tokens. Production CI deploys with its own
  Cloudflare token; staging's credential is not yet separated (below).
  The Worker never receives ak-web's CLI HS256 signing key.
- **Bootstrap exceptions (owner decision, 2026-10-13):** an agent could approve the
  production deployment, and staging and production shared one Cloudflare API token
  (stored separately in each GitHub Environment); both were meant to end before
  enabling production sync, and the owner allowed enabling it with the token item
  still open ([waivers](#owner-waivers)). On 2026-10-16
  ([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209176887))
  the owner ended the first: only the owner approves production deployments,
  including the one that enabled production sync. The second ended the same day
  ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209542641)):
  production deploys use a production-only Cloudflare token without Workers Tail
  permission, set as the `production` environment secret. That record covers only
  the `production` secret: the `staging` environment secret is unchanged since
  2026-10-13, although the record says staging keeps its own secret, so the owner
  should correct the record or replace the staging secret. The next production
  deploy shows the new token can deploy; that it lacks Workers Tail rests on the
  owner's record. **Open:** the `staging` environment secret was not
  replaced, so staging, whose deploys run from `main` without a reviewer, still
  holds the formerly shared token with production scope, and the operator's
  emergency kill-switch token is that same token. Close this when staging gets a
  staging-only token (and the operator a narrow kill-switch token) and that is
  recorded on #8. Worker secrets stay separate per environment.
- GitHub secret scanning, push protection and private vulnerability reporting stay
  enabled on the repository (enabled 2026-10-13; re-check the security settings
  before GA rather than assuming), and no token, key or personal data is committed.

## External review

An independent reviewer with cryptographic expertise, who did not implement the
protocol, reviews the ADR, spec, vectors, Worker auth path and these gates. The
reviewer's sign-off, scope and the reviewed commit are recorded on #8. This gate
cannot be self-attested by the owner's agents or closed by a checklist alone, and the
owner's 2026-10-16 waiver for enabling production sync does not close it; until the
sign-off exists, #8 stays `blocked` and sync is not GA.

## Performance targets

| Target | Owner | Conditions |
|---|---|---|
| `resolve` warm-cache p95 overhead < 50 ms, never blocked by the Worker | AgentKit client (agentkit#2298) | Overhead = p95 with sync enabled minus p95 with sync off, same backend, process model and machine; must hold on each supported backend (memory, keychain, file). Rig and workload recorded with the result |
| Set on device A visible on device B < 60 s | AgentKit client + this Worker | Only when **both** devices run an active sync service and the network is healthy; a CLI without a background service syncs on its next invocation |

## Red-team scenarios

1. Wrong issuer, wrong audience, wrong `alg`, unknown `kid`, expired or not-yet-valid token.
2. Stolen token without the device key; replayed proof; proof for another URL or body.
3. Revoked session; revoked device; revocation registry unavailable.
4. Server injects a recipient or device into membership.
5. Server serves stale membership or rolls back state after a witnessed checkpoint.
6. Server withholds updates from a new device (confirm it is reported as the
   documented limitation, not silently claimed as detected).
7. Concurrent writes from two devices; conflict resolution; retry with the same and
   a different idempotency body.
8. Stale offline device replays writes below a tombstone.
9. Rekey interrupted mid-way; recovery interrupted mid-way.
10. Removed member attempts to read new material; `needs-rotate` set for the rest.
11. Reader and machine identities attempt writes; machine identity reads outside its vault.
12. Cross-tenant read with a valid token for another vault.
13. Hostile shared profile or policy text tries to widen a grant or run a command
    (client-side, agentkit#2299 / #7).
14. Forked pull request tries to read secrets or trigger a deploy.
15. Planted plaintext and names searched for in dumps, logs, metrics and errors.
