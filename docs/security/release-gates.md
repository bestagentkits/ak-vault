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
recommended for production credentials. The external-review requirement was later
dropped; the review gate is the [review by the owner](#review-by-the-owner).
Production sync was enabled while these remain open:
every red-team scenario executed (scenario 13), the staging restore (since
rehearsed), the staging cost measurement (since met by a lab-Worker measurement of
the staging build, accepted by the owner), the review (by the owner;
accepted 2026-10-16, not an independent third-party review;
[below](#review-by-the-owner))
and ADR 0001 approval (since accepted by the owner, P0 gates below). Also open when
production went live, since confirmed on 2026-10-16: the staging and production JWKS
share no key material, compared by the keys' `(crv, x, y)` coordinates
([staging soak](#staging-soak),
[evidence on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6213027838)).
The complement to the tail waiver, Workers
Tail access on production restricted, was confirmed by the owner on 2026-10-16
([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)).
The owner's decisions on #8 enabled production sync with these items open; they still gate GA. The waivers recorded on
#8 are listed [below](#owner-waivers); nothing else is waived, and sync is not GA.

**Older clients lag the Worker.** The removal-fence client (agentkit `67ff8e6`)
first shipped in agentkit [`v3.0.0-beta.31`](https://github.com/bestagentkits/agentkit/releases/tag/v3.0.0-beta.31) (2026-10-16,
[agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469)), with the
sync commands still hidden. Releases up to `v3.0.0-beta.30` predate it. Against the
production Worker their device and member removals fail closed (`400 bad_request`,
no signed `log_head`), recovery is blocked as well (the pre-fence client in the
[Docker e2e run on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6206840562)
showed both), and they do not verify change-log contents against removal fences. A
user on such a release upgrades, or revokes a lost device in the ak-web account,
which the Worker enforces on the device's next request.

**Capacity.** Every authenticated request checks the single revocation registry. A
lab ramp test put its knee between 800 and 1,000 checks a second for the whole
service ([cost model](../operations/cost-model.md#revocation-registry-throughput),
[#91](https://github.com/bestagentkits/ak-vault/issues/91)): at 1,000 a second registry
wall p99 rose from about 200 ms to 1.2 s, and 800 a second ran without that rise. That
is one lab run from one client machine, with requests the registry refuses (all three
lookups, no vault object), so treat it as the registry's own limit, not a measured
end-to-end figure. Past
the knee, requests queue and, on bursts, fail closed with `503`. With the client's
15 s default sync interval and one request per sync, the knee is about 15,000 active
devices. The query, alert threshold (500 checks a second sustained, half the knee)
and response are in the
[runbook](../operations/runbooks.md#revocation-registry-capacity-alert)
([#65](https://github.com/bestagentkits/ak-vault/issues/65)); replicate or shard
revocation state before demand nears the knee.

CI evidence cited below is the `main` run at `b25c2bb`
([CI run](https://github.com/bestagentkits/ak-vault/actions/runs/38858206218)); the
change that enabled production sync touched only Worker configuration, the landing
page and docs, and its own CI run is linked from its pull request.

## P0 gates

- [x] [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md) approved by the owner.
      Evidence: the owner accepted it on 2026-10-16
      ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210567772)). The owner accepted it with restore reconciliation
      still an [open item](../adr/0001-opt-in-zero-knowledge-sync.md#open-items) of
      the ADR, so this gate no longer requires that item resolved; the staging
      restore gate below was met separately. Acceptance is not the [review](#review-by-the-owner).
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
      Added after that run: `api_key_device` and `machine` sessions refused on
      `GET /recovery`, a replacing `PUT /recovery` and recovery-key rotation whatever
      their role, with the genesis seal (first bundle of a vault without one) allowed
      ([#90](https://github.com/bestagentkits/ak-vault/issues/90),
      [`recovery-fetch.test.ts`](../../worker/test/recovery-fetch.test.ts)); its
      evidence is the CI run of [#152](https://github.com/bestagentkits/ak-vault/pull/152). The
      [red-team evidence](./red-team-evidence.md) mapping (scenario 11) cites it.
- [x] Disclosure scan, **ticked by owner waiver for live tail; the waiver's complement (Workers Tail access restricted on production) confirmed by the owner on 2026-10-16**: a full Durable Object dump, Worker logs, traces, metrics and
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
      [data classification](./data-classification.md#handling-rules). The owner
      confirmed the complement, Workers Tail access on production restricted, on
      2026-10-16 ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)); agents did not inspect the account, so it
      rests on the owner's statement. #61 stays open as later hardening (rename the
      headers).
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
      scenarios 1 to 12, 14 and 15 executed, findings filed as issues
      ([#41](https://github.com/bestagentkits/ak-vault/issues/41) fixed; open include
      [#42](https://github.com/bestagentkits/ak-vault/issues/42), blocked on ak-web
      marking non-human sessions). Scenario 13 was re-run on 2026-10-27 against
      agentkit `dev` with synced profiles, enforced synced policy and MCP relay
      arguments as the hostile input: no grant widened, no command ran and no
      forged profile field passed the provenance check; hardening filed as
      [#150](https://github.com/bestagentkits/ak-vault/issues/150) and
      [agentkit#2745](https://github.com/bestagentkits/agentkit/issues/2745)
      ([red-team evidence](./red-team-evidence.md#scenario-13-hostile-policy-and-profile-text);
      first run [#80](https://github.com/bestagentkits/ak-vault/issues/80)).
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
- [x] Backup/restore and rollback rehearsed on staging using the
      [runbooks](../operations/runbooks.md).
      Evidence: [rehearsal log](../operations/rehearsal-2026-10.md): rollback and
      kill switch on staging (2026-10-15); backup, restore, undo and client
      reconciliation on staging through the operator restore route
      ([2026-10-16](../operations/rehearsal-2026-10.md#staging-restore-2026-10-16),
      [#51](https://github.com/bestagentkits/ak-vault/issues/51)). Devices that
      witnessed newer state refused the restored vault (a log regrown past the
      witnessed position is covered by protocol vectors and TS and Go tests,
      `removal-fence.json` `restored_regrown_*`; the agentkit client test is open on
      [#76](https://github.com/bestagentkits/ak-vault/issues/76)); v1 has no automatic
      re-convergence (an [ADR 0001 open item](../adr/0001-opt-in-zero-knowledge-sync.md#open-items)).
- [x] Cost measured on a lab Worker running the staging commit and configuration,
      accepted by the owner in place of staging, and compared with the
      [cost model](../operations/cost-model.md). The owner accepted this method as
      meeting the gate on 2026-10-16, with no re-measurement on staging
      ([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212027109),
      [options](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6211030336)).
      Evidence: 2026-10-16, a lab Worker built from the staging commit (`b49865c`)
      and configuration, plus the read-only staging idle baseline
      ([cost model](../operations/cost-model.md#measured-2026-10-16-staging-configuration),
      [#75](https://github.com/bestagentkits/ak-vault/pull/75), repeatable with
      `pnpm cost:measure`). It is a lab measurement of the staging build, not of
      staging traffic: staging accepts only ak-web staging tokens and no
      authenticated staging session is used, so the lab trusted a synthetic issuer,
      and device counts and pull rates in the model are still assumptions. Pinned
      to `b49865c`; `6851b0b` has since changed the request path, so re-run
      `pnpm cost:measure` on the release commit before GA.
      The dominant cost at scale is still rows written by every pull; reducing it is
      [#63](https://github.com/bestagentkits/ak-vault/issues/63).
- [x] Review by the owner ([below](#review-by-the-owner)): **accepted by the owner
      on 2026-10-16** (owner instruction in chat, recorded by an agent on the
      owner's behalf; [record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)). No written findings were recorded, and
      the owner did not state which checks or commits were reviewed. This is the
      owner's review, not an independent third-party review. Production sync was
      enabled before it under the owner waiver of 2026-10-16
      ([owner waivers](#owner-waivers)).
- [x] The removal fence binds the change-log contents, not only a position
      ([#21](https://github.com/bestagentkits/ak-vault/issues/21)): a device that
      first reads the log after a removal can detect a record substituted at or
      below the fence, with vectors in TypeScript and Go and a Worker test.
      Evidence: [#48](https://github.com/bestagentkits/ak-vault/pull/48),
      `protocol/v1/vectors/removal-fence.json` and
      `worker/test/removal-fence-binds-log.test.ts`.

## Remote access gates

The browser device, relay and remote MCP
([ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md)) run on staging only,
behind `VAULT_REMOTE_ACCESS_ENABLED`. They are not part of sync GA. Turning the flag on
in production needs every box below, at the exact commit, plus an owner decision on
[#101](https://github.com/bestagentkits/ak-vault/issues/101):

- [ ] ADR 0002 accepted by the owner, and REVIEW.md and AGENTS.md carry its
      exception scopes.
- [ ] Go and TypeScript reproduce `seal-key.json`, `sealed-op.json`, `name-tag.json`,
      `enroll-codes.json`, `profile.json` and `relay-frames.json`, including every
      negative case ([spec §3.6–§3.8, §5.1, §9.7](../protocol/v1/spec.md#36-seal-key-and-sealed-operations)).
- [ ] Relay: Worker tests for the closed frame set and close codes, signed `hello` and
      `result`, `reauth` before expiry, revocation and membership checked before each
      call (a device removed mid-connection gets no further call), a replaced
      connection, in-flight and connection caps, and dropped late results.
- [ ] MCP: Worker tests for token audience and claims (`<aud>/mcp` only, refused on
      `/v1`), grant revocation by `sid`, scope-to-tool mapping, 2026-07-28 and
      stateless 2025-11-25 handshakes (no `Mcp-Session-Id`), protected-resource
      metadata, rate limits, `no_device_online`, `device_timeout` and sealing with
      `sealed_queue_full`; sealing refused for a reader account and while
      `rekey_required` is set; another account's sealed operations never served.
- [ ] Dashboard: `/app` served as static assets under a CSP with `script-src 'self'`,
      SRI and no third-party code; `browser` session refused on genesis, membership,
      recovery, seal-key PUT and the sealed queue; enrollment needs SAS approval from
      an existing owner device.
- [ ] Disclosure scan rerun with remote access on: planted values and names sent
      through MCP set, relayed results and `run` output are absent from the Durable
      Object dump, Worker logs, live tail and errors (scenario 15 and
      [data classification](./data-classification.md#transits-worker-memory-never-stored-or-logged-remote-access-only)).
- [ ] Red-team scenarios 16–21 executed and scenario 13 rerun with synced profiles
      (`meta.profile` provenance) and MCP-originated text as the hostile input.
      Scenario 13 part: done on 2026-10-27, with hostile synced profiles, synced
      policy and MCP relay arguments as input
      ([red-team evidence](./red-team-evidence.md#scenario-13-hostile-policy-and-profile-text)).
      Scenarios 16–21: open.
- [ ] The D7 boundary (plaintext transits Worker memory) is stated on the MCP consent
      screen and in the vault guide, matching the
      [threat model](./threat-model.md#explicit-limitations).

Staging status (2026-10-20): the live staging run passed part of the MCP and dashboard
header checks, and no box above is ticked, because each box covers more than the live
checks reached. Live passes: the MCP challenge, the path-suffixed protected-resource
metadata, the origin-level PRM path, the stateless POST-only `/mcp`, the audience
refusals of forged tokens, and the `/app` CSP, isolation headers and SRI. Still open
on staging: the ak-web authorization-server checks, the signed-in dashboard and MCP
tool flows, the sync-token and MCP-token audience checks, the revoked-client step, and
scenarios 16 to 21. These wait on ak-web's OAuth configuration and a signed-in staging
test account. Details are in the
[red-team evidence](./red-team-evidence.md#remote-access-staging-run-2026-10-20).

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

**Residual risk, for the reviewer to weigh.** The integration with ak-web
staging's real issuer and JWKS, the delivery of its revocation webhook and the
Cloudflare edge are verified by configuration and by the lab Worker rehearsal
([#54](https://github.com/bestagentkits/ak-vault/pull/54),
[rehearsal log](../operations/rehearsal-2026-10.md)), not by authenticated staging
traffic. Platform logs, traces and analytics were scanned with seeded traffic on a
lab Worker instead (disclosure-scan gate above). Staging trusts ak-web staging's
issuer and JWKS; keeping staging's signing keys separate from production's is
ak-web's responsibility. Confirmed on 2026-10-16 that the two JWKS share no key
material: both published JWKS were fetched and every key compared by its
`(crv, x, y)` coordinates, not only its `kid`; each endpoint published one key and
none was shared
([evidence on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6213027838)).
This is a point-in-time check of the keys published that day; keeping keys separate
across later rotations stays ak-web's responsibility.

## Owner waivers

Recorded on #8 by the owner. A waiver accepts a stated risk; it is not evidence and
does not satisfy the [review](#review-by-the-owner).

| Date | Waiver | Record |
|---|---|---|
| 2026-10-16 | Live `wrangler tail` shows `AKV-Proof` and `AKV-Webhook-Signature` values to account members with tail access. Accepted as account-operator access: proofs are single-use, bound to token hash, method, URL and body within a ±60 s window; webhook signatures cover one timestamped body with a single-use `event_id`. Complement: restrict Workers Tail permission on production. The header rename stays open as hardening. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248), [#61](https://github.com/bestagentkits/ak-vault/issues/61#issuecomment-6209133562); scan evidence [#62](https://github.com/bestagentkits/ak-vault/pull/62) |
| 2026-10-16 | The Docker two-device e2e replaces the staging two-device round trip and the staging soak; no authenticated staging session is used. Residual risk is stated under [staging soak](#staging-soak). | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6207406980) |
| 2026-10-16 | The external-review gate is waived for enabling `VAULT_SYNC_ENABLED=true` on the production Worker. The external review stays open on #8. **Superseded on 2026-10-27:** no external or independent review is a GA gate; the review gate is the [review by the owner](#review-by-the-owner), accepted 2026-10-16. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248); superseded by [#99](https://github.com/bestagentkits/ak-vault/issues/99#issuecomment-6435169217) |
| 2026-10-16 | Production sync is fully live: ak-web production mints vault tokens together with the Worker flag, so any logged-in user running the preview `ak secrets sync` commands can sync to production before the external review. Docs say it is pre-release, not externally reviewed and not yet recommended for production credentials. This supersedes the earlier statement that minting stays off. The external review it refers to is no longer a gate (row above). | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209425010) |
| 2026-10-16 | The review gate is a review by the owner, not an independent third-party review: the owner posts the result on #8 personally, and agents never post, attest or tick it. The gate stays open until then. Residual risk: no reviewer outside the project ([review by the owner](#review-by-the-owner)). | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235) |
| 2026-10-16 | The owner told an agent in chat to tick the review gate as accepted by the owner, and the agent recorded it on #8 on the owner's behalf. This supersedes the previous row's rule that the owner posts the result personally and agents never tick it. No written findings; the open items listed in the record stay open. Still not an independent third-party review. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397) |
| 2026-10-16 | API-key sign-ins may use sync through a revocable device session (opt-in per API key, at most 5 devices per key, email notice on enrolment). Recorded in the ADR [amendment](../adr/0001-opt-in-zero-knowledge-sync.md#amendment-api-key-bootstrapped-device-sessions); the Worker refuses the recovery path for these sessions. Production rollout only through the gated Deploy workflow with owner approval; the ak-web endpoint and the CLI enrolment ship separately. Not a review. | [#74](https://github.com/bestagentkits/ak-vault/issues/74) |
| 2026-10-16 | ADR 0001 is accepted with restore reconciliation still an open item, so the ADR gate no longer requires its open items resolved. The staging backup/restore and staging cost gates are not waived. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210567772) |
| 2026-10-16 | The owner approves the deploy that enables production sync while the shared-Cloudflare-token bootstrap exception stays an open item ([production deploy control](#production-deploy-control)). Superseded by the next row. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209176887) |
| 2026-10-16 | Staging keeps a Cloudflare token that can reach the production Worker, because Cloudflare cannot scope a Workers token to one script. The exception closes under owner code review of `.github/` and `worker/wrangler.jsonc`, in effect since 2026-10-16 ([production deploy control](#production-deploy-control)). Residual risk: agents act as the owner's GitHub account. | [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210230956) |

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
  so neither accepts the other's tokens. ak-web production's `VAULT_*` environment
  values, which configure its vault-token issuing, were set by the owner personally
  in DXUP, ak-web's deploy platform ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210567772));
  this repository holds none of them. Production CI deploys with its own
  Cloudflare token. Staging's token can still reach the production Worker; the
  owner accepted that under code-owner review (below), not a separate credential.
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
  2026-10-13, although the record says staging keeps its own secret; the later
  decision below supersedes that claim. The next production
  deploy shows the new token can deploy; that it lacks Workers Tail rests on the
  owner's record. The rest of the second exception closed by owner decision
  ([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210230956)) under a mitigation instead
  of a separate credential: Cloudflare cannot scope a Workers token to one script,
  so the `staging` secret, which deploys from `main` without a reviewer, can still
  reach the production Worker, and the operator's emergency kill-switch token is
  that same token. The mitigation is that `.github/` and `worker/wrangler.jsonc` are
  code-owned by the owner ([#67](https://github.com/bestagentkits/ak-vault/pull/67))
  and the `main` ruleset requires code-owner review, with the repository admin role
  allowed to bypass in pull-request mode only. Both conditions were met on
  2026-10-16 (#67 merged; the ruleset requires code-owner review); check the
  ruleset rather than assuming. Maintainers then cannot change `.github/` or `worker/wrangler.jsonc`
  without the owner's review. The deploy job also runs `wrangler` from
  dependencies resolved by the `package.json` files and the lockfile, which are not
  code-owned, so a dependency change can still reach the deploy token without the
  owner's review
  ([#68](https://github.com/bestagentkits/ak-vault/issues/68)). **Residual risk:** agents act as the owner's
  GitHub account, so for agent PRs the control rests on the
  [AGENTS.md](../../AGENTS.md) rules (green CI, agents never approve production).
  Worker secrets stay separate per environment.
- GitHub secret scanning, push protection and private vulnerability reporting stay
  enabled on the repository (enabled 2026-10-13; re-check the security settings
  before GA rather than assuming), and no token, key or personal data is committed.

## Review by the owner

By owner decision on 2026-10-16 ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)) the reviewer is the project
owner, who reviews the ADR, spec, vectors, Worker auth path and these gates. **This is
not an independent third-party review**: the owner directs the agents that
implemented the protocol, and no reviewer outside the project has signed off.

**Accepted by the owner on 2026-10-16.** At 16:40 (Asia/Saigon) the owner told an
agent in chat to tick this gate, and the agent recorded it on #8 on the owner's
behalf ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)). The owner recorded no written findings, no result
level and no reviewed scope or commit; the record lists what the owner was given. Agents act
through the owner's GitHub account, so the record is the agent's account of the
owner's instruction, not a result posted by the owner; this supersedes the earlier
rule that the owner posts the result personally. The open items listed in the record stay open. Sync stays pre-release and not GA
until every remaining gate on this page is met at the release commit.

This replaces the earlier requirement of an independent reviewer with cryptographic
expertise who did not implement the protocol. By owner decision on 2026-10-27
(relayed in chat and recorded by an agent on [#99](https://github.com/bestagentkits/ak-vault/issues/99#issuecomment-6435169217)
and [#8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6435169673)), an independent third-party review is
**not** a GA gate. Residual risk: no reviewer outside the project.

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

Remote access (staging, [ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md)):

16. Forged, replayed, late or other-device relay results; unknown frame types,
    oversize or binary frames.
17. Revoked device or MCP grant mid-connection; `reauth` after expiry or for another
    account or device.
18. Prompt-injected MCP client tries to reveal a value, call a tool outside its
    scopes, or `run` without a pinned `exec` grant.
19. Server substitutes the seal key, replays or reorders sealed operations, or
    serves one after its TTL.
20. Browser session tries genesis, membership, recovery, seal-key publication and the
    sealed queue; script injection blocked by the dashboard CSP.
21. Server returns lookup hits for the wrong item or a stale epoch; malformed or
    substituted enrollment codes.

Scenario 13 is rerun once profiles sync: a hostile synced profile field, including
one forged in another device's name, must not widen a grant, run a command or pass
the provenance check.
