# Release gates

The go/no-go contract for issue
[#8](https://github.com/bestagentkits/ak-vault/issues/8). Production sync carries
real credentials only after every gate below is satisfied **at the exact commit
being released** and the evidence is linked on #8. A checked box without linked
evidence does not count.

## P0 gates

- [ ] [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md) approved by the owner,
      including resolution of its open items.
- [ ] Go and TypeScript reproduce every vector in `protocol/v1/vectors/` byte for
      byte, including every rejection vector (tamper, wrong AAD, duplicate nonce,
      invalid signature, injected recipient, replay, rollback, unsupported version).
- [ ] Worker integration suite in `worker/test/` green: CAS and preserved `409`
      branches, tombstones, idempotency, cross-tenant denial, wrong `iss`/`aud`/`alg`,
      replayed proof, revoked device and session, stale membership, injected
      recipient, reader and machine write denial.
- [ ] Disclosure scan: a full Durable Object dump, Worker logs, traces, metrics and
      every error response from a run seeded with known plaintext values and names
      contain none of them ([data classification](./data-classification.md)).
- [ ] Revocation: a revoked session or device is refused on its next request even
      with an unexpired token; revocation-registry failure returns `503`.
- [ ] Sync-off regression (agentkit#2298): zero HTTP requests; vault v1 behavior
      unchanged.
- [ ] `resolve` keeps working with the Worker unreachable (agentkit#2298).
- [ ] Every scenario in the [red-team list](#red-team-scenarios) executed, findings
      triaged on GitHub.
- [ ] Staging soak complete (below).
- [ ] Backup/restore and rollback rehearsed on staging using the
      [runbooks](../operations/runbooks.md).
- [ ] Cost measured on staging and compared with the
      [cost model](../operations/cost-model.md).
- [ ] External review signed off (below).

## Staging soak

Staging runs on `vault-staging.agentkit.best` against ak-web's staging issuer
(test-only keys). The soak uses at least two enrolled devices with active sync
services, exercises the red-team scenarios and the runbook rehearsals, and records
error rates and latency. The soak duration is an owner decision recorded on #8.

## Feature flag and kill switch

`VAULT_SYNC_ENABLED` gates the sync API. It stays `false` in production until this
checklist is complete, and returning it to `false` is the first incident response
step ([runbooks](../operations/runbooks.md#kill-switch)). Landing page and health
endpoints are not affected by the flag.

## Production deploy control

- Production deploys run only through a GitHub Environment with a required human
  reviewer; an agent cannot approve its own deploy.
- Production and staging use separate Cloudflare credentials and separate Worker
  secrets. The Worker never receives ak-web's CLI HS256 signing key.
- GitHub secret scanning, push protection and private vulnerability reporting stay
  enabled on the repository (enabled 2026-10-13; re-check the security settings
  before GA rather than assuming), and no token, key or personal data is committed.

## External review

An independent reviewer with cryptographic expertise, who did not implement the
protocol, reviews the ADR, spec, vectors, Worker auth path and these gates. The
reviewer's sign-off, scope and the reviewed commit are recorded on #8. This gate
cannot be self-attested by the owner's agents or closed by a checklist alone; until
it exists, #8 stays `blocked` and sync is not GA.

## Performance targets

| Target | Owner | Conditions |
|---|---|---|
| `resolve` warm-cache p95 overhead < 50 ms, never blocked by the Worker | AgentKit client (agentkit#2298) | Defined test rig and workload, recorded with the result |
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
