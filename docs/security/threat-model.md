# Threat model: ak-vault sync

Scope: the opt-in sync protocol ([spec](../protocol/v1/spec.md)), the Worker and
per-vault Durable Object in `worker/`, and the client obligations the spec places on
AgentKit (agentkit#2298/#2299). Decisions and rationale are in
[ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md). What the server can see is in
[data classification](./data-classification.md).

## Assets

| Asset | Where it lives |
|---|---|
| Secret values, names, descriptions, tags, profiles | Plaintext only on member devices; ciphertext on the server |
| Vault keys `VK[e]` | Member devices; wrapped copies on the server |
| Device signing and key-agreement private keys | Each device only |
| Password and recovery key | The user only |
| Owner trust anchor and witnessed checkpoints | Each device; inside the encrypted recovery bundle |
| Portable policy and encrypted audit | Encrypted items / audit stream |
| Vault-resource tokens and session/device IDs | ak-web issuer, client, Worker in transit |
| Worker operational secrets (webhook HMAC key) | Worker secret store only |
| Availability of local `resolve` | Local client; must not depend on this service |

## Actors

| Actor | Assumed capability |
|---|---|
| Malicious or compromised server (Worker, DO, Cloudflare account) | Read/alter/drop/replay anything stored or in transit through the Worker; serve different views to different devices |
| Malicious member (shared vault) | Holds current vault key and a valid device; may later be removed |
| Stolen or lost device | Attacker holds device keys and any cached plaintext |
| Stolen token | Attacker holds a vault JWT, without the device private key |
| Compromised CI runner | Code execution inside a job holding a machine identity |
| Forked pull request | Untrusted code in CI on this repo or a consumer repo |
| Prompt-injected agent or hostile shared profile | Controls text an agent reads; may call local `ak` commands |
| Network attacker | On-path between client and edge |

## Trust boundaries

1. **Device ↔ server.** Everything crossing it is ciphertext or signed, except the
   metadata listed in [data classification](./data-classification.md).
2. **ak-web issuer ↔ Worker.** The Worker trusts only ES256 tokens from the
   configured issuer and the HMAC-authenticated revocation webhook; it never holds a
   key that can mint CLI sessions.
3. **Owner devices ↔ other devices.** Only owner-role devices author membership.
4. **Local client ↔ agent / child process.** Device-local grants and operator
   approval gate release; `run` crosses this boundary with plaintext by design.
5. **Repository / CI ↔ production.** Production deploy is gated by a protected
   GitHub Environment reviewer; forked PRs get no secrets.

## Invariants

- The server never receives plaintext values, names, profiles, policy or audit, and
  never holds a key that decrypts them.
- No write is accepted unless its base revision matches (CAS); no write silently
  overwrites another.
- A write below a tombstone never becomes live.
- No recipient, device or member exists unless an owner-signed event added it, and
  no device uses a vault-key wrap that event's signed `wraps_digest` does not cover.
- No record by a removed device is accepted at a change-log position above its
  signed removal fence, and no client accepts a log prefix at or below a removal
  fence that differs from the one the removal signed.
- A client never accepts state older than, or forked from, a checkpoint it witnessed.
- Unknown version, algorithm, event type, key epoch or signature fails closed.
- A request is served only if token, proof, live revocation check and membership all
  pass; revocation lookup failure is a refusal.
- Synced data can narrow a grant, never create or widen one.
- Sync-off makes zero network requests; `resolve` never waits on the network.

## Threats, mitigations and tests

Vector paths are under `protocol/v1/vectors/`; Worker integration tests are under
`worker/test/`. The categories below are what those suites must cover; the
directories themselves are the authority for exact file names.

| # | Threat | Actor | Mitigation | Test evidence |
|---|---|---|---|---|
| S1 | Forged record or membership event | Server | Ed25519 signatures with domain-separated contexts ([spec §2, §4, §5](../protocol/v1/spec.md#4-membership-log-owner-signed-hash-chained)) | Vectors: invalid signature, wrong context |
| S2 | Injected recipient / added device | Server, member | Owner-signed hash-chained membership; every wrap belongs to the set an owner-signed event commits to with `wraps_digest`; no separate wrap upload ([spec §3.3, §4](../protocol/v1/spec.md#33-device-key-wrap-x25519-xc20p)) | Vectors: injected recipient, non-owner author, `device-add-wraps.json`; `worker/test/` injected-recipient rejection, digest mismatch; `authorization.test.ts` "wraps are accepted only inside a signed event" (`POST /wraps` → 404) |
| S6 | Key substitution for a joining device: the server swaps the vault key wrapped to a new device for one it knows, then reads what the device writes | Server | The joiner verifies the wrap set against the signed `wraps_digest` before unwrapping (`verifyDeviceWraps`); the full set is served per event to members, including wraps of devices removed since | Vectors: `device-add-wraps.json` injected key, dropped wrap, missing current epoch; `worker/test/signed-wrap-sets.test.ts` |
| S7 | A removed device, colluding with the server, appends records after its removal, or places them at or below the fence in place of honest records | Server + removed device | Every removal signs `log_fence` and `log_head`, the change-log head chain at the fence computed by the remover; contiguous change-log positions; `verifyLoggedRecord` refuses a record by a removed author above the fence; `verifyChangeLog` refuses a prefix whose head differs from a signed fence (substituted, dropped or reordered records, or a changed `conflict_id`), a resume past a fence without the head the client kept there, and a log behind a fence; clients derive kind, revision and resolution from their own replay, never from served feed fields; the Worker refuses records by non-current authors, stale or future fences and a `log_head` that does not match the stored log ([spec §5](../protocol/v1/spec.md#5-records-revisions-conflicts-and-tombstones)) | Vectors: `removal-fence.json` (records and log replay, including substitution at and below the fence); `worker/test/removal-fence-and-recovery-rotation.test.ts` stale/ahead fence, relayed write by a removed author; `worker/test/removal-fence-binds-log.test.ts` signed head, wrong head refused, substitution detected by a device enrolled after the removal, head backfill |
| S8 | A leaked or superseded recovery key enrolls a device | Holder of an old recovery key or bundle | Owner-signed `recovery_rotate`; only the current recovery key may author, and only `device_add`; the resealed bundle lands atomically with the event; a bundle sealed before the latest rotation is refused; recovering devices check the bundle key against the chain ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)) | Vectors: `membership.json` rotation cases, `recovery-bundle.json` rotated key, `device-add-wraps.json` recovery set without the current epoch; `worker/test/removal-fence-and-recovery-rotation.test.ts` rotation, stale-sealer refusal and stale-bundle enrollment refusal |
| S3 | Token replay or theft without device key | Stolen token, network | Device-signed `AKV-Proof` bound to method, URL, token hash and body hash; single-use `jti` window | `worker/test/` replayed proof, missing proof, wrong `did` |
| S4 | Audience/issuer/alg confusion | Network, attacker | Exact `iss`/`aud`, `alg` = ES256 only, `kid` must match JWKS; production and staging use distinct audiences and distinct issuers, each with keys fetched from its own JWKS URL (separate signing keys are ak-web's responsibility) | `worker/test/` wrong `aud`/`iss`/`alg`/`kid`, expired, `nbf` in future; `auth-token.test.ts` cross-environment refusal using the deployed audiences, and deployed issuer/JWKS URLs with no inline keys |
| S5 | Revoked session/device keeps access | Stolen device/token | Live revocation registry per request; fail closed on registry error | `worker/test/` revoked `sid`, revoked `did`, minimum-`iat`, registry failure → 503 |
| T1 | Ciphertext or AAD tampering | Server | AEAD with AAD rebuilt from authenticated context | Vectors: tamper, wrong AAD, wrong key epoch |
| T2 | Lost update via concurrent writes | Any two devices | CAS + `409` + preserved conflict branch | `worker/test/` concurrent writers, conflict preservation, resolution |
| T3 | Resurrection of deleted/revoked secret | Stale offline device | Tombstones; stale writes refused and not preserved | `worker/test/` tombstone replay, offline rejoin |
| T4 | Duplicate side effects on retry | Network | Idempotency keys; mismatched body → `422` | `worker/test/` duplicate request, idempotency mismatch |
| T5 | Rollback or fork of vault state | Server | Client-signed checkpoints; rollback/fork alarm | Vectors: rollback, fork; `worker/test/` stale membership |
| T6 | Nonce reuse | Buggy client | Random 24-byte nonces from the platform CSPRNG; only vectors inject fixed nonces | Vectors: duplicate nonce |
| T7 | Weak password parameters downgrade | Server | Argon2id minimums enforced by verifiers; re-wrap upgrade | Vectors: below-minimum parameters |
| R1 | Undetected audit drop/reorder, or audit entries forged by a removed device | Server, removed device | Hash-chained encrypted audit + audit checkpoints; a per-epoch audit key derived from `VK[e]`, so a removed device cannot write entries at an epoch it never held; epochs never decrease along the chain; the Worker accepts only the current epoch; the rekeying device MUST append at the new epoch; verifiers require the current epoch's key ([spec §7](../protocol/v1/spec.md#7-encrypted-audit-stream)) | Vectors: `audit.json` reorder/drop/relabel across a rekey, refusal without the current key; `worker/test/checkpoints-audit.test.ts` |
| I1 | Plaintext or name in logs, errors, dumps, metrics | Server operator, log reader | Names/values only inside ciphertext; stable error codes never echo bodies | `worker/test/` full DO dump and log scan for planted plaintext and names |
| I2 | Cross-tenant read | Malicious account | Scope ∩ membership; DO per vault | `worker/test/` cross-vault access |
| I3 | Removed member reads new material | Malicious member | `device_remove`/`member_remove` → `rekey_required` → rekey; `needs_rotate`; new devices receive keys only through signed wrap sets | `worker/test/` writes refused while rekey required; vectors: removed recipient |
| D1 | Server outage blocks local use | Server, network | `resolve` reads local backend only | agentkit#2298 regression (owned there) |
| D2 | Abuse / quota exhaustion | Any client | Rate limits and quotas published by `/v1/meta`; membership quotas never block the rekey a removal requires, nor recovery enrollment | `worker/test/` rate-limit and quota responses; `vault-storage-limits.test.ts` boundary cases |
| E1 | Reader or machine identity writes | Member, CI | Role and device kind enforced read-only | `worker/test/` reader write denied, machine write denied |
| E2 | Synced policy or profile elevates a grant | Hostile profile, injected agent | Policy is a maximum; profile text is untrusted data ([spec §8](../protocol/v1/spec.md#8-portable-policy-restrictive-only)) | agentkit#2299 / #7 negative tests (owned client-side) |
| E3 | Unsupported version accepted | Server, attacker | Closed identifier sets; fail closed | Vectors: unsupported version, unknown algorithm |
| C1 | Forked PR reaches secrets or deploys | Forked PR | No secrets to fork workflows; production Environment reviewer | Workflow config in `.github/`; red-team scenario in [release gates](./release-gates.md) |
| I4 | Offline guessing of the recovery bundle; recovery identity reading beyond its need | Holder of an owner-account token (stolen session) | Bundle and the read-only membership log are released only to the owner account with a device-key proof; every other route refuses the recovery identity; removed device IDs refused; Argon2id minimums and a 256-bit recovery key; owner revokes sessions after a loss | `worker/test/recovery-fetch.test.ts` wrong account, removed device, key/did mismatch; `worker/test/removal-fence-and-recovery-rotation.test.ts` route refusals |
| C2 | Compromised CI runner reads beyond scope | CI runner | Dedicated CI vault, machine read-only identity, revocable; incomplete while a machine device on the owner account can take the recovery-identity path into other vaults of that account ([#42](https://github.com/bestagentkits/ak-vault/issues/42); planned fix [ak-web#578](https://github.com/bestagentkits/ak-web/issues/578), required before #6 ships) | #6 tests (post-MVP); `red-team-tenant-and-role-isolation.test.ts` pins the current #42 behaviour |

## Explicit limitations

These are accepted and must be stated wherever the guarantees are described:

- **Withholding never-seen updates.** A malicious server can freeze a new or
  long-offline device at any state it has not yet witnessed. Detection needs a
  second channel (another device's checkpoint, SAS transfer, or the recovery
  bundle). No transparency log or gossip in v1.
- **Vault-wide key.** Any member device can decrypt every item in the vault. Roles
  do not create per-secret read boundaries.
- **No clawback.** Values already decrypted by a removed member or a lost device
  remain exposed. Rekey protects only new material; affected items become
  `needs-rotate` and must be rotated at the provider.
- **`run` releases plaintext.** `run --env` hands the value to a child process;
  from there the v1 limits (post-inject exposure, transcripts, memory) apply.
- **Compromised local client.** Malware running as the user, or a modified `ak`,
  sees plaintext and keys. The protocol does not defend the endpoint.
- **Recovery bundle ciphertext.** Anyone holding a live owner-account session can
  download the encrypted recovery bundle and guess the password offline. A weak
  password is the residual exposure; revoking the owner's sessions after a loss
  closes the path. This includes **machine identities on the owner account**: a
  machine or CI device signed in to the owner account can take the
  recovery-identity path on any other vault of that account in which it is not
  enrolled, fetching that vault's encrypted bundle and read-only membership log.
  The owner decided to fix this rather than accept it
  ([#42](https://github.com/bestagentkits/ak-vault/issues/42)). Planned, not yet
  built: ak-web will mark machine and CI sessions with a vault-token claim
  ([ak-web#578](https://github.com/bestagentkits/ak-web/issues/578)) and the Worker
  will refuse the recovery-identity path for those sessions, failing closed on an
  unknown claim value. The fix is a prerequisite for shipping machine identities
  ([#6](https://github.com/bestagentkits/ak-vault/issues/6)). Until it lands, this
  stays a stated limitation.
- **Audit entries are not signed per author.** Any device that held `VK[e]` can
  write audit entries at epoch `e`, including a device removed later. With a
  colluding server it can keep doing so after the rekey until the first entry at a
  later epoch is in the chain; the rekeying device MUST append one right away
  (spec §7), which closes the window. Entries at an epoch older than the reader's
  minimum epoch, whose key it lacks, are opaque: chained and epoch-checked, but
  their content is unverified. A reader without the current epoch's key is refused.
  A reader with it can still receive a chain the server truncated before the first
  entry at its minimum epoch, which is entirely opaque and passes; only a witnessed
  audit checkpoint bounds that, and clients must not present it as verified.
- **The removal fence binds the log as its remover verified it.** A device that
  first reads the log after a removal detects any record substituted, dropped or
  reordered, or any `conflict_id` changed, at or below the fence. The fence cannot vouch for what the remover
  itself was shown: records the removed device got accepted before its removal
  stay valid, including any written after it was compromised but before it was
  removed. Positions above the latest fence are covered only by checkpoints and
  the withholding limitation above. A client that passed a fence before it
  learned of the removal must compare a head it kept or replay the log from the
  start.
- **Live tail shows proofs and webhook signatures.** Account members with Workers
  Tail permission see `AKV-Proof` and `AKV-Webhook-Signature` values in
  `wrangler tail`, along with URLs, client IPs and other headers; only header names
  the platform recognises (`Authorization`, `Idempotency-Key`, `AKV-Device-Key`) are
  redacted. Accepted by owner waiver as account-operator access
  ([data classification](./data-classification.md#handling-rules),
  [#61](https://github.com/bestagentkits/ak-vault/issues/61)).
- **Production sync runs before the external review.** By owner decision on
  [#8](https://github.com/bestagentkits/ak-vault/issues/8) (2026-10-16) production
  sync is live, with ak-web minting production vault tokens, before the
  independent cryptographic review and with other release gates open
  ([release gates](./release-gates.md#owner-waivers)). It is pre-release and not
  yet recommended for production credentials. The latest released client
  (`v3.0.0-beta.30`) also predates the removal-fence client: its removals are
  refused and it does not check change-log contents against removal fences, so the
  fence guarantee above holds only for clients that include it
  ([agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469)).
- **A live device can stall its own removal.** The fence must equal the current
  log head, so a device that keeps writing keeps the fence stale. Revoke it first;
  live revocation stops its requests.
- **Records are not checked against role history.** `verifyLoggedRecord` accepts
  records by any current device; read-only roles and machine devices are enforced
  by the Worker only
  ([#22](https://github.com/bestagentkits/ak-vault/issues/22)).
- **Recovery bundle contents are not server-checked.** The server cannot open the
  bundle. It refuses a `PUT /recovery` whose declared sealing position predates the
  latest `recovery_rotate`, which stops an honest but stale owner device from
  replacing a fresh bundle; it cannot stop an owner device that declares a current
  position yet seals the wrong key. Recovering devices detect the mismatch
  (`forbidden`) instead of trusting it.
- **A stopped removal can strand the recovery bundle.** Every device-adding
  event, recovery included, must deliver the current key epoch, so a bundle sealed
  before the latest rekey cannot enroll a device. A removal whose author stopped
  after its rekey and before it resealed the bundle therefore makes the bundle
  unusable until a device that still syncs reseals it; if no such device remains,
  that bundle cannot recover the vault
  ([#36](https://github.com/bestagentkits/ak-vault/issues/36)).
- **Wraps of older epochs are optional.** A device enrolled without a wrap for an
  older epoch cannot read items still at that epoch; they are rotated forward by a
  device that can, never delivered by an unsigned late wrap.
- **Metadata.** Item counts, sizes, timing, revisions, membership and device
  public keys are visible to the server
  ([data classification](./data-classification.md)).
