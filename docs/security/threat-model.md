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
- No recipient, device or member exists unless an owner-signed event added it.
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
| S2 | Injected recipient / added device | Server, member | Owner-signed hash-chained membership; wraps to non-members rejected | Vectors: injected recipient, non-owner author; `worker/test/` injected-recipient rejection |
| S3 | Token replay or theft without device key | Stolen token, network | Device-signed `AKV-Proof` bound to method, URL, token hash and body hash; single-use `jti` window | `worker/test/` replayed proof, missing proof, wrong `did` |
| S4 | Audience/issuer/alg confusion | Network, attacker | Exact `iss`/`aud`, `alg` = ES256 only, `kid` must match JWKS | `worker/test/` wrong `aud`/`iss`/`alg`/`kid`, expired, `nbf` in future |
| S5 | Revoked session/device keeps access | Stolen device/token | Live revocation registry per request; fail closed on registry error | `worker/test/` revoked `sid`, revoked `did`, minimum-`iat`, registry failure → 503 |
| T1 | Ciphertext or AAD tampering | Server | AEAD with AAD rebuilt from authenticated context | Vectors: tamper, wrong AAD, wrong key epoch |
| T2 | Lost update via concurrent writes | Any two devices | CAS + `409` + preserved conflict branch | `worker/test/` concurrent writers, conflict preservation, resolution |
| T3 | Resurrection of deleted/revoked secret | Stale offline device | Tombstones; stale writes refused and not preserved | `worker/test/` tombstone replay, offline rejoin |
| T4 | Duplicate side effects on retry | Network | Idempotency keys; mismatched body → `422` | `worker/test/` duplicate request, idempotency mismatch |
| T5 | Rollback or fork of vault state | Server | Client-signed checkpoints; rollback/fork alarm | Vectors: rollback, fork; `worker/test/` stale membership |
| T6 | Nonce reuse | Buggy client | Random 24-byte nonces from the platform CSPRNG; only vectors inject fixed nonces | Vectors: duplicate nonce |
| T7 | Weak password parameters downgrade | Server | Argon2id minimums enforced by verifiers; re-wrap upgrade | Vectors: below-minimum parameters |
| R1 | Undetected audit drop/reorder | Server | Hash-chained encrypted audit + audit checkpoints ([spec §7](../protocol/v1/spec.md#7-encrypted-audit-stream)) | Vectors: audit reorder/drop |
| I1 | Plaintext or name in logs, errors, dumps, metrics | Server operator, log reader | Names/values only inside ciphertext; stable error codes never echo bodies | `worker/test/` full DO dump and log scan for planted plaintext and names |
| I2 | Cross-tenant read | Malicious account | Scope ∩ membership; DO per vault | `worker/test/` cross-vault access |
| I3 | Removed member reads new material | Malicious member | `device_remove`/`member_remove` → `rekey_required` → rekey; `needs_rotate` | `worker/test/` writes refused while rekey required; vectors: removed recipient |
| D1 | Server outage blocks local use | Server, network | `resolve` reads local backend only | agentkit#2298 regression (owned there) |
| D2 | Abuse / quota exhaustion | Any client | Rate limits and quotas published by `/v1/meta` | `worker/test/` rate-limit and quota responses |
| E1 | Reader or machine identity writes | Member, CI | Role and device kind enforced read-only | `worker/test/` reader write denied, machine write denied |
| E2 | Synced policy or profile elevates a grant | Hostile profile, injected agent | Policy is a maximum; profile text is untrusted data ([spec §8](../protocol/v1/spec.md#8-portable-policy-restrictive-only)) | agentkit#2299 / #7 negative tests (owned client-side) |
| E3 | Unsupported version accepted | Server, attacker | Closed identifier sets; fail closed | Vectors: unsupported version, unknown algorithm |
| C1 | Forked PR reaches secrets or deploys | Forked PR | No secrets to fork workflows; production Environment reviewer | Workflow config in `.github/`; red-team scenario in [release gates](./release-gates.md) |
| I4 | Offline guessing of the recovery bundle | Holder of an owner-account token (stolen session) | Bundle is released only to the owner account with a device-key proof; removed device IDs refused; Argon2id minimums and a 256-bit recovery key; owner revokes sessions after a loss | `worker/test/recovery-fetch.test.ts` wrong account, removed device, key/did mismatch |
| C2 | Compromised CI runner reads beyond scope | CI runner | Dedicated CI vault, machine read-only identity, revocable | #6 tests (post-MVP) |

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
  closes the path.
- **Metadata.** Item counts, sizes, timing, revisions, membership and device
  public keys are visible to the server
  ([data classification](./data-classification.md)).
