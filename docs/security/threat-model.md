# Threat model: ak-vault sync

Scope: the opt-in sync protocol ([spec](../protocol/v1/spec.md)), the Worker and
per-vault Durable Object in `worker/`, and the client obligations the spec places on
AgentKit (agentkit#2298/#2299). Decisions and rationale are in
[ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md); the browser device, relay and
remote MCP (staging only) are in [ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md).
What the server can see is in
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
| Worker operational secrets (webhook HMAC key; operator restore HMAC key, set only for a restore) | Worker secret store; the operator key also on the operator's machine for the restore |
| Availability of local `resolve` | Local client; must not depend on this service |
| Browser device keys and the dashboard's decrypted view | Page memory of the enrolled browser device at `/app` |
| Seal private keys `SealSK[e]` | Derived from `VK[e]` on member devices only; the server holds only `seal_pub[e]` |
| MCP grants and tokens | ak-web authorization server, the MCP client, the Worker's `/mcp` endpoint in transit |

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
| Remote MCP client (hosted agent), possibly prompt-injected | Holds an MCP grant within its scopes; controls tool arguments |
| Script injected into the dashboard (XSS, malicious dependency) | Runs in the browser device's page with its keys |

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
6. **Operator ↔ Worker.** The operator restore route (`POST /internal/v1/operator`)
   answers 404 unless `VAULT_OPERATOR_SECRET` is set for that environment; it is set
   only for a restore and deleted afterwards. Its holder can return one vault object
   to an earlier point. That is no more than the "malicious server" actor above
   already has, and it is detected the same way: only by devices that witnessed a
   newer checkpoint (T5).
7. **MCP client ↔ Worker ↔ relayed device.** An MCP call crosses the Worker, which
   relays it to an opted-in device or seals a write. Plaintext tool arguments and
   relayed metadata results are in Worker memory after TLS termination (ADR 0002 D7);
   the device applies its own grants, approvals and redaction and signs its answer.
8. **Browser device ↔ Worker.** The dashboard is a device: it decrypts in page
   memory, and its `browser` session kind is refused on genesis, membership,
   recovery, seal-key publication and the sealed queue
   ([spec §9](../protocol/v1/spec.md#9-transport-authentication-worker)).

## Invariants

- The server never stores plaintext values, names, profiles, policy or audit, and
  never holds a key that decrypts them. It never receives them either, except, while
  remote access is enabled, the plaintext in transit through Worker memory that
  ADR 0002 D7 names (an MCP set's `value`, relayed metadata results and redacted run
  output); that plaintext is never logged, stored or put into an error.
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
- A sealed operation becomes vault state only as a normal record signed by the
  device that drained it; no relayed result carries an item value except redacted
  `run` output.

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
| T5 | Rollback or fork of vault state, including a restore regrown past the witnessed position and an older policy revision re-served | Server | Client-signed checkpoints; rollback/fork alarm; `verifyChangeLog` refuses a log whose head differs from one the client kept, or that ends below it once the whole log is read; a replayed record is refused per item ([spec §5, §6](../protocol/v1/spec.md#6-checkpoints-anti-rollback)) | Vectors: `checkpoints.json` rollback, fork and the regrown view that passes the checkpoint comparison alone; `removal-fence.json` `restored_regrown_*`, `restored_log_behind_kept_head`; `records.json` `replayed_older_revision`; `red-team-replayed-policy.test.ts` / `red_team_replayed_policy_test.go`; `worker/test/` stale membership; [staging restore rehearsal](../operations/rehearsal-2026-10.md#staging-restore-2026-10-16) |
| T8 | Misuse of the operator restore route (forged, replayed or cross-environment restore, restoring the revocation registry, writes lost around a restore) | Network attacker, holder of a captured request, operator mistake | Off (404) without its secret; HMAC-SHA256 over a context-separated request carried in the body, not a header, so live tail does not show it; origin and ±60 s time bound; compare-and-swap on the vault's current bookmark (a replay is refused: on staging storage the bookmark stayed put without writes and every restore and undo checked moved it forward); one vault object per request, never the registry; every request to the vault refused from scheduling until the confirmed restart; platform errors never echoed. A restore by the secret holder is a rollback: detected only by devices that witnessed a newer checkpoint (T5), invisible to the others, and it can roll membership back to before a removal or rekey | `worker/test/operator-restore.test.ts`; [staging restore rehearsal](../operations/rehearsal-2026-10.md#staging-restore-2026-10-16) |
| T6 | Nonce reuse | Buggy client | Random 24-byte nonces from the platform CSPRNG; only vectors inject fixed nonces | Vectors: duplicate nonce |
| T7 | Weak password parameters downgrade | Server | Argon2id minimums enforced by verifiers; re-wrap upgrade | Vectors: below-minimum parameters |
| R1 | Undetected audit drop/reorder, or audit entries forged by a removed device | Server, removed device | Hash-chained encrypted audit + audit checkpoints; a per-epoch audit key derived from `VK[e]`, so a removed device cannot write entries at an epoch it never held; epochs never decrease along the chain; the Worker accepts only the current epoch; the rekeying device MUST append at the new epoch; verifiers require the current epoch's key ([spec §7](../protocol/v1/spec.md#7-encrypted-audit-stream)) | Vectors: `audit.json` reorder/drop/relabel across a rekey, refusal without the current key; `worker/test/checkpoints-audit.test.ts` |
| I1 | Plaintext or name in logs, errors, dumps, metrics | Server operator, log reader | Names/values only inside ciphertext; stable error codes never echo bodies | `worker/test/` full DO dump and log scan for planted plaintext and names |
| I2 | Cross-tenant read | Malicious account | Scope ∩ membership; DO per vault | `worker/test/` cross-vault access |
| I3 | Removed member reads new material | Malicious member | `device_remove`/`member_remove` → `rekey_required` → rekey; `needs_rotate`; new devices receive keys only through signed wrap sets | `worker/test/` writes refused while rekey required; vectors: removed recipient |
| D1 | Server outage blocks local use | Server, network | `resolve` reads local backend only | agentkit#2298 regression (owned there) |
| D2 | Abuse / quota exhaustion, including a stolen token used to exhaust its device's rate budget | Any client, stolen token | Rate limits and quotas published by `/v1/meta`; requests the vault's Durable Object refuses at authorization of an existing vault (for example no valid proof, not a member, wrong scope, role or session kind, malformed body or Idempotency-Key) count against a separate per-device refused budget (refusals in the stateless Worker, such as a bad token or a missing Idempotency-Key, and requests for a vault that does not exist write no counter), so only the holder of the device key spends the budget for authorized requests. Limits: the refused budget is shared with whoever presents the device's token, so during a flood the device's own refusals also answer `rate_limited`; each request the Durable Object refuses costs its authorization work (proof check, and event verification for membership appends); volumetric flooding is left to the platform; membership quotas never block the rekey a removal requires, nor recovery enrollment | `worker/test/` rate-limit and quota responses (`rate-limit.test.ts`: stolen-token flood leaves the device's budget whole); `vault-storage-limits.test.ts` boundary cases |
| E1 | Reader or machine identity writes | Member, CI | Role and device kind enforced read-only | `worker/test/` reader write denied, machine write denied |
| E2 | Synced policy or profile elevates a grant | Hostile profile, injected agent | Policy is a maximum; profile text is untrusted data; project IDs only narrow the device-local grant; a policy item does not open in another vault ([spec §8](../protocol/v1/spec.md#8-portable-policy-restrictive-only)). A policy names the items it governs by item ID inside its ciphertext; several policies combine by intersection and can only raise sensitivity; an unopenable record or malformed binding anywhere in the vault, a malformed governing policy, or a governing policy in an unresolved conflict refuses release rather than falling back to the local grant alone ([spec §8.1](../protocol/v1/spec.md#81-policy-binding)). Limits: a device that never received a policy is subject to the withholding limitation (T5); any vault member can edit or delete a policy, as it can read every item; a policy covers only the item IDs it lists (no vault-wide default, a re-created secret under a new ID is ungoverned); an unopenable record or malformed binding refuses every item of the vault (availability, not confidentiality) | Vectors: `policy.json` (including `foreign_project_ids_grant_nothing`), `policy-binding.json`, `item.json` `moved_to_other_vault`; red-team hostile policy tests; `vectors-policy-binding.test.ts` / `vectors_policy_binding_test.go` (binding only narrows); agentkit#2299 / #7 negative tests (owned client-side) |
| E3 | Unsupported version accepted | Server, attacker | Closed identifier sets; fail closed | Vectors: unsupported version, unknown algorithm |
| C1 | Forked PR reaches secrets or deploys | Forked PR | No secrets to fork workflows; production Environment reviewer | Workflow config in `.github/`; red-team scenario in [release gates](./release-gates.md) |
| I4 | Offline guessing of the recovery bundle; recovery identity reading beyond its need | Holder of an owner-account token (stolen session) | Bundle and the read-only membership log are released only to the owner account with a device-key proof; every other route refuses the recovery identity; removed device IDs refused; Argon2id minimums and a 256-bit recovery key; owner revokes sessions after a loss | `worker/test/recovery-fetch.test.ts` wrong account, removed device, key/did mismatch; `worker/test/removal-fence-and-recovery-rotation.test.ts` route refusals |
| C2 | Compromised CI runner reads beyond scope | CI runner | Dedicated CI vault, machine read-only identity, revocable; the Worker refuses the recovery-identity path for `session_kind` `machine` ([#42](https://github.com/bestagentkits/ak-vault/issues/42)); incomplete until ak-web marks machine sessions with the claim ([ak-web#578](https://github.com/bestagentkits/ak-web/issues/578), required before #6 ships) | #6 tests (post-MVP); `red-team-tenant-and-role-isolation.test.ts` (marked machine refused, unmarked token still admitted) |
| I5 | Stolen or leaked AgentKit API key used to sync ([#74](https://github.com/bestagentkits/ak-vault/issues/74)) | Holder of an API key | The key never mints vault tokens. Once [ak-web#583](https://github.com/bestagentkits/ak-web/issues/583) ships (it is open; no API-key sign-in gets a vault token today), it is exchanged for a revocable `api_key_device` session bound to a device key (ak-web). The Worker refuses that session on the recovery bundle, the membership read by a non-member and recovery enrollment, so the key alone cannot collect bundles for offline guessing. Joining an existing vault needs a `device_add` signed by an existing owner device; creating a new vault is allowed. Revoking the key revokes derived sessions through the revocation webhook. Per-key device cap (5), enrolment email notice and per-key opt-in are ak-web controls (ak-web#583). Residual: a leaked key with opt-in can create vaults and devices up to the cap, and an owner who approves an unknown device enrols it. Decision (owner-delegated, recorded by an agent on the owner's behalf on [#90](https://github.com/bestagentkits/ak-vault/issues/90); it answers [#74](https://github.com/bestagentkits/ak-vault/issues/74)): approved `api_key_device` devices keep member access to items but are refused all recovery operations (`GET /recovery`, `PUT /recovery`, recovery-key rotation), even with an owner role. That refusal is not implemented yet: until [#90](https://github.com/bestagentkits/ak-vault/issues/90) lands, an owner-role `api_key_device` device could read and replace the recovery bundle and rotate the recovery key. Revocation of derived sessions is an ak-web control; the Worker checks revoked `sid` per request | `worker/test/recovery-fetch.test.ts` "human email-OTP sessions only"; `worker/test/auth-token.test.ts` session kinds |
| X1 | Forged or replayed relayed result, or a result from another device | Network, another device, a Worker bug | `hello` and every `result` signed by the device key (`akv1/relay`, `akv1/relay-result`); `device_id` = token `did` and the upgrade key; one answer per `call_id`, late or unknown results dropped ([spec §9.7](../protocol/v1/spec.md#97-relay)) | Vectors: `relay-frames.json` bad signature, other device's signature; relay Worker tests |
| X2 | A revoked or removed device, or a revoked grant, keeps relaying or calling | Stolen device, removed device, revoked MCP client | Revocation and vault membership checked before every relayed call (`sid`, `did`, minimum `iat`; `did` still a current human device of the vault); `reauth` before token expiry or close 4401; MCP tokens live at most 600 s and `sid` = `grant_id` reuses the revocation webhook | Relay and MCP Worker tests: revoked `did` mid-connection, revoked grant |
| X3 | Prompt-injected MCP client exfiltrates values or escalates | Remote MCP client | No reveal tool; results never carry values except `run` output after device-side redaction; scopes map to tools (`vault-mcp:read`/`write`/`use`); the device applies its own grants, `run` needs a pinned `exec` grant and never prompts from the relay | Vectors: `relay-frames.json`; device-side tests (agentkit) |
| X4 | Tampered, replayed or cross-account sealed operation, or one applied twice | Storage reader, replay of queued data, another account's MCP client | AEAD with AAD over vault, ID, epoch, origin (including the requesting account) and time; sealing only for an `owner`/`editor` account with `vault-mcp:write` and never while `rekey_required` is set; queue served only to the requesting account's devices, which refuse another account; draining devices dedupe `sealed_id`, enforce TTL and time bounds, and write a normal signed record audited `sealed_applied` / `sealed_refused`. A live compromised Worker can still seal what it likes (limitation below) ([spec §3.6](../protocol/v1/spec.md#36-seal-key-and-sealed-operations)) | Vectors: `seal-key.json`; `sealed-op.json` tampered AAD, wrong epoch, and drain admission (`checkSealedDrain`): replayed `sealed_id` (also after its TTL), another account, expired and too-far-future `ts`; device drain tests (agentkit) |
| X5 | Substituted seal key, so a later reader of stored queue entries can open them | Storage or document substitution | Seal-key document signed by an owner device current at its `membership_seq`; devices holding `VK[e]` recompute `seal_pub[e]` and refuse a mismatch; the MCP handler seals only to the current-epoch document | Vectors: `seal-key.json` non-owner author, wrong `seal_pub`, untrusted anchor, forked or longer witnessed checkpoint |
| X6 | Name-tag lookup misleads a reader into acting on the wrong item | Server | Tags are unsigned hints: a reader decrypts and compares the name before acting; a tag must match the record's `key_epoch`; tombstones carry none ([spec §3.7](../protocol/v1/spec.md#37-name-tags-keyed-blind-index)) | Vectors: `name-tag.json`; lookup Worker tests |
| X7 | Browser session changes membership or reads recovery | XSS in `/app`, stolen browser token | `browser` session kind refused (`403`) on genesis, every membership POST, recovery bundle and identity routes, seal-key PUT and the sealed queue; strict CSP, SRI, no third-party code; sync token TTL 300 s | Worker tests: browser session refusals; CSP header test |
| X8 | Synced profile field forged in another device's name | Malicious member, server relaying old fields | Per-field provenance: changed fields carry the record author and time, unchanged fields keep prior provenance; violating fields dropped and audited `profile_provenance_invalid`; another device's field shown as `sync`; the own label is transitive and comes only from this device's own write history, so a field kept without a held base revision stays `sync` while carried, even through the device's own later records ([spec §5.1](../protocol/v1/spec.md#51-profile-layout)) | Vectors: `profile.json` cases and `chains` (`forged_without_prev_never_becomes_own`); `red-team-profile-provenance.test.ts` / `red_team_profile_provenance_test.go` |
| X9 | Malformed or substituted enrollment code joins the wrong device | Network, phishing | Closed key set, exact contexts, version and size checks; owner role and `human` kind required; SAS confirmation on approval ([spec §3.8](../protocol/v1/spec.md#38-enrollment-codes)) | Vectors: `enroll-codes.json` |
| X10 | Relay or MCP flood exhausts an account | MCP client, stolen token | Per-client and per-account MCP rate limits, per-device in-flight cap, per-account connection cap, sealed queue cap with `sealed_queue_full` ([spec §10](../protocol/v1/spec.md#10-errors-and-limits)) | Relay and MCP rate-limit tests |

| X12 | Dashboard history or restore used to bypass CAS, a tombstone, a removal fence or key rotation, or to reveal a value | Hostile server, concurrent device, XSS in `/app` | History is projected only from the log the browser verified (a gap, a forged record, a relabelled branch and a withheld entry are refused before any history shows); entries are metadata and never carry a payload. Restore and resolve write a new record under the current key epoch at the verified head by CAS, so a concurrent write becomes a preserved branch and the Worker still refuses a non-current epoch, a removed author or a pending rekey; a deletion, a deleted item, a branch, an unreadable revision, a value from before the item's latest deletion and a value a removed device wrote or could hold cannot be restored; resolving is refused while any open branch is a deletion or unreadable; both need an explicit confirmation. Limits: restore opens the old value in browser memory (the same trust as every head the dashboard opens, ADR 0002) and a script running in `/app` could therefore read it, which the strict CSP, SRI and Trusted Types are there to prevent; restoring an old credential does not make it valid at its provider; history older than 200 entries per item is in the signed log but not listed | `packages/vault-app/test/dashboard-history.test.ts`, `packages/vault-app/test/history.test.ts` |

Rows X1–X10 and X12 cover remote access (ADR 0002); their vectors and tests land with the
implementation, before the feature leaves staging.

## Explicit limitations

These are accepted and must be stated wherever the guarantees are described:

- **Withholding never-seen updates.** A malicious server can freeze a new or
  long-offline device at any state it has not yet witnessed. Detection needs a
  second channel (another device's checkpoint, SAS transfer, or the recovery
  bundle). No transparency log or gossip in v1.
- **A device resuming from its cursor does not see a restore below it.** A device
  that only reads positions above its own cursor cannot compare heads at a
  restored position. Comparing the served current head catches an operational
  restore, not a server that serves the head the device expects. The device keeps
  the records it holds (a re-served older revision is refused as a replay), but
  records members wrote on the restored line still apply by compare-and-swap.
  Reading the log again with the kept head at the witnessed position, or comparing
  its own state digest with another device's checkpoint at that checkpoint's
  position, detects it ([spec §6](../protocol/v1/spec.md#6-checkpoints-anti-rollback)).
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
  ([#42](https://github.com/bestagentkits/ak-vault/issues/42)). The Worker now refuses
  the recovery-identity path, and recovery enrollment, for sessions whose token carries
  `session_kind` `machine` or `api_key_device`, and fails closed on an unknown value
  ([spec §9.1](../protocol/v1/spec.md#9-transport-authentication-worker)). The refusal is
  only as good as the claim ak-web puts in the token, and it does not yet cover any
  machine identity that exists today. A token without the claim is treated as `email_otp`
  (making the claim mandatory is [#88](https://github.com/bestagentkits/ak-vault/issues/88)).
  ak-web mints vault tokens only for email-OTP sign-ins (its API-key sign-in gets no
  vault token, and there is no machine sign-in), so a machine or CI device provisioned by
  signing in to the owner account with email OTP is an `email_otp` session and still
  takes the path. Until machine
  identities get their own sign-in that ak-web marks `session_kind: machine`
  ([ak-web#578](https://github.com/bestagentkits/ak-web/issues/578),
  [#6](https://github.com/bestagentkits/ak-vault/issues/6)), the only way to prevent the
  fetch is not signing a CI runner in to the owner account. Marking sessions is a
  prerequisite for shipping machine identities and API-key device sessions
  ([ak-web#583](https://github.com/bestagentkits/ak-web/issues/583)).
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
- **No independent third-party review.** By owner decision on 2026-10-16
  ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)) the review gate is a review by the project owner, who
  directs the implementing agents. No reviewer outside the project has reviewed the
  protocol or the Worker, and none is required for GA
  ([release gates](./release-gates.md#review-by-the-owner)). The owner accepted
  the review gate on 2026-10-16 by instruction in chat, recorded by an agent, with
  no written findings ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)).
- **Production sync went live before the review.** By owner decision on
  [#8](https://github.com/bestagentkits/ak-vault/issues/8) (2026-10-16) production
  sync is live, with ak-web minting production vault tokens, before the
  owner's review and with other release gates open
  ([release gates](./release-gates.md#owner-waivers)). It is pre-release and not
  yet recommended for production credentials. Clients released up to
  `v3.0.0-beta.30` also predate the removal-fence client, which first shipped in
  `v3.0.0-beta.31` ([agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469)):
  their removals and recovery are refused, a lost device is revoked through ak-web
  instead, and they do not check change-log contents against removal fences, so
  the fence guarantee above holds only for clients that include it.
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
- **Remote access puts plaintext in Worker memory** (ADR 0002 D7). While remote access
  is enabled, an MCP set's `value`, relayed names and profile fields, and redacted run
  output pass through the Worker after TLS termination on their way to or from a
  device. A compromised Worker sees them; it still stores none and holds no key.
- **A compromised Worker can forge relay calls and sealed operations** for devices that
  opted in, within any MCP scope it claims. Devices apply their own grants and
  approvals, and every drained operation is a signed, audited record, but devices do
  not verify the MCP token themselves.
- **The browser device holds an owner-role key.** Script running in the dashboard can
  decrypt every item and could sign a membership event offline that another channel
  delivers; the `browser` session kind only stops the Worker from accepting it.
  Removing the browser device and rekeying is the response.
- **`run` redaction is literal.** The device removes exact released values from
  relayed `run` output; output a command encoded, split or truncated still leaks.
- **MCP clients trust the Worker for results.** They do not verify device
  signatures; only the Worker checks them, so a compromised Worker can answer an MCP
  client with anything.
- **Old writers drop synced profiles.** A client that predates the profile layout
  does not carry `meta.profile` forward, so its edit removes the item's profile.
- **Offline MCP cannot read.** With no opted-in device online, MCP reads answer
  `no_device_online`; only sealed writes work (ADR 0002 D3).
- **Name tags leak name equality** within a key epoch, across that epoch's revisions.
- **Metadata.** Item counts, sizes, timing, revisions, membership and device
  public keys are visible to the server
  ([data classification](./data-classification.md)).
