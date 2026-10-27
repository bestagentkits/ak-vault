# ADR 0001: Opt-in zero-knowledge sync for AgentKit secrets

- **Status:** Accepted
- **Proposed:** 2026-10-13
- **Accepted:** 2026-10-16, by the repository owner
  ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6210567772)). The first draft required
  the owner's approval **and** an external cryptographic review before acceptance;
  the owner accepted the design ahead of that review. Acceptance is the owner's
  design decision, not a review sign-off ([external review milestone](#external-review-milestone)).
  Since 2026-10-16 the reviewer is the owner, not an independent third party; the
  review gate was accepted by the owner on 2026-10-16 (owner instruction recorded
  by an agent, no written findings, [record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)). Neither the owner's
  approval nor the review can be self-attested by an implementing agent.
- **Tracking:** epic [#1](https://github.com/bestagentkits/ak-vault/issues/1),
  protocol issue [#2](https://github.com/bestagentkits/ak-vault/issues/2)
- **Wire contract:** [protocol v1 spec](../protocol/v1/spec.md). This ADR records
  *why*; the spec owns *what goes on the wire*. If they disagree, the spec wins and
  this ADR is corrected.

## Context

AgentKit secrets vault v1 (`ak secrets`, issue agentkit#1543) is local-only: OS
keychain or an age-encrypted file, device-local grants keyed on secret, project,
binary fingerprint and purpose. Its plan listed **cross-device sync, team-shared
vault, org RBAC and remote policy admin as non-goals**, and its accepted limits
(post-inject exposure, keychain ACL, memory attackers, static TTLs) are recorded in
the AgentKit architecture ledger under "Secrets vault v1 limits".

Users now need the same secrets on several trusted devices, later in shared and CI
vaults, without handing a server the ability to read them. A design review of the
first sync proposal found blocking problems: per-secret last-writer-wins, no
cryptographic specification, a server trusted for membership, "valid JWKS" treated
as sufficient auth, and agent execution described as if plaintext never left the
vault.

## Relationship to vault v1 (no history rewrite)

The v1 non-goals were correct **for v1** and stay in its history unchanged. This
ADR adds an **opt-in** layer next to v1; it does not reinterpret v1:

- Sync is off unless the user runs `ak login` and enables sync. Sync-off means
  **zero** network requests and identical v1 behavior.
- `resolve` reads only the local backend. It never waits on, or fails because of,
  the network or this service.
- Device-local grants stay authoritative. Nothing synced (policy, profile,
  membership) creates or widens a grant on another device.
- Every v1 limit still applies after a value is released. Sync adds new limits; it
  removes none (see [threat model](../security/threat-model.md#explicit-limitations)).

## Decision

1. **Boring, audited primitives only.** XChaCha20-Poly1305, Ed25519, X25519,
   HKDF-SHA256, SHA-256, Argon2id, from `@noble/*` (TypeScript) and Go
   `crypto`/`x/crypto`. Signing and key-agreement keys are separate per device.
   Algorithm identifiers are closed sets; agility means a new identifier and a new
   protocol version, never silent downgrade. ([spec §1–2](../protocol/v1/spec.md#1-primitives-no-custom-cryptography))
2. **Vault-wide key; no per-secret access claim.** One vault key per key epoch
   decrypts every item in that vault. v1 promises no per-secret authorization;
   least privilege comes from separate vaults (for example a dedicated CI vault).
   Roles (owner/editor/reader) are server-enforced write rights, not cryptographic
   read boundaries.
3. **CAS, never last-writer-wins.** Each write names its base revision. A mismatch
   returns `409` and the losing ciphertext is preserved as a conflict branch for
   explicit client resolution. Writes are idempotent by key.
4. **Tombstones.** Deletion is a signed tombstone record. Stale writes below it are
   refused and not preserved, so an offline device cannot resurrect a deleted or
   revoked credential.
5. **Owner-signed membership.** Membership is a hash-chained, owner-signed event
   log. The server stores and relays it but cannot add a device, member or
   recipient. The genesis owner key is pinned (TOFU, SAS, or recovery bundle).
6. **Client-signed checkpoints.** Clients sign and keep the highest checkpoint they
   verified and refuse any later state that rolls back or forks from it.
7. **Recovery.** The vault key is also wrapped under an Argon2id password KEK and a
   separate random recovery key. The encrypted recovery bundle carries the owner
   trust anchor and the newest owner-witnessed checkpoint, so a fresh device does
   not trust the server's word for either.
8. **Transport auth is device-bound and live-revocable.** ak-web issues a
   vault-resource ES256 JWT (exact `iss`/`aud`, `sid`, `did`, scoped
   `vault:read`/`vault:write`). Each request also carries a proof signed by the
   device key. The Worker consults a revocation registry on every request and fails
   closed if it cannot. ak-web pushes revocations to the Worker over an
   HMAC-authenticated webhook ([ak-web#568](https://github.com/bestagentkits/ak-web/issues/568)
   implements the sender). The CLI's HS256 signing key is never given to the Worker.
9. **One SQLite-backed Durable Object per vault**, inside a dedicated Worker at
   `vault.agentkit.best`. A single object serializes every write for a vault, which
   is what CAS, tombstones and the membership chain need.
10. **No R2 and no D1 until measured.** R2 only after a measured blob/snapshot
    need; D1 only for a demonstrated cross-vault query. See the
    [cost model](../operations/cost-model.md).
11. **Kill switch.** `VAULT_SYNC_ENABLED` gates the sync API on the Worker. When
    off, the sync API refuses with `sync_disabled`; local AgentKit use is
    unaffected. Production has run with it on since the owner's 2026-10-16 waiver,
    as a pre-release preview, enabled before the owner's review
    ([release gates](../security/release-gates.md#feature-flag-and-kill-switch));
    turning it off is the first incident response step. The server-side flag does
    not make sync opt-out for users: each user still enables sync explicitly.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Per-secret last-writer-wins | Silently loses concurrent edits and lets a stale device overwrite a rotation or resurrect a deletion. |
| Per-item recipient keys in v1 | Needed only to promise per-secret access; adds rewrap fan-out and complexity before personal sync exists. Revisit with shared vaults (#5) if per-secret access is required. |
| Server-held keys / KMS, web decryption | Contradicts zero-knowledge; a server or browser compromise would expose every value. |
| Server-authored membership | A malicious server could inject a recipient and receive the vault key. |
| Bearer JWT validated only against JWKS | Revocation would wait for expiry; a stolen token would be replayable. |
| Reusing the CLI HS256 key in the Worker | A Worker compromise would let an attacker mint CLI sessions. |
| Custom or hand-rolled constructions | Unreviewable; audited libraries cover every need. |
| D1 or a single shared database | Cross-vault blast radius and no per-vault serialization without extra locking. |
| Transparency log / gossip in v1 | Real value against withheld updates, but large scope; recorded as a limitation instead. |

## Consequences

- A malicious server sees operational metadata (enumerated in
  [data classification](../security/data-classification.md)) and can deny service
  or withhold updates a device has never witnessed. It cannot read values or names,
  forge records, inject recipients, or roll back a device past a witnessed
  checkpoint without detection. A device that resumes from its own cursor after a
  restore can still be forked without detection (see the threat model's
  explicit limitations).
- Removing a device or member forces a rekey before further writes, and every item
  the removed party could decrypt is flagged `needs-rotate`. Rekey cannot recall
  plaintext already obtained; provider-side rotation is the only remedy.
- Conflicts surface to users instead of being resolved silently.
- Restoring server state from backup is indistinguishable from rollback for clients
  that witnessed newer checkpoints; operations must treat restore as an incident
  ([runbooks](../operations/runbooks.md#durable-object-backup-and-restore)).
- `run --env` releases plaintext to an approved child process by design. Sync does
  not change that boundary.

## Compatibility and migration

- Sync-off installs see no change and make no network calls.
- Enabling sync uploads ciphertext of existing local items; it never deletes or
  migrates the local backend. Disabling sync stops network use and keeps the local
  vault intact.
- Wire versions are negotiated by explicit `v` and rejected when unknown; there is
  no downgrade path. Format changes require a new version, regenerated vectors in
  `protocol/v1/vectors/` (or a new `protocol/vN/`), and green Go and TypeScript
  suites.
- Server rollback, kill switch or outage never instructs clients to delete local
  caches.

## Open items

The owner accepted this ADR with the item below still open; it is a stated
limitation, not a resolved design.

- **Restore reconciliation.** v1 specifies no automatic re-convergence after a
  deliberate server restore (spec §6): devices that witnessed newer state refuse it
  and stop syncing, and recovery is operational (undo the restore, or move to a
  fresh vault). A client re-seed protocol remains open.

Resolved since the first draft: owner authority after losing every owner device
(the recovery signing key in the bundle, spec §3.5) and the SAS transcript format
(spec §3.5).

## Amendment: API-key-bootstrapped device sessions

Owner decision, 2026-10-16 ([#74](https://github.com/bestagentkits/ak-vault/issues/74)):
a user signed in with an AgentKit API key can use sync. This adds a second sign-in
path next to email OTP; it does not change the cryptographic design.

- An API key never mints vault tokens. The CLI exchanges it, with a proof of
  possession of a fresh device key, for a revocable ak-web device session tagged
  `api_key_device` and linked to the key. Vault tokens carry `session_kind`
  (`email_otp`, `api_key_device`, `machine`; [spec §9.1](../protocol/v1/spec.md#9-transport-authentication-worker)).
- Revoking the key revokes every derived session through the existing revocation
  webhook; a device is revoked as today.
- The Worker refuses the recovery identity and recovery enrollment for
  `api_key_device` and `machine` sessions and fails closed on an unknown kind, so a
  leaked key alone cannot collect recovery bundles. Joining an existing vault requires a
  `device_add` signed by an existing owner device; creating a vault is allowed. Once an
  owner approves a device it is a member under its role, except for recovery
  operations (below).
- Recovery operations need a human session (owner decision delegated on 2026-10-16,
  recorded on [#90](https://github.com/bestagentkits/ak-vault/issues/90)): the Worker
  refuses `GET /recovery`, `PUT /recovery` that replaces a stored bundle, and
  recovery-key rotation to `api_key_device` and `machine` sessions, even on an
  owner-role device, with the same `403 forbidden` as the recovery identity. A
  long-lived API key or CI credential leaks more easily than an email-OTP session,
  and recovery material is the vault's highest-value object; recovery stays
  available from any email-OTP owner device. One exception, the genesis seal: such a
  session may store the first bundle of a vault that has none, so a vault created
  through an API key is recoverable from the start (the CLI seals right after
  genesis). It can never read, replace or rotate that bundle afterwards; a rekey it
  makes leaves the bundle stale until an email-OTP owner device reseals it
  ([threat model](../security/threat-model.md) limitations).
- ak-web enforces opt-in per API key (off by default, existing keys included), at
  most 5 devices per key and an email notice on every new API-key device
  ([ak-web#583](https://github.com/bestagentkits/ak-web/issues/583)); the CLI enrols
  and approves devices ([agentkit#2475](https://github.com/bestagentkits/agentkit/issues/2475)).
- Rejected: minting vault tokens directly from an API key (no per-device revocation,
  a leaked key syncs until revoked, exposes recovery bundles).
- A personal API key in CI gets full personal-device rights; read-only scoped CI stays
  in [#6](https://github.com/bestagentkits/ak-vault/issues/6).
- Transition: a token without `session_kind` is read as `email_otp` until ak-web emits
  the claim; ak-web must set it on every `api_key_device` and machine token before
  those sessions are minted.

## External review milestone

GA is blocked until an independent cryptographic and security reviewer, who is not
an implementing agent, has reviewed this ADR, the spec, the vectors and the Worker,
and the sign-off is recorded on #8. The checklist is in
[release gates](../security/release-gates.md). Superseded; see below.

**Changed 2026-10-16 by owner decision** ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)): the reviewer is the
project owner, not an independent third party. The gate is now
[review by the owner](../security/release-gates.md#review-by-the-owner). The owner
first said they would post the result personally; on 2026-10-16 the owner instead
told an agent in chat to record it as accepted ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)), with no
written findings. On 2026-10-27 the owner decided that an independent third-party
review is not a GA gate ([record on #99](https://github.com/bestagentkits/ak-vault/issues/99#issuecomment-6435169217)), so the independent-reviewer requirement above is
superseded. GA still waits for the remaining release gates.
