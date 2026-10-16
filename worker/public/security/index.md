---
title: "ak-vault security model: guarantees and limitations"
url: https://vault.agentkit.best/security/
status: "Protocol v1 proposed, in security review. Not approved for production credentials."
---

# Security model, in plain language

Who ak-vault defends against, how protocol v1 does it, and what remains your risk. This page summarizes the normative [protocol v1 specification](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md) and [threat model](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/threat-model.md); where they differ, they win.

## 1. Scope and status

The assets are your secret values and everything that describes them: names, descriptions, tags, profiles, portable policy and the audit trail. All of them are encrypted on your devices before upload. The server keeps ciphertext, wrapped vault keys and the operational metadata it needs to order and authorize writes.

> **Status:** protocol v1 is *proposed*. It is not approved for production credentials until every security gate in [issue #8](https://github.com/bestagentkits/ak-vault/issues/8) is met. The owner accepted the review gate on 2026-10-16 (recorded by an agent on the owner's instruction, no written findings); that is not an independent third-party review. The owner made the production sync API live before that review (an owner waiver, not a sign-off): anyone signed in who runs the preview `ak secrets sync` commands can use it. It is pre-release and not yet recommended for production credentials.

Out of scope by design: decryption in a web browser, server-held vault keys or KMS, and taking back plaintext that has already been disclosed.

## 2. Threat map

Plaintext exists only inside your devices. Everything that crosses the network or rests on the server is ciphertext, signatures or the listed metadata.

- **Your devices (plaintext lives here):** stolen or lost device; removed member; stale or conflicting devices; hostile shared metadata.
- **Network:** network attacker; stolen token without the device key.
- **Worker and storage (ciphertext only):** malicious or compromised server.

The device boundary matters most: a compromised local client sees everything, and the protocol does not defend it.

## 3. Threats we design against

### 1. Malicious or compromised server

- **Defence in protocol v1:** Client-side encryption for everything sensitive; signed records; an owner-signed, hash-chained member list; signed checkpoints that refuse rollback or forks; injected key recipients rejected.
- **Residual risk:** It can withhold updates a new or long-offline device has never witnessed, and it sees operational metadata.

### 2. Network attacker

- **Defence in protocol v1:** TLS, plus a per-request device signature bound to method, URL, token and body hash, accepted only within a ±60-second window and only once.
- **Residual risk:** Request timing and sizes are observable.

### 3. Stolen token without the device key

- **Defence in protocol v1:** A token alone is not enough: every request also needs a fresh signature from the device's private key, and replayed proofs are refused.
- **Residual risk:** A thief who also holds the device key is the stolen-device case below.

### 4. Stolen or lost device

- **Defence in protocol v1:** Device-bound tokens; revoked sessions and devices are checked on every request and fail closed. Removing a device requires a rekey before new writes.
- **Residual risk:** Values already decrypted on that device stay exposed. Rotate them.

### 5. Removed member of a shared vault

- **Defence in protocol v1:** Removal moves the vault to a new key epoch wrapped only to the remaining members, and affected items are marked to rotate.
- **Residual risk:** Values they already saw cannot be clawed back.

### 6. Stale or conflicting devices

- **Defence in protocol v1:** Revision compare-and-swap with preserved conflict branches, idempotent writes and tombstones. An offline device cannot resurrect a deleted secret.
- **Residual risk:** Conflicts need an explicit decision from you.

### 7. Hostile shared metadata (prompt injection)

- **Defence in protocol v1:** Descriptions, URLs and profiles are untrusted, author-attributed data and never instructions. Portable policy can only narrow local grants. High-sensitivity secrets always need fresh approval.
- **Residual risk:** An agent you grant a secret to receives its plaintext.

## 4. Guarantees and limitations

These are design properties of protocol v1 as proposed, not reviewed results.

### Design guarantees

- **No custom cryptography.** XChaCha20-Poly1305, Ed25519, X25519, HKDF-SHA256 and Argon2id from audited libraries. Unknown algorithm IDs fail closed. (spec §1)
- **Cross-language test vectors.** Go and TypeScript must reproduce every vector byte for byte, including the rejection cases.
- **Local-first.** `resolve` never depends on the network; with sync off, secrets make zero network requests.
- **Recovery without trusting the server.** The recovery bundle carries the owner's public trust anchor, the recovery signing key and the newest witnessed checkpoint, so a fresh device does not take the server's word. (spec §3.4)
- **Encrypted, chained audit.** Reordering, dropping or overwriting audit entries since a witnessed checkpoint is detected. (spec §7)
- **Least-privilege authorization.** Token scope intersected with vault membership; readers and machine identities are read-only at the Worker; no cross-vault access. (spec §9)

### Known limitations

- **Vault-wide key.** A vault key decrypts every item in that vault. v1 makes no per-secret access claim; use separate vaults. (spec §3)
- **Freeze attack.** Updates a device never witnessed can be withheld. Detection needs a second channel; transparency logs and gossip are out of scope for v1. (spec §6)
- **Plaintext to the child process.** `ak secrets run` (planned) releases the value to the approved process by design.
- **No claw-back.** Removing a device or member protects only new material. Anything already decrypted stays exposed; affected items are marked to rotate.
- **Visible metadata.** Random IDs, revisions, sizes, timestamps, device public keys, roles and request metadata.
- **Compromised local client.** Malware running as you, or a modified `ak`, sees plaintext and keys. The protocol does not defend the endpoint.
- **Key loss is final.** Lose every enrolled device, the master password and the recovery key, and nobody can decrypt the vault.
- **Audit entries are not signed per author.** Any device that held a key epoch can write audit entries at that epoch, including one removed later, until the rekeying device appends at the new epoch. (spec §7)
- **Roles are enforced by the Worker.** Clients do not yet check records against role history, so read-only roles and machine identities rely on the Worker ([#22](https://github.com/bestagentkits/ak-vault/issues/22)).
- **Removal fence binds the log its remover verified.** A device that reads the log later detects records substituted at or below the fence, but records the removed device wrote before its removal stay valid. A device that keeps writing can stall its own removal, so revoke it first. (spec §5)
- **Older betas lack the removal fence.** `ak` releases up to `v3.0.0-beta.30` neither sign nor check removal fences, so they cannot remove a device or recover, and they do not get the fence check above. Upgrade to `v3.0.0-beta.31` or later, which includes the fence client, or revoke a lost device in your AgentKit account ([agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469)).
- **Operators can see proofs in the live log tail.** Account members with Workers Tail access see request proofs and webhook signatures in the live tail. Each is single-use and bound to one request; tokens are redacted ([#61](https://github.com/bestagentkits/ak-vault/issues/61)).
- **No independent third-party review.** By owner decision the GA security review is performed by the project owner, who accepted it on 2026-10-16 by an instruction recorded on #8 by an agent, with no written findings; the owner directs the agents that built ak-vault. No reviewer outside the project has reviewed it ([#8](https://github.com/bestagentkits/ak-vault/issues/8)).
- **Recovery bundle can be guessed offline.** Anyone with a live owner-account session can download the encrypted bundle and guess a weak password offline. Revoke your sessions after a loss. (spec §3.4)
- **Trust on first use at genesis.** The owner's key is pinned on first use unless it arrives through the recovery bundle or a SAS-verified pairing. (spec §4)

## 5. Release gate

A box counts only when its evidence is linked on [issue #8](https://github.com/bestagentkits/ak-vault/issues/8) for the exact commit being released. The full list lives in the [release gates](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/release-gates.md).

Gate items; status and evidence are in the release gates:

- ADR 0001 approved by the owner, with its open items resolved.
- Go and TypeScript reproduce every test vector byte for byte, including every rejection vector.
- The Worker integration suite is green: conflicts, tombstones, idempotency, cross-tenant denial, replayed proofs, revoked devices and stale membership.
- Disclosure scan: storage dumps, logs, traces, metrics and error responses from a seeded run contain no planted plaintext values or names. The live log tail shows request proofs and webhook signatures to account operators; the owner accepted that ([#61](https://github.com/bestagentkits/ak-vault/issues/61)).
- A revoked session or device is refused on its next request, even with an unexpired token.
- With sync off, ak makes zero HTTP requests and `resolve` works with the Worker unreachable.
- Red-team scenarios executed (13 waits for the feature it attacks), a two-device end-to-end run with real clients, and backup, restore and rollback rehearsed on staging.
- The removal fence binds the change-log contents, not only a position.
- Review by the project owner: accepted by the owner on 2026-10-16 ([recorded on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397) by an agent on the owner's instruction, no written findings). This is not an independent third-party review.

## 6. Sources and disclosure

- [Protocol v1 normative wire specification](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md)
- [ADR 0001: opt-in zero-knowledge sync](https://github.com/bestagentkits/ak-vault/blob/main/docs/adr/0001-opt-in-zero-knowledge-sync.md)
- [Threat model](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/threat-model.md) and [data classification](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/data-classification.md)

Report suspected vulnerabilities through [GitHub security advisories for ak-vault](https://github.com/bestagentkits/ak-vault/security), not a public issue.
