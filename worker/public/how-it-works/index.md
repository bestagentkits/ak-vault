---
title: "How ak-vault works: keys, enrollment, conflicts and rollback"
url: https://vault.agentkit.best/how-it-works/
status: "Protocol v1 proposed, in security review. Cloud sync not generally available."
---

# How a secret stays sealed from one device to the next

A walkthrough of protocol v1 as proposed: the keys, how a new device joins, how conflicting edits are kept, and how devices notice a server that lies about history. Where this page simplifies, the [normative spec](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md) wins.

## 1. Keys: three ways to open a vault, none held by the server

Each vault has one random 32-byte vault key per key epoch, and every item gets its own key derived from it with HKDF. The server stores the vault key only in wrapped form, locked to things only you hold:

- **Each enrolled device.** The vault key is wrapped to the device's X25519 key, so only that device can unwrap its copy.
- **Your master password.** Stretched with Argon2id, so a stolen wrapped copy has to be guessed offline.
- **Your recovery key.** 32 random bytes shown in groups of characters, for when every device is gone.

On the server: wrapped copies of the vault key and the item ciphertext. Never a device private key, your password or your recovery key.

> **Limitation: one key opens the whole vault.** Any member device can decrypt every item. Separate vaults are the only access boundary. When a device or member is removed, the vault moves to a new key epoch wrapped only to the devices that remain. (Spec §3.)

## 2. Enrollment: a new device joins only after you compare six digits

The server relays enrollment messages, so it could try to slip in a key of its own. A short authentication string (SAS) stops that. Both devices derive the same six digits from one transcript: the vault, both device IDs and a random nonce from each side. A server that swapped a key in transit would make the codes differ. (Spec §3.5.)

1. **The new device creates its keys.** It generates its own signing and key-exchange keys. The private halves never leave it.
2. **Both screens show a code.** Each device hashes the same transcript and shows six digits.
3. **You compare, then approve.** If the codes match, the owner device signs a `device_add` event that commits to the enrollment transcript and to the vault key wrapped for the new device. If they differ, enrollment aborts.
4. **The new device verifies first.** It checks the signed member list and wrap set against the owner's signature before it unwraps anything.

The protocol defines this flow; the enrollment experience in `ak` is **planned**. If every device is lost, a fresh device can enroll itself with your password or recovery key through the encrypted recovery bundle.

## 3. Conflicts: two edits, one secret, neither lost

Many sync tools keep whichever write lands last. ak-vault never does. Every write names the revision it started from (`base_revision`), and the server accepts it only if that is still the current revision.

1. Laptop and desktop both have revision 7; the desktop goes offline.
2. Laptop writes a new value with `base_revision: 7`. The Worker accepts it as revision 8.
3. Desktop comes back and writes its edit with `base_revision: 7`. The Worker answers `409 conflict` and keeps the edit as a branch, not dropped.
4. You choose a value on either device; the new record lists the branch in `resolves`. The Worker accepts it as revision 9.

With last-writer-wins, one of these edits would have silently replaced the other. Here both survive until you decide. Retries are safe too: a repeated request with the same idempotency key returns the original answer. (Spec §5.)

## 4. Deletes and rollback: deleted stays deleted, old state stays old

- **Tombstones.** A delete is a signed record too, kept for the life of the vault. A stale device that writes on top of an older revision gets `409 tombstoned`, and its write is not kept as a branch.
- **Checkpoints.** After each verified pull a device signs a checkpoint and keeps the newest one. If the server later serves older or forked history, the device raises a rollback alarm instead of accepting it. (Spec §6.)

> **Limitation: withheld updates.** A malicious server can still hide updates from a device that has never seen them, such as a new or long-offline device. Detecting that needs a second channel, like another device's checkpoint or the recovery bundle. Transparency logs are out of scope for v1.

## 5. Architecture: small server, strong clients

All encryption, decryption and signing of vault data happens in clients, using audited libraries. The server verifies tokens and request signatures, orders writes and stores ciphertext. There is no custom cryptography anywhere.

- **Clients (agentkit CLI and Desktop):** device signing and exchange keys; encrypt, sign, verify, decrypt; the local vault stays authoritative.
- **Cloudflare Worker (this project):** token, device proof and revocation checks; versioned protocol and test vectors; production sync live as a pre-release preview, before the external review.
- **Durable Object per vault (storage):** SQLite-backed, one per vault; revisions, conflicts, tombstones; ciphertext and minimal metadata.
- **ak-web (accounts):** issues device-bound ES256 tokens and feeds revocations to the Worker; the browser never decrypts vault data.

The Worker never receives the key ak-web uses to sign CLI sessions. Every request carries a token plus a signature from the device's own key, bound to that exact request.

| Purpose | Primitive |
|---|---|
| Encryption | XChaCha20-Poly1305 |
| Signatures | Ed25519 |
| Key agreement | X25519 |
| Key derivation | HKDF-SHA256 |
| Password KDF | Argon2id |
| Server tokens | ES256 JWT |

## 6. What the server sees

Data classification for a synced vault (protocol v1, proposed). The [data classification](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/data-classification.md) owns the full list.

| Data | Server access | Notes |
|---|---|---|
| Secret values | encrypted | Inside the AEAD ciphertext; never in logs, errors or telemetry. |
| Secret names, descriptions, tags, profiles, sensitivity | encrypted | Item IDs are random, never derived from names. |
| Portable policy and audit entries | encrypted | Audit is a hash-chained, encrypted stream. |
| Vault key and recovery bundle | wrapped | The vault key is wrapped to member devices, your password-derived key and your recovery key; the recovery bundle only to the last two. |
| Vault and item IDs, revisions, tombstone flags, key epochs | visible | Needed for compare-and-swap ordering, conflicts and refusing stale writes. |
| Ciphertext sizes and timestamps | visible | Reveals roughly how many items change and when; sizes hint at value length. |
| Devices, public keys, roles, accounts | visible | The signed membership log is readable so the server can authorize requests. |
| Token claims and rate-limit counters | visible | Authentication, authorization, revocation and abuse protection. |
| Request metadata | visible | As with any HTTPS service, the edge sees IP address and request timing. |
| Master password, recovery key, device private keys | never sent | They never leave your devices. |

## Keep reading

- [Security model](https://vault.agentkit.best/security/index.md)
- [Guide](https://vault.agentkit.best/guide/index.md)
- [FAQ](https://vault.agentkit.best/faq/index.md)
- [Protocol v1 spec](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md)
