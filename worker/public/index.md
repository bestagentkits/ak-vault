---
title: "ak-vault: end-to-end encrypted sync for ak secrets"
url: https://vault.agentkit.best/
status: "Protocol v1 proposed, in security review. Cloud sync not generally available."
---

# Your secrets sync. The server only sees ciphertext.

ak-vault is the opt-in, end-to-end encrypted sync layer for AgentKit's `ak secrets`. Values are sealed on your device before they leave it, `resolve` never waits on the network, and with sync off the CLI makes zero network requests.

> **Status: Protocol v1 · in security review.** Cloud sync is not generally available. The production sync API stays behind a kill switch until an independent security review signs off. Do not put production credentials in it yet. Local `ak secrets` works today without it.

## How it works

1. **You set a secret (device A).** `ak secrets set` writes to the OS keychain or the age-encrypted file vault, as it does today. Nothing leaves the machine unless sync is enabled.
2. **It is sealed locally.** Name, value and metadata are encrypted with XChaCha20-Poly1305 under a per-item key derived from the vault key; the record is signed with the device's Ed25519 key.
3. **The Worker stores ciphertext.** A Cloudflare Worker with a per-vault SQLite Durable Object checks the device-bound token and proof, applies the write only if the revision matches (compare-and-swap), and keeps conflicts and tombstones. It cannot decrypt.
4. **Another device verifies, then decrypts (device B).** It checks signatures, the owner-signed membership chain and its last witnessed checkpoint, refuses rollbacks, and only then decrypts into its own local vault.

Cross-device updates are targeted to arrive within about a minute only when both devices run an active sync service and the network works. A CLI without a background service syncs on its next invocation. Reads through `resolve` always come from the local vault.

## Guarantees and limitations

These are design properties of protocol v1 as proposed. They hold only once the implementation passes the security gate in [issue #8](https://github.com/bestagentkits/ak-vault/issues/8).

### Guarantees

- **Client-side encryption of everything sensitive:** values, names, descriptions, tags, profiles, portable policy and audit entries (spec §3.2, §7).
- **Local-first resolve:** `resolve` reads the local vault and is never blocked by Worker downtime.
- **Sync off means no traffic:** without `ak login` and an explicit sync enable, secrets cause zero network requests.
- **No silent overwrites:** revision compare-and-swap; a stale write gets `409` and is preserved as a conflict branch (spec §5).
- **Deleted stays deleted:** tombstones stop a stale offline device from resurrecting a removed secret.
- **Owner-signed membership:** a hash-chained, owner-signed log decides which devices get the vault key; injected recipients are rejected (spec §4).
- **Rollback detection:** devices keep signed checkpoints and refuse server state older than one they witnessed (spec §6).
- **Device-bound access, live revocation:** ES256 tokens plus a per-request device signature; revocation is checked on every request and fails closed (spec §9).
- **Policy can only restrict:** synced policy narrows local grants and never grants access on its own (spec §8).

### Limitations

- **Vault-wide key, no per-secret access:** anyone holding a vault's key can decrypt every item in it. Use separate vaults to share selectively.
- **Withheld updates:** a malicious server can hide updates a new or long-offline device has never seen. Detection needs a second channel.
- **Plaintext reaches the child process:** `ak secrets run` deliberately hands the value to the approved process.
- **No claw-back:** removing a member or device blocks new keys and ciphertext, but anything already decrypted stays exposed. Affected secrets are marked to rotate.
- **Metadata is visible:** see the next section.
- **Lose every key, lose the vault:** without an enrolled device, your master password or your recovery key, nobody can decrypt the vault, including AgentKit.
- **Not yet reviewed:** treat every property here as a design target until the external review signs off.

## What the server can see

| Data | Server access | Notes |
|---|---|---|
| Secret values | encrypted | Never in logs, errors or telemetry |
| Secret names, descriptions, tags, profiles | encrypted | Item IDs are random, never derived from names |
| Portable policy and audit entries | encrypted | Audit is a hash-chained, encrypted stream |
| Vault key | wrapped | Only wrapped to member devices, password-derived key and recovery key |
| Vault and item IDs, revisions, tombstone flags | visible | Needed for compare-and-swap ordering |
| Ciphertext sizes and timestamps | visible | Reveals roughly how many items change and when |
| Devices, public keys, roles, account | visible | Signed membership log, needed for authorization |
| Request metadata | visible | IP address and request timing at the edge |
| Master password, recovery key, device private keys | never sent | Never leave your devices |

## Developer quickstart

Available today (local vault v1):

```sh
ak secrets set OPENAI_API_KEY   # prompted, never echoed
ak secrets list                 # what is stored, never the value
# agents reference it as ${secret:OPENAI_API_KEY}
```

**Planned, not available yet; syntax may change:**

```sh
ak login
ak secrets sync enable
ak secrets search openai          # metadata only
ak secrets describe OPENAI_API_KEY
ak secrets request OPENAI_API_KEY
ak secrets run …                  # releases plaintext to the approved child process only
```

## Architecture

- **Clients (agentkit CLI and Desktop):** device keys; encrypt, sign, verify, decrypt; the local vault stays authoritative.
- **Cloudflare Worker (ak-vault):** token, device proof and revocation checks; versioned protocol and test vectors; kill switch until review sign-off.
- **Durable Object per vault (ak-vault):** SQLite-backed; CAS revisions, conflicts, tombstones; ciphertext and minimal metadata.
- **Login and dashboard (ak-web):** OAuth and device-bound tokens; revocation feed; metadata-only dashboard; the browser never decrypts.

Primitives: XChaCha20-Poly1305, Ed25519, X25519, HKDF-SHA256, Argon2id, ES256 JWT. No custom cryptography.

## Roadmap

Tracked in the [epic, issue #1](https://github.com/bestagentkits/ak-vault/issues/1). No dates are promised.

- [#2](https://github.com/bestagentkits/ak-vault/issues/2) P0 Protocol v1: ADR, threat model, cryptography, recovery and anti-rollback (first dependency)
- [#4](https://github.com/bestagentkits/ak-vault/issues/4) P0 Cloudflare Worker and SQLite Durable Object: encrypted records, CAS and tombstones
- [#5](https://github.com/bestagentkits/ak-vault/issues/5) P1 Shared vaults: roles, signed membership and safe rekey on removal
- [#6](https://github.com/bestagentkits/ak-vault/issues/6) P1 Machine identities: read-only CI secrets and workload revocation
- [#7](https://github.com/bestagentkits/ak-vault/issues/7) P1 Portable policy and encrypted audit
- [#8](https://github.com/bestagentkits/ak-vault/issues/8) P0 Security validation and staged release gates (required for general availability)

## FAQ

**Can I use cloud sync today?** No. Protocol v1 is in security review and the production sync API is behind a kill switch until an independent review signs off. The local vault works today.

**Can AgentKit read my secrets?** The design says no: the server stores ciphertext and wrapped keys only and never receives your master password, recovery key or device private keys. It does see the metadata listed above.

**What happens if the server is down?** `resolve` reads the local vault and never waits on the network. Offline changes sync on the next successful connection; conflicts are preserved.

**Does anything call home if I don't enable sync?** No. With sync off, secrets cause zero network requests.

**Can I give a teammate access to just one secret?** Not within one vault. Put shared secrets in a separate shared vault (planned, #5).

**What if I lose my laptop?** Revoke the device; revocation is checked on every request. Already-decrypted values cannot be clawed back, so rotate sensitive credentials.

**Is it open source? What does it cost?** MIT licensed at [bestagentkits/ak-vault](https://github.com/bestagentkits/ak-vault). No pricing has been announced.

## Links

- [Security model](https://vault.agentkit.best/security/)
- [Protocol v1 spec](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md)
- [AgentKit](https://agentkit.best)
