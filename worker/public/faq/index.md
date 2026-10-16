---
title: "ak-vault FAQ"
url: https://vault.agentkit.best/faq/
status: "Protocol v1 proposed, in security review. Cloud sync not generally available."
---

# Questions worth asking a secrets product

Straight answers about status, privacy, everyday use, teams, agents and recovery. Guarantees here are design properties of protocol v1 as proposed, and each comes with its limitation.

## Status and availability

### Can I use cloud sync today?

Only as a preview. Protocol v1 is proposed and in security review on [issue #8](https://github.com/bestagentkits/ak-vault/issues/8), and cloud sync is not generally available. By owner decision the production sync API is live before that review as a pre-release preview: if you are signed in and run the preview `ak secrets sync` commands, your device syncs with it. It is not yet recommended for production credentials. The local `ak secrets` vault works today.

### What works right now?

The local vault in the AgentKit CLI: importing a `.env` file, setting, rotating and inspecting secrets, `${secret:NAME}` references, agent grants and approvals, and the access audit. See [Part 1 of the guide](https://vault.agentkit.best/guide/#local).

### Is there a date for general availability?

No date is promised. Sync ships when every item in the [release gates](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/release-gates.md) is met at the release commit, including the owner's review. Progress is tracked on [the epic](https://github.com/bestagentkits/ak-vault/issues/1).

### Is the server code open?

Yes. The Worker, the TypeScript and Go protocol implementations and the cross-language test vectors are in the [public repository](https://github.com/bestagentkits/ak-vault) under the MIT license.

## Security and privacy

### Can AgentKit read my secrets?

The design says no. The server stores ciphertext and wrapped keys only, and never receives your master password, recovery key or device private keys. It can see the metadata listed in the [data classification](https://vault.agentkit.best/how-it-works/#data). Treat this as a design claim: the owner accepted the review gate with no written findings, no independent third party has reviewed it, and the release gates are not all met.

### What can the server see?

Random vault and item IDs, revisions, tombstone flags, key epochs, ciphertext sizes, timestamps, device public keys, roles, token claims and request metadata such as IP address and timing. Secret names, descriptions and values are encrypted.

### What if the server is malicious or hacked?

It cannot decrypt, and signed records, an owner-signed member list and checkpoints let devices detect tampering, rollback and forks. It can still withhold updates a device has never seen (a freeze attack) and observe metadata. [See the threat card](https://vault.agentkit.best/security/#t-server).

### Which cryptography does it use?

XChaCha20-Poly1305, Ed25519, X25519, HKDF-SHA256 and Argon2id from audited libraries, plus ES256 tokens for transport. There is no custom cryptography, and an unknown algorithm is refused.

### Does turning sync off stop all network traffic?

That is a release gate: with sync off, `ak secrets` must make zero network requests, and `resolve` must work with the Worker unreachable.

## Everyday use

### What happens if the server is down?

Running agents are not affected. `resolve` reads the local vault and never waits on the network. Changes made offline sync on the next successful connection.

### What if two devices edit the same secret?

Neither edit is silently lost. Writes are compare-and-swap on a revision; the second writer gets a conflict and its version is kept as a branch until you choose. There is no last-writer-wins. [See the diagram](https://vault.agentkit.best/how-it-works/#conflicts).

### Can a deleted secret come back?

Not by accident. A delete is a signed tombstone, and a stale write based on a revision older than the delete gets `409 tombstoned`, so an offline device cannot resurrect it. You can still re-create the secret deliberately.

### How fast does a change reach my other devices?

The design target is about a minute on a healthy connection. It is a target, not a measured result.

## Teams and agents

### Can I give a teammate access to just one secret?

Not within one vault. A vault key decrypts every item in the vault, so v1 makes no per-secret access claim. Put the secrets you want to share in a separate shared vault.

### Do agents see the values?

An agent sees a value only when you grant or approve it, and then it receives plaintext. Planned `search` and `describe` let agents find secrets by description without seeing values.

### Can a shared description trick my agent?

It can try. `ak` treats descriptions, URLs and profiles as untrusted, author-attributed data, never instructions, but an agent that reads a description (for example through the planned `describe`) can still be influenced by it. Portable policy can only narrow local grants and high-sensitivity secrets always need fresh approval, which bounds what a misled agent can obtain.

### What happens when I remove a member?

The vault moves to a new key epoch wrapped only to the remaining members, and affected items are marked to rotate. Values the member already saw cannot be taken back.

## Devices and recovery

### What if I lose my laptop?

Revoke the device. Revocation is checked on every request, so a revoked device or session is refused. Anything it already decrypted cannot be clawed back, so rotate sensitive credentials at the provider.

### What if I lose every device?

A fresh device can recover with your master password or your recovery key through the encrypted recovery bundle. If you lose all devices, the password and the recovery key, nobody can decrypt the vault, including AgentKit.

### How do I add a new device safely?

Both devices show the same six-digit code derived from the enrollment transcript. Approve only if the codes match; a mismatch aborts. [See enrollment](https://vault.agentkit.best/how-it-works/#enrollment).

## The project

### How do I report a vulnerability?

Privately, through [GitHub security advisories](https://github.com/bestagentkits/ak-vault/security). Please do not open a public issue.

### Where is the specification?

The normative [protocol v1 spec](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md), the [threat model](https://github.com/bestagentkits/ak-vault/blob/main/docs/security/threat-model.md) and [ADR 0001](https://github.com/bestagentkits/ak-vault/blob/main/docs/adr/0001-opt-in-zero-knowledge-sync.md) are on GitHub.

### How is this related to AgentKit?

ak-vault is the sync service for `ak secrets`, the secrets vault in the [AgentKit](https://agentkit.best) CLI. It uses your AgentKit account to sign in.
