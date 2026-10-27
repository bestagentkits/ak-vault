---
title: "ak-vault: end-to-end encrypted sync for ak secrets"
url: https://vault.agentkit.best/
status: "Protocol v1 proposed, reviewed by the owner (not an independent review). Cloud sync pre-release, not generally available."
---

# Your secrets sync. The server only sees ciphertext.

ak-vault is the opt-in, end-to-end encrypted sync layer for AgentKit's `ak secrets`. Secrets are sealed on your device before they leave it, agents keep reading from the local vault, and with sync off nothing touches the network. A browser dashboard and remote MCP run on staging only, pre-release and not for production credentials; remote MCP passes plaintext through server memory during a call ([details](https://vault.agentkit.best/security/#remote-access)).

> **Status: Protocol v1 · owner-reviewed · sync pre-release.** Cloud sync is not generally available. The production sync API is live as a pre-release preview, by owner decision, before the owner's security review, which is not an independent third-party review: anyone signed in to AgentKit who runs the preview `ak secrets sync` commands can use it. Do not put production credentials in it yet. The local `ak secrets` vault works today without it.

## 1. The problem

A key starts in one `.env` file. Then it is pasted into a chat for a teammate, lands in shell history, gets copied to a second laptop and ends up in an agent's config. Every copy is plaintext that someone else can read.

The local vault, available today, fixes one machine: values live in the OS keychain or the age-encrypted file vault, configs say `${secret:OPENAI_API_KEY}`, agents receive a value only through a grant you approved, and every release is recorded in a local audit ledger. ak-vault adds the missing piece: the same vault on your other devices, without handing the values to a server.

## 2. How sync works

Your local vault stays the source of truth. Sync is an optional path between devices you enrolled yourself.

1. **You set a secret (device A).** `ak secrets set` stores it in the OS keychain or the age-encrypted file vault, as it does today. Nothing leaves the machine unless you turn sync on.
2. **It is sealed locally.** Name, value and description are encrypted together with XChaCha20-Poly1305 under a per-item key derived from the vault key. The device signs the record with its own Ed25519 key.
3. **The Worker stores ciphertext.** A Cloudflare Worker checks the device's token and proof, accepts the write only if the revision matches, and keeps conflicts and deletions. It holds no key that opens the record.
4. **Another device verifies, then decrypts (device B).** It checks the signature, the owner-signed member list and its last witnessed checkpoint, refuses anything older, then decrypts into its own local vault.

Cross-device updates are targeted to arrive within about a minute, only when both devices run an active sync service and the network works. A CLI without a background service syncs on its next run. Reads through `resolve` always come from the local vault. Full walkthrough: [How it works](https://vault.agentkit.best/how-it-works/index.md).

## 3. Two views of one secret

One synced secret, seen from each side (protocol v1, proposed; values illustrative).

| Data | On your device | What the server stores |
|---|---|---|
| Secret name | `OPENAI_API_KEY` | encrypted inside `ct`; item IDs are random and never derived from names |
| Secret value | `sk-proj-…` | encrypted inside `ct`; never in logs, errors or telemetry |
| Description, tags, profile, sensitivity | "Billing project key", `high` | encrypted inside `ct` |
| Vault key | unwrapped in memory when needed | wrapped only to your devices, your password-derived key and your recovery key |
| Item ID and revision | you use the name instead | visible (`q7N2fXk0…`, revision 8); needed to order writes and catch conflicts |
| Sizes and timestamps | same | visible; shows roughly how many items change and when; sizes hint at value length |
| Devices and members | your device list | visible: device IDs, public keys, roles, accounts (the signed member list) |
| Network metadata | not applicable | visible: IP address and request timing at the edge |
| Master password, recovery key, device private keys | only here | never sent |

## 4. Every promise comes with its fine print

These are design properties of protocol v1 as proposed. They hold only after the implementation passes every security gate in [issue #8](https://github.com/bestagentkits/ak-vault/issues/8). The owner accepted the review gate on 2026-10-16 with no written findings; no independent third party has reviewed it.

| Design property | Limitation |
|---|---|
| **Encrypted before upload.** Values, names, descriptions, tags, profiles, policy and audit entries are sealed on the device (spec §3.2, §7). | **Metadata is visible.** Random IDs, revisions, sizes, timestamps, device public keys, roles and request metadata. |
| **Owner-signed membership.** A hash-chained, owner-signed log decides which devices receive the vault key; injected recipients are rejected (spec §4). | **One key per vault.** Anyone holding a vault's key can decrypt every item in it. No per-secret access; use separate vaults. |
| **Rollback detection.** Devices keep signed checkpoints and refuse server state older than one they already witnessed (spec §6). | **Withheld updates.** A malicious server can hide updates a new or long-offline device has never seen. Detecting that needs a second channel. |
| **Live revocation.** Device-bound tokens plus a per-request device signature; revoked devices and sessions are refused on every request, and lookup errors fail closed (spec §9). | **No claw-back.** Anything a device already decrypted stays exposed, so affected secrets are marked to rotate. |
| **Local-first and opt-in.** `resolve` never waits on the Worker; with sync off, secrets make zero network requests. | **Plaintext reaches the child process.** `ak secrets run` (planned) hands the value to the process you approved. |
| **No silent overwrites.** Revision compare-and-swap; a stale write gets `409` and is kept as a conflict branch; deleted stays deleted (spec §5). | **Not independently reviewed.** The owner accepted the review gate with no written findings. Treat every property as a design target until every release gate is met. |
| **Recovery without trusting the server.** The encrypted recovery bundle carries the owner's public trust anchor, the recovery signing key and the newest witnessed checkpoint (spec §3.4). | **Lose every key, lose the vault.** Without an enrolled device, your master password or your recovery key, nobody can decrypt the vault, including AgentKit. |

Full threat model: [Security model](https://vault.agentkit.best/security/index.md).

## 5. Start local today

The local vault ships in the AgentKit CLI now. Sync commands are a hidden, unsupported preview in the released CLI; agent-discovery commands are planned and not available yet.

1. **Import your `.env`** (available). Delete the plaintext file once you have checked the import.
   ```sh
   ak secrets import-env .env
   ak secrets list
   ```
2. **Reference, don't paste** (available). The value is resolved locally, for an agent you granted it to.
   ```
   OPENAI_API_KEY=${secret:OPENAI_API_KEY}
   ```
3. **Sync a second device** (preview: hidden in the released CLI, not a supported workflow; syntax may change). Opt in, then enroll another device by comparing a six-digit code on both screens.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets sync enable
   ```

Step by step: [Guide](https://vault.agentkit.best/guide/index.md).

## 6. Where it stands

Work is tracked in the [epic, issue #1](https://github.com/bestagentkits/ak-vault/issues/1). Personal-vault sync comes first. No dates are promised.

- **Local vault: available.** Keychain or age-encrypted file vault, agent grants, approvals and an audit ledger in the AgentKit CLI.
- **Protocol v1 and test vectors: in review.** Spec, TypeScript reference and a Go implementation that reproduce every vector ([#2](https://github.com/bestagentkits/ak-vault/issues/2)).
- **Worker and storage: preview.** Cloudflare Worker with a SQLite Durable Object per vault, including shared-vault membership. The production sync API is live as a pre-release preview, before the review ([#4](https://github.com/bestagentkits/ak-vault/issues/4), [#5](https://github.com/bestagentkits/ak-vault/issues/5)).
- **Client sync in the CLI: preview.** The sync commands ship hidden in the released `ak` beta; the removal-fence client is included since `v3.0.0-beta.31`.
- **Security gate: required for GA.** Red team, a two-device end-to-end run with real clients, rollback rehearsal and a review by the owner (not independent) ([#8](https://github.com/bestagentkits/ak-vault/issues/8)).
- After personal sync: read-only CI identities ([#6](https://github.com/bestagentkits/ak-vault/issues/6)) and portable policy with encrypted audit ([#7](https://github.com/bestagentkits/ak-vault/issues/7)).

## 7. Questions

- **Can I use cloud sync today?** Only as a preview. Protocol v1 is proposed; its review gate was accepted by the owner, not by an independent third party, and cloud sync is not generally available. By owner decision the production sync API went live before that review as a pre-release preview: if you are signed in and run the preview `ak secrets sync` commands, your device syncs with it. It is not yet recommended for production credentials. The local `ak secrets` vault works today.
- **Can AgentKit read my secrets?** The design says no: the server stores ciphertext and wrapped keys only. It can see the metadata in the table above. Treat this as a design claim: the owner accepted the review gate with no written findings, no independent third party has reviewed it, and the release gates are not all met. On staging only (pre-release, not for production credentials), remote MCP narrows this: during a call, plaintext passes through the server's memory, though it is never stored or logged ([remote access](https://vault.agentkit.best/security/#remote-access)).
- **What happens if the server is down?** Nothing changes for running agents. `resolve` reads the local vault. Offline changes sync on the next successful connection, and conflicting edits are kept for you to resolve.
- **Can I give a teammate access to just one secret?** Not within one vault. Put shared secrets in a separate shared vault.
- **What if I lose my laptop?** Revoke the device. Anything it already decrypted cannot be clawed back, so rotate sensitive credentials at the provider.

All questions: [FAQ](https://vault.agentkit.best/faq/index.md).

## Links

- [Protocol v1 specification](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md)
- [GitHub repository](https://github.com/bestagentkits/ak-vault) (MIT)
- [Report a vulnerability](https://github.com/bestagentkits/ak-vault/security)
- [AgentKit](https://agentkit.best)
