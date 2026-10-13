---
title: "ak-vault security model: guarantees and limitations"
url: https://vault.agentkit.best/security/
status: "Protocol v1 proposed, in security review."
---

# Security model, in plain language

Who ak-vault defends against, how protocol v1 does it, and what remains your risk. This page summarizes the normative [protocol v1 specification](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md); where they differ, the spec wins.

## Scope and status

The assets are your secret values and everything that describes them: names, descriptions, tags, profiles, portable policy and the audit trail. All are encrypted on your devices before upload. The server keeps ciphertext, wrapped vault keys and the operational metadata it needs to order and authorize writes.

> **Status:** protocol v1 is *Proposed*. It is not approved for production credentials until the security gate in [issue #8](https://github.com/bestagentkits/ak-vault/issues/8) records an external review sign-off. Until then the production sync API stays behind a kill switch.

Out of scope by design: decryption in a web browser, server-held vault keys or KMS, and automatic revocation of plaintext that has already been disclosed.

## Adversaries

| Threat | Defence in protocol v1 | Residual risk |
|---|---|---|
| Malicious or compromised server | Client-side AEAD; signed records; owner-signed, hash-chained membership; signed checkpoints that refuse rollback or forks; injected key recipients rejected | Can withhold updates a new or long-offline device never witnessed; sees operational metadata |
| Network attacker | TLS plus a per-request device signature bound to method, URL, token and body hash, valid ±60 s with single-use IDs | Request timing and sizes are observable |
| Stolen or revoked device | Device-bound ES256 tokens; revocation checked on every request, fails closed; device removal requires a rekey before new writes | Values already decrypted on that device stay exposed; rotate them |
| Removed member of a shared vault | New key epoch wrapped only to remaining members; affected items marked to rotate | Previously exposed values cannot be clawed back |
| Stale or conflicting devices | Revision CAS with preserved conflict branches, idempotent writes, tombstones | Conflicts need an explicit decision |
| Hostile shared metadata (prompt injection) | Descriptions, URLs and profiles are untrusted data, never instructions; policy only narrows local grants; high sensitivity always needs fresh approval | An agent you grant a secret to receives its plaintext |

## Design guarantees

- **No custom cryptography:** XChaCha20-Poly1305, Ed25519, X25519, HKDF-SHA256, Argon2id via audited libraries; unknown algorithm IDs fail closed (§1).
- **Cross-language test vectors:** Go and TypeScript must reproduce every vector byte for byte, including rejection cases.
- **Local-first:** `resolve` never depends on the network; sync-off causes zero network requests.
- **Recovery without trusting the server:** the recovery bundle carries the owner's signing key and newest witnessed checkpoint (§3.4).
- **Encrypted, chained audit:** reordering, dropping or overwriting since a witnessed checkpoint is detected (§7).
- **Least-privilege authorization:** token scope intersected with vault membership; readers and machine identities are read-only; no cross-vault access (§9).

## Known limitations

- **Vault-wide key:** a vault key decrypts every item in that vault; no per-secret access claim. Use separate vaults (§3).
- **Freeze attack:** updates never witnessed by a device can be withheld; detection needs a second channel. Transparency logs and gossip are out of scope for v1 (§6).
- **Plaintext to child process:** `ak secrets run` releases the value to the approved process by design.
- **Visible metadata:** random IDs, revisions, sizes, timestamps, device public keys, roles and request metadata.
- **Key loss is final:** lose every enrolled device, the master password and the recovery key, and nobody can decrypt the vault.
- **TOFU at genesis:** the owner's key is pinned on first use unless it arrives via the recovery bundle or a SAS-verified pairing (§4).

## Release gate

- The protocol ADR is approved and the cross-language vectors pass.
- Malicious server, member and device scenarios are exercised in staging.
- A full dump of the Worker and its storage, logs, telemetry and API errors contains no plaintext secret values or names.
- Concurrent updates keep conflicting ciphertexts, tombstones hold, and signed rollback is detected after a witnessed checkpoint.
- Revoked devices and sessions are denied; removed members lose access to new keys and ciphertext.
- No unexpected outbound calls with sync disabled.
- An independent security review signs off. This cannot be self-attested.

## Sources

- [Protocol v1 normative wire specification](https://github.com/bestagentkits/ak-vault/blob/main/docs/protocol/v1/spec.md)
- [ADR 0001: opt-in zero-knowledge sync](https://github.com/bestagentkits/ak-vault/blob/main/docs/adr/0001-opt-in-zero-knowledge-sync.md)
- [All project documentation](https://github.com/bestagentkits/ak-vault/tree/main/docs)
- [Issue #2: protocol, threat model, cryptography and recovery](https://github.com/bestagentkits/ak-vault/issues/2)

## Report a vulnerability

Report suspected vulnerabilities privately through [GitHub security advisories for ak-vault](https://github.com/bestagentkits/ak-vault/security), not a public issue.
