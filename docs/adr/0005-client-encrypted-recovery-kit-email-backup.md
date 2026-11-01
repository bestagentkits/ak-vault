# ADR 0005: Opt-in email delivery of a client-encrypted recovery kit

- **Status:** Proposed. An agent drafted it on the owner's request of 2026-11-01
  ([#209](https://github.com/bestagentkits/ak-vault/issues/209)). The owner's request
  authorizes the feature work, **not** a waiver of the release gates and **not** an
  approval of this construction: it needs the owner's review like ADR 0001 did, and no
  agent may record that approval for the owner without an explicit instruction.
- **Proposed:** 2026-11-01
- **Amends:** [ADR 0001](./0001-opt-in-zero-knowledge-sync.md) (recovery). It adds no
  Worker route, changes no stored vault data and widens no [REVIEW.md](../../REVIEW.md)
  hard-rejection exception. The envelope is a client-side file format, specified in
  [spec §3.12](../protocol/v1/spec.md#312-recovery-kit-backup-client-encrypted-email-backup).
- **Tracking:** [#209](https://github.com/bestagentkits/ak-vault/issues/209); client
  half in agentkit; mail delivery and account UX in ak-web
  ([ak-web#569](https://github.com/bestagentkits/ak-web/issues/569)).

## Context

Sync gives the owner one recovery kit (vault ID, account, vault origin, recovery key)
at enable time and after every recovery-key rotation. A person who loses every
enrolled device and the paper kit loses the vault, by design. Some people will lose the
paper; an encrypted copy in their own mailbox is a convenience that can rescue them,
provided it never becomes an escrow the service can open.

Requirements, from the issue: no plaintext key or kit ever leaves the trusted device;
the mail service, ak-web, the Worker and the mail provider see only delivery metadata
and ciphertext; the mailbox alone, and the passphrase alone, must each be useless; and
recovery keeps using the existing `recover` flow with its account-session and
device-proof checks.

## Decision

1. **D1: a file format, not a protocol feature.** The kit is encrypted on the owner's
   trusted device into one small JSON file (`argon2id-xc20p-kit`, spec §3.12). The
   Worker never receives it: no new route, no change to the recovery bundle, the
   membership log or any vector but the new `kit-backup.json`. Sync-off makes no
   request, and a client that never offers the option behaves exactly as today.
2. **D2: a separate backup passphrase, entered only on the client.** The key is
   `HKDF(Argon2id(NFC(passphrase), salt))`, with the passphrase independent of the
   vault password and of the account password. Clients offer a generated passphrase
   (160 bits, spec §3.12) by default, require at least 12 code points otherwise, tell
   the user plainly not to reuse the vault or account password, and never put the
   passphrase in an argument, environment variable, log or agent transcript.
   Argon2id parameters are stronger than the vault wraps' defaults (`t=3`, 256 MiB) and
   bounded on both sides, so a hostile file cannot make a client allocate more than
   512 MiB.
3. **D3: authenticated context.** The file header names the vault, the account and the
   **recovery signing public key** the kit belongs to, all under the AAD with the
   KDF parameters. The opener supplies the account from its own signed-in session; a
   file for another account or vault is refused before any key derivation. The
   recovery signing public key is the kit's generation: it changes exactly when
   `recovery_rotate` replaces the recovery key, so a client can say "this kit is
   obsolete" from the membership chain it already verifies
   ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)).
   The file is never trusted for that key: recovery still checks the bundle's key
   against the chain.
4. **D4: delivery is a service contract, not crypto.** ak-web may email the file only
   to the account's verified address, after a fresh email-OTP step-up, with rate
   limits, idempotency, and no storage of the file beyond the delivery attempt (so a
   "send again" needs a trusted device to prepare a new file, never a stored copy).
   It validates structure only (`parseKitBackupFile`; it cannot decrypt). The message
   carries no key, passphrase or reusable link. "Delivery requested", "provider
   accepted" and "delivered" are different states; only the first two can be known, and
   neither is a completed backup. The client offers a local self-check right after
   sending: open the file it just produced with the passphrase, no network.
5. **D5: recovery reuses `recover`.** After a total device loss the user signs in
   (email OTP), opens the attachment with the passphrase, and feeds the recovered kit to
   `ak secrets sync recover`. There is no email-only bypass: the recovery routes still
   need an `email_otp` session and the device proof
   ([spec §9](../protocol/v1/spec.md#9-transport-authentication-worker)), and enrollment
   still needs the chain's current recovery signing key.
6. **D6: rotation and disable.** A recovery-key rotation or a recovery makes earlier
   files obsolete; the client offers a new opt-in backup of the new kit, never sends it
   automatically, and tells the user older emails hold unusable kits (they still open
   to the old key and the vault keys the old bundle held, so treat an obsolete file in a
   compromised mailbox as described in
   [key lifecycle](../security/key-lifecycle-and-recovery.md#recovery-kit-email-backup)).
   A failed send after a successful rotation never undoes the rotation. Disabling stops
   future sends; it cannot recall mail already delivered.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| Email the recovery key, or a link that reveals it | Mailbox compromise alone recovers the vault; a bearer link is a reusable secret in mail logs |
| Encrypt to a key ak-web or the Worker holds | A server-held decryption key is escrow; it breaks zero-knowledge ([ADR 0001](./0001-opt-in-zero-knowledge-sync.md)) |
| Encrypt under the vault password or account password | Does not help the forgotten-password case, and ties two secrets together |
| Encrypt to an enrolled device's public key | Useless when every device is lost, the case this exists for |
| Store the encrypted blob in ak-web for later resend | New retention policy and a standing target; needs its own review before it exists |
| Split the key (Shamir) among services or contacts | A different product with its own recovery UX and trust model |
| A new wire message or Worker route to store the backup | Widens the hard-rejection exceptions for no benefit; the file can live in the mailbox |

## Residual risks (state them wherever the feature is described)

- **The passphrase is the only barrier to the file.** Anyone who gets the file (a
  compromised mailbox, a mail provider, a backup of the mail client) can guess the
  passphrase offline. Argon2id slows the guessing; a generated passphrase stops it. A
  weak chosen passphrase makes the email a weak copy of the key.
- **A mailbox compromise is also an account compromise path.** Account sign-in uses
  email OTP, so an attacker who controls the mailbox can sign in and, with the file and
  a guessed passphrase, recover the vault. The passphrase is the second factor that
  makes the file worth more than the account.
- **Availability depends on a second thing the user must remember.** Forgetting the
  passphrase makes the file useless; the service cannot help.
- **The user can still lose everything.** All devices, the paper kit, the vault
  password, the file and the passphrase lost means the vault is unrecoverable by design.
- **The header is plaintext metadata**: vault ID, account, recovery signing public key
  and KDF parameters. The recovery key and the vault origin are inside the ciphertext.
- **No remote erase.** Disabling cannot delete delivered mail.
- **Obsolete files stay decryptable.** Rotation supersedes a kit; it does not make an
  old file undecryptable.
- **Not independently reviewed.** The construction reuses the spec's primitives
  (Argon2id, HKDF-SHA256, XChaCha20-Poly1305) and bounds, but this ADR and the format
  have had no outside review; whether GA needs one is the owner's call.

## Verification

Vectors `kit-backup.json` (TypeScript and Go): round trips, NFC, a maximum-length kit, a
reformatted file, relabel of each header field and of each Argon2id parameter,
ciphertext, nonce and salt tamper, wrong passphrase, wrong account, vault and recovery
key, parameter bounds (DoS), malformed and oversized input, inner payload
disagreements.
Client, delivery and dashboard tests are tracked in agentkit and ak-web with the
acceptance criteria of #209.
