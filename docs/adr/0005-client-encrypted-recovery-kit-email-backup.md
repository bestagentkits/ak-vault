# ADR 0005: Opt-in email delivery of a client-encrypted recovery kit

- **Status:** Accepted
- **Proposed:** 2026-11-01, drafted by an agent on the owner's request
  ([#209](https://github.com/bestagentkits/ak-vault/issues/209)).
- **Accepted:** 2026-11-01, by the repository owner (owner instruction in chat, recorded
  by an agent on the owner's behalf,
  [record on #209](https://github.com/bestagentkits/ak-vault/issues/209#issuecomment-6557957425)),
  with the answers under [Owner decisions](#owner-decisions). Acceptance is the owner's
  design decision, not an independent review, and waives no release gate.
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
   recovery signing public key changes exactly when `recovery_rotate` replaces it, so a
   client can say "this kit is obsolete" from the membership chain it already verifies
   ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)).
   It identifies one kit only for a client that signs `recovery_rotate` whenever it
   issues a new recovery key: a kit replaced without that event shares its
   predecessor's signing key, and the chain cannot tell the two apart
   ([#210](https://github.com/bestagentkits/ak-vault/issues/210)).
   The file is never trusted for that key: recovery still checks the bundle's key
   against the chain.
4. **D4: delivery is a service contract, not crypto.** ak-web may email the file only
   to the account's verified address, after a fresh email-OTP step-up, with rate
   limits, idempotency, and no storage of the file beyond the delivery attempt. A
   client holds a new kit only until the user saves it or the send attempt ends, and
   never persists it; by design a later "send again" means rotating the recovery key on
   an enrolled owner device and backing up the new kit (D6), not re-entering an old kit.
   There is no resend from a stored copy or from the dashboard.
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
6. **D6: rotation and disable.** Earlier files become obsolete only when the chain
   records a `recovery_rotate`: from that event on, a `device_add` signed by the old
   recovery key is `forbidden`. The client offers a backup only for a kit whose
   recovery signing key is the chain's current one and was issued with it: the kit issued when sync is enabled
   (genesis), or one issued by an operation that signs `recovery_rotate`
   (`rotate-recovery`, `recover`). A path that hands out a new kit without that event
   leaves the old recovery signing key current, so an older file and a copy of the old
   bundle can still enroll an owner device, which can then rekey under a key it chose
   and remove honest devices
   ([#210](https://github.com/bestagentkits/ak-vault/issues/210);
   [#213](https://github.com/bestagentkits/ak-vault/pull/213) makes spec §3.5 require the
   rotation on every such path). After a rotation the client tells the user that older
   emails can no longer enroll a device, **not** that they are harmless: they still open
   to the old key and the vault keys the old bundle held (see Residual risks). It offers
   a new opt-in backup of the new kit and never sends it automatically. A failed send
   after a successful rotation never undoes the rotation. Disabling stops future sends;
   it cannot recall mail already delivered.

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
- **Obsolete files stay decryptable, and rotation alone does not make them harmless.**
  An old kit still opens any copy of the bundle it was sealed with (anyone who fetched
  an earlier bundle, and the server and its backups, hold old copies) and yields the
  vault keys that bundle held. The response to a suspected mailbox leak is the
  "password or recovery key leaked" row of the
  [compromise response](../security/key-lifecycle-and-recovery.md#compromise-response):
  rekey, rotate the recovery key with `recovery_rotate`, and rotate items if the bundle
  may have been taken.
- **A superseded file is detectable only through the chain.** The file carries no issue time, so a
  client learns a file is obsolete from the chain's recovery signing key (D3), and the
  chain refuses enrollment by it only after `recovery_rotate`.
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

## Owner decisions

Answered by the owner on 2026-11-01 when accepting this ADR
([record on #209](https://github.com/bestagentkits/ak-vault/issues/209#issuecomment-6557957425)):

1. D3 and the spec §3.12 bounds are accepted, including the KDF floor `t>=3` and the
   `m` range 65536..524288 KiB. A file outside them is refused even where a lenient
   reader would open it.
2. The passphrase policy is accepted: a generated 160-bit passphrase by default and at
   least 12 code points when the user chooses one.
3. ak-web keeps no copy for "send again later" (D4). Retention would need a separate
   ADR with its own retention and abuse analysis.
