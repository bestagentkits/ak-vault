# ADR 0005: Opt-in email delivery of a client-encrypted Recovery Kit

- **Status:** Proposed. An agent drafted it from the owner's request on
  [#209](https://github.com/bestagentkits/ak-vault/issues/209) (2026-11-01). The
  request authorizes designing and tracking the feature; it does **not** accept this
  construction, waive a release gate or approve a new cryptographic design. No code
  that follows from this ADR may ship before the owner accepts it.
- **Proposed:** 2026-11-01
- **Amends:** nothing in force today. The backup envelope adds a client-side format
  and no Worker route, so it does not widen [REVIEW.md](../../REVIEW.md) hard
  rejection criteria, the remote-access exceptions in
  [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable) or the session kinds of
  [spec §9](../protocol/v1/spec.md#9-transport-authentication-worker).
- **Tracking:** [#209](https://github.com/bestagentkits/ak-vault/issues/209); epic
  [#1](https://github.com/bestagentkits/ak-vault/issues/1); account UX
  [ak-web#569](https://github.com/bestagentkits/ak-web/issues/569)
- **Wire contract:** none yet. The envelope in D3 is a **file format**, not a
  protocol message. When accepted, a spec section and deterministic vectors own it
  (D9); until then this ADR fixes only the shape, and the spec wins if they disagree.

## Context

A user who loses every enrolled device and the paper Recovery Kit has no way back
into the vault ([key lifecycle](../security/key-lifecycle-and-recovery.md#lost-home-or-all-devices)):
recovery needs the password or the 256-bit recovery key. Many users lose the
printout, or never save it. Mailing themselves a copy is the obvious convenience and
the obvious trap: an emailed **plaintext** kit turns mailbox access into vault
access and puts the key in the mail provider's storage forever.

What exists today, from the code and the spec:

- The kit is five fields: vault ID, issuing device ID, account, vault origin and the
  recovery key (`secretsync.RecoveryKit`). The recovery key is 32 random bytes
  ([spec §3.4](../protocol/v1/spec.md#34-password-and-recovery-wraps)).
- **No enrolled device keeps the recovery key.** It is shown once at `enable` or
  `rotate-recovery`. Devices hold only vault keys wrapped to themselves. So no
  device, and certainly not the server or the dashboard, can later "send the kit
  again": only a **new** recovery key can be mailed, which means a rotation.
- Reading the bundle and recovery enrollment already need a human email-OTP
  session of the owner account plus the password or recovery key
  ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)).
  The `browser`, `api_key_device` and `machine` sessions are refused on those routes.

## Decision

1. **D1: opt-in, off by default, never a precondition.** `enable` and
   `rotate-recovery` keep issuing the kit locally exactly as today. "Email an
   encrypted backup" is a separate, clearly labeled choice that the user must turn on
   each time. Declining, failing or interrupting it never blocks, delays or rolls back
   enabling sync, a rotation, or local use of the vault. Sync off means no network
   request and no behavior change.
2. **D2: the kit is encrypted on the user's trusted device, before anything leaves
   it.** Only a device that holds the plaintext kit (the one that just ran `enable` or
   `rotate-recovery`, a human owner session) can prepare a backup. ak-web, the Worker
   and the mail provider receive only the envelope. The **backup passphrase** is typed
   or generated on that device, used to derive the key and discarded; it is never sent,
   stored, logged or put in an email. The dashboard at `/app` and any unenrolled browser
   never see the recovery key and never prepare a backup (a `browser` session is
   refused on recovery routes already).
3. **D3: envelope, with the spec's primitives only.** No new primitive, no new
   library, no `age`, `scrypt` or `PBKDF2`:

   ```
   pt   = cjson({"v":1,"vault_id","account","vault_origin","recovery_key":b64(32 bytes)})
   s    = random 16 bytes
   ikm  = Argon2id(passphrase_utf8_nfc, s, t, m_KiB, p, L=32)
   key  = HKDF(ikm=ikm, salt=utf8("akv1"), info=utf8("akv1/recovery-backup-kek"), L=32)
   n    = random 24 bytes
   aad  = cjson({"ctx":"akv1/recovery-backup","v":1,"vault_id","account","t","m","p"})
   ct   = XC20P(key, n, pt, aad)
   file = cjson({"v":1,"alg":"argon2id-xc20p-backup","vault_id","account","s":b64,
                 "t","m","p","n":b64,"ct":b64})
   ```

   - The `ctx`, HKDF `info` and `alg` are new, so a backup never opens as a password
     wrap, recovery wrap, bundle or input seal, or the reverse (domain separation).
   - Defaults `t=3, m=65536, p=1`, the spec's current password defaults. The **decrypter**
     enforces `t` in 3..10, `m` in 65536..262144 KiB, `p` in 1..4 before running Argon2id,
     so a hostile file cannot make a device burn memory or time: stricter floors than
     the bundle's, because a mailbox copy is attacker-readable offline for ever, and
     tighter ceilings, because the file arrives from outside. Anything outside refuses.
   - `v`, `alg` and every field are closed sets. Unknown version or algorithm, a missing
     or extra field, non-canonical JSON, an invalid base64 length, or a file over 2 KiB is
     `bad_request` before any KDF work. Wrong passphrase, a tampered or truncated `ct`,
     and a wrong `vault_id`/`account`/parameter all surface as the same `decrypt_failed`.
   - `vault_id` and `account` are authenticated: a blob moved to another vault or
     account fails. They are in the clear, and the mailbox owner already knows both.
   - The plaintext holds no device ID, vault key, password, session token or name of
     any secret.
4. **D4: the passphrase is a separate secret, and the client is strict about it.**
   The default is a **generated** passphrase (at least 80 bits of entropy, from a
   reviewed word list, shown once on the device) that the user must confirm by typing it
   back. A user-chosen one needs at least 20 characters and may not equal the vault
   password the client holds at that moment; the client says plainly not to reuse the
   vault, account or email password. Nothing is "remembered": forgetting it makes the
   email copy useless, and the UX says so. A strength check that the user can lower is
   not offered; weaker input is refused.
5. **D5: ak-web delivers; it never decrypts and never keeps the file.** The device posts
   the envelope to an ak-web endpoint, authenticated as a human email-OTP session with a
   **fresh** step-up (a recent OTP, not just a live session). The recipient is the
   account's **verified email**, never an address in the request. ak-web checks the
   envelope's closed shape and size and that `account` equals the session subject (it
   cannot decrypt, so that is all it can check), then sends one transactional message
   with the file attached and discards the bytes once the provider accepts or refuses
   them. Required controls: per-account and per-vault rate limit, an idempotency key so a
   retry does not mail twice, a daily cap, abuse and bounce handling, no retained copy
   and no body, subject, header or link that carries key material or a reusable
   download URL. The message tells the user what the file is, to decrypt it **locally**
   with the separate passphrase, and what it cannot do. It never names the passphrase.
   Retention of anything beyond the delivery metadata in D6 is **out of scope** and needs
   its own reviewed decision; this ADR does not authorize an ak-web "download your
   backup later" store.
6. **D6: honest status; metadata only.** ak-web keeps, per account and vault: opted in
   or not, last attempt time and outcome. The states the UX may show are exactly:
   `kit_created` (kit issued locally), `encrypted_locally`, `delivery_requested`,
   `delivery_accepted` (the mail provider accepted it) and `delivery_failed` (with a
   stable reason code). **Nothing says "delivered" or "backed up"**, because accepted
   mail can still bounce or land in spam; the UX says "sent, confirm you can find the
   email and decrypt it". A failed or unknown delivery is never shown as a completed
   backup, and a rotation that succeeded stays succeeded when mailing fails (the user is
   told to save the new kit by hand or retry).
7. **D7: recovery reuses the existing flow; there is no email-only path.** After a total
   loss the user signs in to AgentKit with email OTP, opens the mail, decrypts the file
   **locally** (`ak secrets sync recover` gains a file/passphrase input; the decrypted
   recovery key goes into the existing signed recovery flow unchanged), and enrolls a new
   device with the recovery signing key. The Worker, its routes and its authorization are
   not touched. Possessing the mailbox alone, or the passphrase alone, adds no device.
8. **D8: "send again" means "rotate".** Because no device keeps the recovery key, the
   only way to produce a fresh backup is `rotate-recovery` on an enrolled owner device,
   which issues a new kit, and then optionally D1-D5 again. The dashboard shows the D6
   status and instructions and points to the CLI or Desktop app; it has no resend button
   and never derives, fetches or displays the key. After a rotation or a recovery, the old
   kit is obsolete: earlier emails hold a recovery key the chain refuses (the bundle no
   longer opens with it and a `device_add` signed by the old recovery key is `forbidden`),
   so the client tells the user that those emails are unusable and offers a new opt-in
   backup. It never sends the new kit on its own.
9. **D9: cross-language vectors before shipping.** The envelope is produced and read by
   Go (CLI) and may be produced by TypeScript (Desktop). Before any client ships it, a
   spec section ("Recovery-kit backup file") and `protocol/v1/vectors/recovery-backup.json`
   (generated by `packages/protocol`, reproduced by `go/`) cover: a valid file; wrong
   passphrase; tampered `ct`, `s`, `n`, `t`/`m`/`p`, `vault_id`, `account`; moved to
   another vault or account; unknown `v`/`alg`; extra and missing fields; truncated and
   oversized input; and KDF parameters just inside and outside the bounds. Spec-change
   procedure in [AGENTS.md](../../AGENTS.md#spec-and-vector-changes) applies, and the
   threat model rows below are claimed only when those vectors and the ak-web and CLI
   tests exist.
10. **D10: disabling is forward-only.** The user can turn future backups off. That cannot
    remove mail already delivered; the UX says so and tells the user that a rotation
    makes every earlier copy useless.

## Consequences and limits

- **A mailbox copy is an offline-guessable target for ever.** Anyone who gets the file
  (mailbox compromise, mail provider, a forwarded message) can guess the passphrase
  offline; Argon2id cost and a generated 80-bit passphrase are the only barrier, and a
  user who picks a weak one weakens it. That is why D4 refuses weak input and why a
  rotation (which obsoletes old kits) is the response to a suspected mailbox leak.
- **It is not escrow.** If the passphrase and every device are lost, the vault is
  unrecoverable. Encrypting the file under the **same** lost vault password would not help
  recovery from a forgotten password, so the passphrase is separate by design; the price
  is that the user must keep a second secret.
- **Three independent things are needed:** AgentKit sign-in (email OTP, the account),
  the encrypted file from the mailbox, and the backup passphrase. Compromising one never
  suffices.
- **ak-web is trusted for delivery only:** it can refuse, delay or drop the mail and can
  see the envelope in transit, like any relay of ciphertext. It cannot make the file
  decrypt, and cannot add a device.
- **Endpoint compromise is out of scope**, as everywhere in this protocol: malware on the
  device that prepares the backup sees the plaintext kit and the passphrase.
- **Terminal and agent transcripts.** The passphrase is a secret typed or shown on a
  terminal; the CLI must never accept it as an argument or echo it in `--json`, and must
  read it from a TTY or a file descriptor the user supplies. The existing
  `--recovery-kit-out` handling of the terminal leak
  ([agentkit#2788](https://github.com/bestagentkits/agentkit/issues/2788)) is a
  prerequisite, not part of this ADR.

## Rejected alternatives

- **Email the plaintext kit or key, or a link to it.** Mailbox access becomes vault
  access; the provider stores the key. Violates the zero-knowledge invariant.
- **Encrypt under the vault password.** Mailbox plus a guessed or leaked password
  recovers everything, and it does not help the user who forgot the password.
- **Server-held key, or an ak-web "recovery escrow".** Server-usable escrow is the
  construction the whole design excludes ([ADR 0001](./0001-opt-in-zero-knowledge-sync.md)).
- **A new Worker route that stores or returns a sealed backup.** Widens REVIEW.md's
  new-endpoint rule and adds a server-side retention surface for a convenience feature;
  mail is the transport precisely so the Worker stays out.
- **Resend from the dashboard or any enrolled device.** Impossible without a device
  keeping the recovery key, which would break "shown once" and widen every device
  compromise. Rotation is the honest mechanism (D8).
- **`age` or another passphrase format.** A second KDF and format to audit for the same
  security; the spec's Argon2id and XC20P are already reviewed and vectored.
- **A signed or two-factor-derived key (account token mixed into the KDF).** The account
  token is revocable and server-minted; a key bound to it would make recovery depend on
  the very service the user may be locked out of.

## Open questions for the owner

1. Accept D3 as the envelope, in particular the stricter KDF floor (`t>=3`) and the
   `m<=262144` KiB ceiling, which refuse some files a lenient reader would open?
2. Accept 80 bits generated / 20 characters chosen as the passphrase floor, and the
   word list (to be chosen and vectored with the implementation)?
3. Confirm that no ak-web retention for "send again later" is wanted (D5, D8). If it is,
   it needs a separate ADR with its own retention and abuse analysis.
