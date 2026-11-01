# Key lifecycle and recovery

Behavior each client and the Worker must implement for keys, devices and members.
Key formats, wraps and event bodies are owned by the
[spec](../protocol/v1/spec.md#3-key-hierarchy); this page explains the flows and
what each one does and does not protect. Client implementation lives in AgentKit
(agentkit#2298, Desktop UX in agentkit#2300).

## Vault creation and TOFU

1. The first device generates its Ed25519 signing key and X25519 key, a vault ID
   and `VK[1]`.
2. It wraps `VK[1]` to itself, to the password KEK and to a new recovery key, signs
   the `genesis` event naming itself owner and committing to its own wrap
   (`wraps_digest`), and uploads the recovery bundle.
3. The genesis owner `sign_pub` becomes the **trust anchor**. A device that learns it
   only from the server is trusting on first use (TOFU); SAS enrollment or the
   recovery bundle removes that reliance.

The user must store the recovery key offline. Losing both the password and the
recovery key, with no surviving device, makes the vault unrecoverable by design.

## Device enrollment (SAS)

1. The new device generates its keys and presents its public keys.
2. An owner device and the new device each display a short authentication string
   (SAS) computed from the enrollment transcript; the user confirms they match.
3. The owner device wraps the current vault key (and, where it holds them, older
   retained epochs) to the new device, signs `device_add` with the SAS transcript
   digest and the digest of that wrap set, and transfers its newest witnessed
   checkpoint over the SAS-verified channel.
4. The new device pins the owner anchor and that checkpoint, fetches the event's
   wrap set and checks it against the signed digest before unwrapping, so the server
   cannot substitute a key it knows.

Web login alone never enrolls a device. The SAS transcript is defined in
[spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment).
The `akj1-`/`ako1-` enrollment codes must travel between the user's own devices
([spec §3.8](../protocol/v1/spec.md#38-enrollment-codes)); a flow that relays codes needs
the committed codes of [spec §3.9](../protocol/v1/spec.md#39-committed-enrollment-codes)
on both sides.

## Device loss or theft

1. Revoke the device's session and device ID in ak-web; the Worker refuses it on the
   next request through the live revocation check.
2. From a remaining owner device, pull and verify the change log, then sign
   `device_remove` with its last position and the head you computed there as
   `log_fence` and `log_head` (on `409`, pull again and re-sign; step 1 stops the
   device from keeping the fence stale), and post a checkpoint. The vault enters
   `rekey_required`; writes are refused until rekey. Records by the removed device
   above the fence are refused from then on
   ([spec §5](../protocol/v1/spec.md#5-records-revisions-conflicts-and-tombstones)).
3. Rekey (below), marking every item the lost device could decrypt `needs-rotate`.
4. Rotate those credentials at their providers.

Step 1 stops new reads and writes. It does not protect anything the device already
cached in plaintext or could decrypt with keys it held.

## Member removal (shared vaults)

Same as device loss, using `member_remove` (removes all of the member's devices).
A removed member cannot obtain **new** keys or ciphertext. Everything they could
decrypt before removal is `needs-rotate`; rekey cannot recall it.

## Rekey

1. An owner device generates `VK[e+1]` and wraps it to every remaining member
   device, the password KEK and the recovery KEK.
2. It signs `rekey` with `new_key_epoch`, the digest of the new wrap list and the
   `needs_rotate` item IDs, then appends an audit entry under the new epoch's audit
   key and signs an audit checkpoint (required by spec §7), so a removed device can
   no longer extend the audit chain.
3. New writes must use the new epoch. Items still encrypted under an older epoch stay
   readable by current members, who hold the older wraps, and move to the new epoch
   when next written. A device enrolled after a rekey receives older-epoch keys
   only inside the signed wrap set of its `device_add`; items at an epoch it was
   not given are rotated forward by a device that can read them.

**Interrupted or cancelled rekey.** Until a valid `rekey` event is accepted, the
vault stays in `rekey_required` and refuses writes; reads continue under the old
epoch. A client that was interrupted discards its unpublished `VK[e+1]` and starts
over. The Worker must accept the rekey event and its wraps atomically so a partial
wrap set is never current; that is a Worker obligation verified by
`worker/test/`.

## Secret rotation

Rotation is an ordinary CAS write of a new value under the current epoch. Clearing
`needs-rotate` happens when the item is rewritten after the flag was set. The
provider-side credential must be rotated as well; writing a new ciphertext of the
old value protects nothing.

Two things are called rotation and are different. A **rekey** (`key_epoch`) re-wraps
the vault key for the devices that remain and replaces no credential. A **provider
credential rotation** replaces the secret at its provider. The dashboard at `/app`
shows them apart and manages only the second.

### Rotation in the dashboard

State comes from signed, encrypted item metadata and the membership log. The server
sees none of it, and nothing here decides access.

- **Health.** From `meta.rotated_ms` (else `created_ms`) plus `meta.rotate_ttl_days`:
  on schedule, due soon (7 days), overdue, or unknown. With no interval or no date the
  state is unknown; the dashboard never invents a date. After a vault write inside an
  active or paused rotation the state is *old key not confirmed revoked*, never on
  schedule, until a member confirms revocation. An item a rekey listed in
  `needs_rotate` shows `needs rotation` until a member confirms the old credential is
  revoked after a value was written under the epoch that rekey installed. A rewrite
  alone never clears it, including a CLI `set`, which bumps `rotated_ms` even for an
  unchanged value. (The base protocol rule, that a rewrite clears `needs-rotate`, is
  unchanged; the dashboard is stricter because it cannot see the provider.) The check
  uses writer-supplied dates, so a member with write access can misstate them; it is a
  display aid, not an authorization input.
- **Expiry.** Shown beside the health, not folded into it, so neither hides the
  other: *expired* once the profile's `expires_at` has passed, *expires soon* within
  `EXPIRING_SOON_DAYS` (14 days) of it, nothing otherwise
  ([`rotation.ts`](../../packages/vault-app/src/sync/rotation.ts)). The date is read
  only from the profile this device verified at the item's head; a field the
  provenance check dropped, an invalid profile, or a head whose base this device
  never held raises no warning. Like the health, it is a writer-supplied date and a
  display aid only: it changes no grant and blocks no action.
- **Workflow.** `meta.rotation` is `{state: active|paused|failed|cancelled, started_ms,
  revoked_ms?}`. A value not in that exact shape reads as no workflow. Older writers
  carry the key forward unchanged.
- **Separate steps.** (1) The operator creates the new credential at the provider,
  outside the dashboard and any AI chat. (2) *Vault updated* is true only when the
  verified head holds a value written after the workflow started (`rotated_ms >=
  started_ms`), so it follows the pulled revision, not the click. (3) *Old credential
  revoked* is a vault member's confirmation (not necessarily the viewer's), accepted only after step 2 while the rotation is active, and the
  dashboard cannot check it with the provider. Writing another value clears it. The
  dashboard never shows "rotated" before step 3 is confirmed.
- **Writes** use the browser device's signing and sealing path, compare-and-swap on the
  verified head: a concurrent edit becomes a conflict branch, a vault waiting on a
  rekey or a device without an owner or editor role is refused, and a dashboard
  replacement equal to the current value or empty is refused (a CLI `set` is not). The previous value is never shown.
- **Limits.** No provider adapters ship; none will rotate or revoke without separate
  least-privilege credentials and the operator's consent. Anyone who held the old
  value (a removed member included) still knows it until the provider revokes it. The
  signed revisions, with their author device and time, are the record of each state
  change. After each one lands, the dashboard also appends an entry to the encrypted
  audit stream (`rotation_started`, `rotation_vault_written`, `rotation_revoked`,
  `rotation_paused`, `rotation_resumed`, `rotation_failed`, `rotation_cancelled`,
  `rotation_cleared`) holding only the type, the opaque item ID, the author device
  and the time, never a name or value. Before appending, the dashboard checks that the
  stored entry at the head the server reports hashes to that head, but it cannot detect a
  server that truncated or forked the chain; only a witnessed audit checkpoint bounds
  that, and the dashboard neither reads nor signs one. The append is best effort: if it fails the
  write stays and the dashboard says the audit entry was not recorded.

## Password and parameter upgrade

- Changing the password re-wraps the current vault key under a new Argon2id KEK
  with a fresh salt and uploads a new recovery bundle.
- After an unlock under parameters weaker than the current defaults, the client
  re-wraps with the defaults ([spec §3.4](../protocol/v1/spec.md#34-password-and-recovery-wraps)).
  Verifiers refuse parameters below the published minimums, so a server cannot
  downgrade them.

## Recovery key

The recovery key unlocks the same recovery bundle as the password. Rotating it
creates a new recovery key and a new recovery signing key: an owner device signs
`recovery_rotate` naming the new signing key and sends it together with the bundle
resealed under the new key and a higher `bundle_seq`; the server stores both
atomically. Every later `PUT /recovery` names the membership position its sealer
had verified, and the server refuses one sealed before the latest rotation, so an
owner device that missed the rotation cannot replace the bundle with a stale key. From then on the membership chain refuses enrollment by the old
signing key, so an old bundle opened with a leaked recovery key cannot add a
device. It still yields the vault keys it held, so treat a leaked recovery key as a
compromise (below).

## Recovery kit email backup

An owner may choose, per recovery kit, to email an **encrypted** copy of the kit to their
verified address ([ADR 0005](../adr/0005-client-encrypted-recovery-kit-email-backup.md),
format in [spec §3.12](../protocol/v1/spec.md#312-recovery-kit-backup-client-encrypted-email-backup)).
It is off by default. Three independent things are needed to use it, and none replaces
the others:

1. AgentKit sign-in to the owner's account (email OTP), which recovery already requires.
2. The encrypted file from the mailbox.
3. The separate backup passphrase, which only the user holds.

Behavior a client implements:

- The client creates the kit locally as today, makes the user confirm it is saved, and
  only then offers the email backup. It encrypts on the device, sends only the file, and
  reports "requested", "provider accepted" and "opened locally" as different states. A
  failed send is never shown as a completed backup and never blocks local use.
- After a recovery or a recovery-key rotation that signs `recovery_rotate`, the old file
  can no longer enroll a device. A new kit handed out without that event leaves the old
  recovery signing key current, so the old file is not obsolete
  ([#210](https://github.com/bestagentkits/ak-vault/issues/210)). The client tells the
  user, without calling old files harmless, and offers a new opt-in backup of the new
  kit; it never sends one on its own. There is no resend: by design a new backup needs
  a new kit from a rotation.
  If the send fails after a successful rotation, the rotation stands and the client
  holds the new kit, without persisting it, until the user saves it or the retry ends.
- After losing every device: sign in, download the attachment, open it with the
  passphrase on the new device, and run the ordinary recovery above with the recovered
  kit. Nothing in the email path adds a device or skips the account session and device
  proof. Then remove the lost devices, rekey and, if wanted, send a new backup.
- Disabling stops later sends. It does not delete mail already delivered; treat an
  obsolete file in a compromised mailbox like a leaked recovery key (the chain refuses
  enrollment by it, but it still opens to the vault keys its bundle held).
- If the mailbox is compromised, follow the "password or recovery key leaked" row of
  the [compromise response](#compromise-response): rekey, rotate the recovery key
  (`ak secrets sync rotate-recovery`, which signs `recovery_rotate`), and rotate items
  if the bundle may have been taken, because an old file still opens an old bundle copy. Choose a new
  passphrase for any new backup; if the passphrase is known to be weak, treat the file
  as exposed.

If the passphrase, the paper kit, every device and the vault password are all lost,
the vault is unrecoverable by design; the service cannot rebuild a key.

## Lost home or all devices

A fresh device with the password or recovery key:

1. Fetches the recovery bundle and the membership log. Outside membership, it
   presents its own signing key in `AKV-Device-Key` and proves possession with
   `AKV-Proof`; the server releases only those two reads, only to the vault's owner
   account, and refuses a removed device ID (spec §3.5).
2. Decrypts the bundle: vault keys, owner anchor, the owner **recovery signing
   key**, and the newest owner-witnessed checkpoint. It verifies the membership
   chain from that anchor and checks the bundle's recovery key is the chain's
   current one and that the bundle holds the chain's current key epoch. A bundle
   sealed before the latest rekey cannot enroll: finish the stopped removal (rekey
   and reseal) on a device that still syncs first.
3. Wraps the vault keys it holds to itself, signs a `device_add` for itself with the
   recovery signing key and the digest of that wrap set, and enrolls; the server
   verifies the event against the current `recovery_sign_pub`.
4. As a member, removes the lost devices (`device_remove`; the recovery key itself
   may only author `device_add`), rekeys, and replaces the bundle with a new
   `bundle_seq`.
5. Pulls state and refuses anything older than, or forked from, the bundle's
   checkpoint.

Anyone holding an owner-account token can download the bundle ciphertext and try to
guess the password offline; Argon2id parameters and the 256-bit recovery key bound
that risk, so a weak password is the residual exposure. Refusing a removed device ID
does not stop a thief who still holds a live owner session from minting a token for
a new device ID, so after any loss the owner revokes all ak-web sessions first.

Local AgentKit state (grants, agent fingerprint trust) is device-local and is not
restored by sync; the user re-grants on the new device.

## Compromise response

| Event | Response |
|---|---|
| Device compromised | Revoke session/device, `device_remove`, rekey, rotate all `needs-rotate` items |
| Password or recovery key leaked | Rekey and replace both wraps and the bundle, then rotate the recovery key with `recovery_rotate` (`ak secrets sync rotate-recovery`), so the leaked key can no longer author `device_add`; rotate items if the attacker may also have obtained the bundle |
| Owner device compromised | As device compromised; the attacker could have signed membership events, so review the membership log from the last trusted checkpoint |
| Server compromised | Values stay encrypted; treat metadata as exposed; follow the [runbook](../operations/runbooks.md#incident-response) and rotate Worker secrets |
| Token signing key (ak-web JWKS) compromised | Owned by ak-web; Worker trusts only current JWKS keys after rotation ([runbooks](../operations/runbooks.md#key-rotation)) |
