# Key lifecycle and recovery

Behavior each client and the Worker must implement for keys, devices and members.
Key formats, wraps and event bodies are owned by the
[spec](../protocol/v1/spec.md#3-key-hierarchy); this page explains the flows and
what each one does and does not protect. Client implementation lives in AgentKit
(agentkit#2298, Desktop UX in agentkit#2300).

## Vault creation and TOFU

1. The first device generates its Ed25519 signing key and X25519 key, a vault ID
   and `VK[1]`.
2. It signs the `genesis` event naming itself owner, wraps `VK[1]` to itself, to the
   password KEK and to a new recovery key, and uploads the recovery bundle.
3. The genesis owner `sign_pub` becomes the **trust anchor**. A device that learns it
   only from the server is trusting on first use (TOFU); SAS enrollment or the
   recovery bundle removes that reliance.

The user must store the recovery key offline. Losing both the password and the
recovery key, with no surviving device, makes the vault unrecoverable by design.

## Device enrollment (SAS)

1. The new device generates its keys and presents its public keys.
2. An owner device and the new device each display a short authentication string
   (SAS) computed from the enrollment transcript; the user confirms they match.
3. The owner device signs `device_add` (with the SAS transcript digest), wraps the
   current vault key to the new device, and transfers its newest witnessed
   checkpoint over the SAS-verified channel.
4. The new device pins the owner anchor and that checkpoint.

Web login alone never enrolls a device. The SAS transcript format is not yet
defined in the spec (open item in [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md#open-items-before-approval)).

## Device loss or theft

1. Revoke the device's session and device ID in ak-web; the Worker refuses it on the
   next request through the live revocation check.
2. From a remaining owner device, sign `device_remove`. The vault enters
   `rekey_required`; writes are refused until rekey.
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
   `needs_rotate` item IDs.
3. New writes must use the new epoch. Items still encrypted under an older epoch stay
   readable by current members, who hold the older wraps, and move to the new epoch
   when next written. A device enrolled after a rekey also needs older-epoch keys
   for items not yet rewritten; the recovery bundle carries every epoch, but how
   `device_add` delivers older epochs is not yet specified.

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

## Password and parameter upgrade

- Changing the password re-wraps the current vault key under a new Argon2id KEK
  with a fresh salt and uploads a new recovery bundle.
- After an unlock under parameters weaker than the current defaults, the client
  re-wraps with the defaults ([spec §3.4](../protocol/v1/spec.md#34-password-and-recovery-wraps)).
  Verifiers refuse parameters below the published minimums, so a server cannot
  downgrade them.

## Recovery key

The recovery key unlocks the same recovery bundle as the password. Rotating it
creates a new recovery key, re-wraps, and replaces the bundle; the old key stops
working only once the old bundle is replaced, so treat a leaked recovery key as a
compromise (below).

## Lost home or all devices

A fresh device with the password or recovery key:

1. Fetches the recovery bundle. Outside membership, it presents its own signing key
   in `AKV-Device-Key` and proves possession with `AKV-Proof`; the server releases
   the bundle only to the vault's owner account and never to a removed device
   (spec §3.5).
2. Decrypts it: vault keys, owner anchor, the owner **recovery signing key**, and the
   newest owner-witnessed checkpoint.
3. Signs a `device_add` for itself with the recovery signing key and enrolls; the
   server verifies the event against `recovery_sign_pub` pinned at genesis.
4. Removes the lost devices (`device_remove`, also allowed for the recovery key),
   rekeys, and replaces the bundle with a new `bundle_seq`.
5. Pulls state and refuses anything older than, or forked from, the bundle's
   checkpoint.

Anyone holding an owner-account token can download the bundle ciphertext and try to
guess the password offline; Argon2id parameters and the 256-bit recovery key bound
that risk, so a weak password is the residual exposure.

Local AgentKit state (grants, agent fingerprint trust) is device-local and is not
restored by sync; the user re-grants on the new device.

## Compromise response

| Event | Response |
|---|---|
| Device compromised | Revoke session/device, `device_remove`, rekey, rotate all `needs-rotate` items |
| Password or recovery key leaked | Rekey and replace both wraps and the bundle; rotate items if the attacker may also have obtained the bundle |
| Owner device compromised | As device compromised; the attacker could have signed membership events, so review the membership log from the last trusted checkpoint |
| Server compromised | Values stay encrypted; treat metadata as exposed; follow the [runbook](../operations/runbooks.md#incident-response) and rotate Worker secrets |
| Token signing key (ak-web JWKS) compromised | Owned by ak-web; Worker trusts only current JWKS keys after rotation ([runbooks](../operations/runbooks.md#key-rotation)) |
