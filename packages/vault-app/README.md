# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only), deletes items and
shows each item's history. It never shows, copies or stores a value; tokens and
vault keys stay in memory.

## History, restore and conflicts

The history of an item is projected from the change log the browser already
verified (signatures, contiguity, removal fences, kept heads), not from server
ordering. Each entry shows metadata only: revision, device (a short ID, marked
this browser, current or removed), time, key epoch, deletion, conflict status.
Content this browser cannot open (a key epoch it was never given) is marked
`unavailable / unverified`. At most 200 entries per item are listed, 20 at a
time; older ones stay in the signed log.

- **Restore** writes the value of a readable earlier revision as a new revision:
  current key epoch, signed by this device, compare-and-swap on the verified
  head. A concurrent write turns it into a preserved conflict branch. Only the
  value is taken from the old revision; name, sensitivity and profile stay the
  current head's; the profile is the one this device verified (spec §5.1), so a
  field the check dropped, or could not examine, is not signed again. A deleted item, a deletion entry, a branch, a revision that
  already equals the current value, a value from before the item's latest
  deletion, and a value a since-removed device wrote or could hold (its key
  epoch is at or below the epoch current at the removal) are refused; a value
  the CLI marked `value_encoding: base64` keeps that marker, any other encoding
  is refused. The old value is opened and sealed
  again in memory and is never rendered, copied or logged: the dashboard already
  opens every live head the same way. It needs no device approval step.
- **Resolve** writes one new revision at the head that lists every open branch in
  `resolves`, keeping the current value or adopting one readable branch. Branches
  stay in the log. If any open branch is a deletion or cannot be read by this
  browser, resolving is refused for every choice and the user is pointed to
  `ak secrets sync settle`: nothing is dismissed unseen.
- Both ask for confirmation. Restoring a provider credential does not make it
  valid again; rotate or revoke it at the provider if it may be exposed.

It also shows each item's rotation health and guides a provider credential
rotation: start, save the replacement value (write-only), then confirm the old
credential was revoked at the provider as a separate step, with pause, fail and
cancel, and appends an encrypted audit entry for each state change (no name or value). This is not a vault rekey. See
[Secret rotation](../../docs/security/key-lifecycle-and-recovery.md#secret-rotation).

## Members and access

The Members screen is a read-only projection of the membership chain this browser
verified: members and their roles, each account's devices (this browser marked),
removed devices, the key epoch, a pending rekey and the items a removal flagged for
rotation. It also lists what this `browser` session can and cannot do. Accounts and
devices show only an 8-character prefix of their ID.

It never writes membership. The Worker refuses a `browser` session on every
membership POST, and ADR 0002 D1 limits browser enrollment to owner accounts, so
inviting, removing, changing a role and rekeying stay with an owner CLI device.
Protocol v1 has no pending-invitation state, so the screen says nothing is waiting
on the server. Write controls follow the verified role and a pending rekey; a write
the Worker refuses re-pulls the chain first, so a demoted role shows an explanation
and a removed device still shows the removed view.

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
