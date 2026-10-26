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
  current head's. A deleted item, a deletion entry, a branch or a revision that
  already equals the current value is refused. The old value is opened and sealed
  again in memory and is never rendered, copied or logged: the dashboard already
  opens every live head the same way. It needs no device approval step.
- **Resolve** writes one new revision at the head that lists every open branch in
  `resolves`, keeping the current value or adopting one readable branch. Branches
  stay in the log. Deletion branches and branches this browser cannot read are
  left to `ak secrets sync settle`.
- Both ask for confirmation. Restoring a provider credential does not make it
  valid again; rotate or revoke it at the provider if it may be exposed.

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
