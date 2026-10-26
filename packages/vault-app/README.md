# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only) and deletes items. It
never shows, copies or stores a value; tokens and vault keys stay in memory.

## History, restore and conflicts

`History` on an item rebuilds its revisions from the whole change log, verified
from position 1 like the vault pull (membership, removal fences, the head this
browser witnessed, and the server's conflict labels against a local replay). It
lists revision, signing device, claimed time, key epoch, tombstones and conflict
branches, and shows an entry this browser cannot authenticate as `unavailable` or
`unverified`. It never shows a value. The server can still withhold the newest
entries; the page says so.

`Restore` writes an earlier revision's value as a new revision on the verified
head, under the current key epoch, after an explicit confirmation. It goes through
the same write authorization as `set`, so a concurrent write becomes a conflict
branch instead of being overwritten, and a deleted item or a revision from before
its deletion is never offered. The old value is decrypted, re-sealed and dropped
inside the write; it is not rendered, copied or stored, so the no-reveal rule
holds. Restoring an old provider credential does not make it valid or safe again.

An open conflict can be settled with one confirmed new revision that keeps the
current value or adopts one branch's value; every open branch is listed in
`resolves` and all branches stay in the log until then. `ak secrets sync settle`
does the same from a terminal and is the route when this browser cannot read a
branch.

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
