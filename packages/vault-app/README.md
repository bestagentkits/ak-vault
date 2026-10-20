# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only) and deletes items. It
never shows, copies or stores a value; tokens and vault keys stay in memory.

## Sync

A visit's first pull verifies the whole membership chain and change log. Later
pulls in the same visit (after a write or a refresh) fetch only the log entries
after the cursor this browser computed itself, and repeat the full replay when
anything does not line up. The verified position is saved by one IndexedDB
transaction that never stores an older position; a position reached again with a
different head is shown as an integrity alarm. A device clock more than 60 seconds
from the vault's `Date` header is reported as such. What the browser keeps locally
is listed in [data classification](../../docs/security/data-classification.md).

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
