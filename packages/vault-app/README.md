# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only) and deletes items. It
never shows, copies or stores a value; tokens and vault keys stay in memory.

It also shows each item's rotation health and guides a provider credential
rotation: start, save the replacement value (write-only), then confirm the old
credential was revoked at the provider as a separate step, with pause, fail and
cancel. This is not a vault rekey. See
[Secret rotation](../../docs/security/key-lifecycle-and-recovery.md#secret-rotation).

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
