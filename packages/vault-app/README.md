# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only) and deletes items. It
never shows, copies or stores a value; tokens and vault keys stay in memory.

The **Vault access** tab shows members, roles, devices, key epoch, rekey and
needs-rotate state and what this browser session can do. It is derived only from
the membership chain this browser verified (no extra request, no server-supplied
list) and has no action that posts a membership event: member add, removal, role
change and rekey need an owner device, and the Worker refuses them from a
`browser` session. v1 has no invitation state, so none is shown. A 403 on a write
re-pulls the chain, so a changed role shows as a read-only view and a removal ends
at the removed screen; the two are never confused.

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
