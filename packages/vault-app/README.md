# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only) and deletes items. It
never shows, copies or stores a value; tokens and vault keys stay in memory.

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
