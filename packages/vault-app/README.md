# @ak-vault/vault-app

The vault dashboard served by the Worker at `/app` when remote access is on. The
browser is an enrolled akv1 device: it signs in to ak-web with OAuth 2.1 and PKCE
(client ID `<origin>/app/client.json`), exchanges that sign-in for a five-minute
device-bound sync token, and holds non-extractable WebCrypto Ed25519 and X25519
keys in IndexedDB. An owner device approves it with a SAS join code
(`ak secrets devices approve <join code>`).

It lists and searches metadata, sets values (write-only), deletes items and tracks
credential rotation. It never shows, copies or stores a value; tokens and vault
keys stay in memory.

## Credential rotation

Two things are called rotation and the dashboard keeps them apart. A **vault rekey**
advances `key_epoch` and re-encrypts items for the devices that remain; it changes
no provider credential. A **provider credential rotation** replaces the secret an
item holds and revokes the old one at the provider; only a person can do that, and
the Vault only tracks it.

Per item the dashboard shows one health state, in text and not only colour, in this
priority order: needs rotation (a rekey listed the item in `needs_rotate` and the
Vault holds no newer value), expired, overdue, failed, vault updated but old key not
confirmed revoked, paused, in progress, due soon, expires soon, on schedule, no
schedule. Due dates come only from signed metadata: `rotated_ms` (else `created_ms`)
plus `rotate_ttl_days`, and the profile's `expires_at`. Nothing is inferred when
those are absent, and nothing here grants or widens access.

A guided rotation has three separate states:

1. **Started**: the operator records the rotation (create the new credential at the
   provider outside any AI chat).
2. **Vault updated**: the new value is saved through the write-only form. This is
   derived, not clicked: it turns done only when the pulled, verified head carries a
   `rotated_ms` newer than the start (or than the rekey that listed the item).
3. **Old key revoked**: recorded only when the operator confirms it, after step 2.
   The Vault cannot check the provider, so the label says it is operator-confirmed.

An item can be paused, resumed or marked failed, and cancelled until step 2 is done.
An item rotated outside the dashboard (for example with the CLI) still shows
"old key not confirmed revoked" until the operator confirms it.

Progress is stored in the item's own metadata as a new signed, encrypted revision
(same value, `rotated_ms` unchanged), so it follows compare-and-swap, trust and role
rules: a concurrent edit is a conflict, never an overwrite, and a step that no longer
fits the item's state is refused. `meta.rotation` is `{state, started_ms,
updated_ms, revoked_ms?}` with `state` one of `in_progress`, `paused`, `failed`,
`revoked`; `meta.rotate_ttl_days` is an integer from 1 to 3650. Writers that do not
know these keys carry them forward, and a malformed `meta.rotation` is ignored.
There is no wire change.

Limits: members or devices removed earlier already saw the old value and rotation is
the only mitigation; the dashboard cannot read the old value back; it does not
rotate or revoke at any provider; and it appends no entry to the encrypted audit
stream, so the audit trail of a step is the signed revision (author device and
timestamp). The consumers listed on the item profile (`usage_hosts`, `projects`) are
a reminder, not an inventory the Vault enforces.

## Build

The deploy step runs no bundler, so the built files are committed:

```sh
pnpm --filter @ak-vault/vault-app build   # writes worker/public/app/
```

`test/build-staleness.test.ts` rebuilds in memory and fails when the committed
files differ from the source. Rebuild and commit them with every source change.
