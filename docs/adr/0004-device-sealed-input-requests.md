# ADR 0004: Device-sealed input requests for accounts without a browser device

- **Status:** Accepted. An agent drafted it on the AgentKit v3 run's instruction; the
  owner approved it as written on 2026-10-30 (owner instruction in the orchestrator
  chat, relayed and recorded by an agent on the owner's behalf,
  [record on #203](https://github.com/bestagentkits/ak-vault/issues/203)).
- **Proposed:** 2026-10-30
- **Amends:** [ADR 0002](./0002-browser-device-relay-and-remote-mcp.md) D8 (human write
  requests), which today needs an enrolled browser device. On acceptance and
  implementation it **widens** the new-endpoint row of the [REVIEW.md](../../REVIEW.md)
  hard rejection criteria, the remote-access exceptions in
  [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable) and the session kinds of
  [spec §9 item 1](../protocol/v1/spec.md#9-transport-authentication-worker). Those change
  in the implementation pull requests, with the spec section and vectors, not here.
- **Tracking:** [#203](https://github.com/bestagentkits/ak-vault/issues/203); device half
  in agentkit's relay; sign-in token in ak-web; parent epic
  [agentkit#2848](https://github.com/bestagentkits/agentkit/issues/2848)
- **Wire contract:** none yet. This ADR fixes the shape (below); the spec section that
  implements it owns the wire and wins if they disagree.

## Context

D8 keeps a secret out of the AI's context: `secrets_prepare_write` returns a one-time
`/app` link, and an **enrolled browser device** opens the sealed intent and writes the
record. A user who never enrolled a browser (CLI-only users, the common case for
hosted agents) cannot complete it, so the AI falls back to asking for the value in
chat, which D8 exists to prevent.

ADR 0002 rejected a write link that is a bearer capability. That rejection stands: this
ADR adds a flow in which the link is bound to the requesting account's signed-in
session, and the value is sealed to a key that only the online device holds.

## Decision

1. **D1: one MCP tool, two flows.** `secrets_request_input` takes the same arguments as
   `secrets_prepare_write` (name, operation, purpose, sensitivity, ttl_s, vault_id) and
   needs `vault-mcp:write`. When the requesting account has a current `browser` device
   in the vault and the epoch's seal-key document is stored, it **is**
   `secrets_prepare_write` (D8, unchanged) and says `flow: "dashboard"`. Otherwise it
   uses the device-sealed flow below and says `flow: "device"`. With neither (no
   browser device and no online device of that account listing the tool) it fails
   `device_offline`; it never asks for the value.
2. **D2: the online device holds the only key.** The Worker sends the account's online
   device a relay `call` for tool `request_input`. The device checks the operation
   against its own view (`create` needs an absent name, `replace` an existing one),
   generates a fresh X25519 keypair for this request, keeps the private half **in
   memory only** until the request completes or expires, and answers a signed result
   with the public half. A device restart drops the key; the request then fails on
   delivery and the AI asks again.
3. **D3: the link carries a public key, not a capability.** The Worker stores the
   request (request ID, vault, account, device ID, the device's input public key,
   client, grant, operation, state, times) and returns
   `form_url = <origin>/input#<fragment>`. The fragment holds the request ID, vault ID,
   the input public key, and the name and purpose for display. Browsers do not send
   fragments to the server. Opening the form requires the requesting account's
   signed-in session: ak-web mints a short-lived vault token of a new session kind
   `input` (no device key, no proof), and the Worker accepts that kind **only** on the
   two input-request routes, only for the token's own account, and for no other
   route. The request ID authorizes nothing on its own; a link sent to another
   account is refused.
4. **D4: seal with explicit AAD.** The page seals the value with the spec's existing
   primitives (X25519, HKDF-SHA-256, XChaCha20-Poly1305, §3.1 and §3.3), not a
   libsodium sealed box, because a sealed box takes no AAD:

   ```
   esk, epk = fresh X25519 keypair
   shared   = X25519(esk, input_pub)                    ; reject all-zero output
   key      = HKDF(ikm=shared, salt=epk || input_pub, info=utf8("akv1/input-seal"), L=32)
   aad      = {"ctx":"akv1/input-seal","request_id","vault_id","account","device_id",
               "name","purpose"|null,"operation","expires_at"}
   pt       = cjson({"value":…,"sensitivity"?:"normal"|"high"})
   wire     = {"v":1,"alg":"x25519-xc20p-input","request_id","epk","n","ct"}
   ```

   The device rebuilds the AAD from what **it** recorded at D2, so a fragment edited to
   show another name or purpose, a request replayed to another device or account, and
   a ciphertext moved to another request all fail `decrypt_failed`. The HKDF `info` and
   AAD `ctx` are new, so an input seal never opens as a write intent or sealed
   operation, or the reverse.
5. **D5: single use, no ciphertext at rest.** `POST` of the sealed value marks the
   request `submitted` in the same vault-object transaction that accepts it, so a
   second submission is refused. The Worker relays the ciphertext to the recorded
   device in a `call` for tool `input_deliver` and never stores it. If that device is
   offline at submission the POST is refused (`device_offline`) and the request stays
   `pending_user`. The device writes a normal signed record with an item PUT that names
   the request, and the Worker completes the request in the same transaction as that
   PUT, as D8 does. Expiry is the D8 lifetime (`write_request_ttl_s`, 10 minutes) and
   counts against the same per-account and per-client caps.
6. **D6: the AI sees only a state.** `secrets_write_status` serves both flows: the
   states and receipts of spec §3.10, never the value, name or ciphertext.

### Device contract (agentkit relay)

The agentkit session that builds the device half implements exactly this; the spec
section will restate it normatively.

- **Advertise.** `hello.tools` lists `request_input` and `input_deliver` only on a
  device that implements both. A device that lists neither never gets these calls.
- **`call` tool `request_input`.** `args` =
  `{"request_id":<b64 16B>,"name","purpose"?,"operation":"create"|"replace","sensitivity"?,"expires_at":unix_ms}`
  (`caller` as in §9.7, needs `vault-mcp:write`). The device refuses with
  `error.code`: `denied` (scope, or the device's own grants), `conflict` (operation
  against its view), `bad_request` (shape), `rate_limited` (more than its own cap of
  held input keys; suggested 8). On success it records `{request_id, vault_id,
  account = token sub, device_id, name, purpose, operation, expires_at, input_sk}` in
  memory and answers `result` = `{"request_id","input_pub":<b64 32B>}`, signed as
  every relay result (`akv1/relay-result`).
- **`call` tool `input_deliver`.** `args` =
  `{"request_id","sealed":{"v":1,"alg":"x25519-xc20p-input","request_id","epk","n","ct"}}`.
  The device looks up the held key and, in order, refuses: `unknown_request` (no held
  key: restarted, completed or never issued), `expired` (now ≥ `expires_at`; it also
  drops the key), `unsupported_version` (`v`/`alg`), `bad_request` (shape, mismatched
  `request_id`, all-zero shared secret), `decrypt_failed` (AEAD under the rebuilt
  AAD), `bad_request` (plaintext not canonical, unknown keys, value over the item
  limit). Then it drops the key **before** writing (single use on the device too),
  writes the record with `PUT …/items/{id}?input_request=<request_id>`, and answers
  `{"status":"stored","receipt":<the Worker's receipt from the PUT>}` or
  `error.code` `conflict` when the PUT loses a compare-and-swap. The value is never
  logged, returned or kept after the write.

### Implementation notes

The spec ([§3.11](../protocol/v1/spec.md#311-input-seals-device-sealed-input-requests))
owns the wire. Where the implementation made a choice this ADR left open:

- **D1 order.** The Worker has no record of which devices are browsers, so
  `secrets_request_input` tries the device-sealed flow first and falls back to the D8
  dashboard flow when no online device of the account lists the input tools; with no
  seal-key document either it fails `device_offline`. The device flow keeps the key
  in one device for ten minutes, narrower than D8's `VK[e]`.
- **D3 token.** The `input` token is a vault token with its own audience
  `<origin>/input`, so no sync, relay or MCP route can accept it even before its
  `session_kind` is read. Claims, lifetime and revocation are in the spec.
- **`/input` page.** `GET /input` is a redirect to `/app/`; the browser carries the
  fragment across it, and the dashboard bundle runs the form under the `/app` CSP with
  the dashboard's OAuth client, so no new client or redirect URI is registered.
- **Rollout.** The input routes and the device flow are off unless
  `VAULT_INPUT_REQUESTS_ENABLED` is `true`. They stay off until ak-web mints `input`
  tokens and the `/input` page ships; until then the tool behaves as D8.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Bearer link (the fragment key alone authorizes the submission) | Rejected by ADR 0002 and still rejected: anyone holding a leaked link could plant a value. |
| libsodium `crypto_box_seal` | No AAD, so a ciphertext could be moved between requests; it also adds a construction the spec does not use. |
| Seal to the epoch seal key (D8's key) instead of a per-request device key | Any holder of `VK[e]` could open it later; a per-request key held in one device's memory narrows that to one device for ten minutes. |
| Store the ciphertext until a device comes online | Adds plaintext-equivalent material at rest tied to a key that dies with the device process; refusing while offline is simpler and honest. |
| Store the name server-side for the form | Contradicts zero-knowledge storage (ADR 0002 rejected it for D8); the fragment shows it and the device's AAD binds it. |
| Reuse the `browser` session kind for the form | That kind implies an enrolled device key and proof; a separate `input` kind keeps the new, weaker session confined to two routes. |

## Consequences

- New routes, both behind the `input` session of the requesting account and the
  remote-access flag: `GET /v1/vaults/:vid/input-requests/:rid` (state, operation,
  requesting client and expiry for the form) and
  `POST /v1/vaults/:vid/input-requests/:rid` (the sealed value). New static page
  `/input` under the `/app` CSP. New item PUT parameter `?input_request=`.
- ak-web mints `input` session tokens for a signed-in account; the Worker never
  receives the CLI signing key.
- New vectors: the seal (fixed `esk`, nonce, key), every AAD field change failing,
  and the `alg`/`ctx` separation from write intents and sealed operations, reproduced
  in TypeScript and Go.
- The threat model gains the residual risks below; D7's honest boundary is unchanged.

## Residual risks

- **A live compromised Worker builds the link.** It could put its own public key in
  the fragment and read the value, or serve a hostile `/input` page. This is the D7
  boundary (the Worker already sees `secrets_set` values in memory) and the D1 XSS
  risk; the flow protects against the AI context, storage dumps and leaked links, not
  against a live compromised Worker. The page cannot verify the device's signature
  because it holds no vault chain.
- **The fragment is in browser history.** It holds the name, purpose and a public key,
  never the value; the request is single use and expires in at most ten minutes.
- **The form shows what the AI chose**, as in D8; it shows the requesting client, and
  `create` refuses an existing name.
- **The device must stay online** from the request to the submission; a restart in
  between fails the request with `unknown_request`.
