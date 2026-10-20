# ADR 0002: Browser device, device relay and remote MCP

- **Status:** Proposed
- **Proposed:** 2026-10-19
- **Amends:** [ADR 0001](./0001-opt-in-zero-knowledge-sync.md), which rejected web
  decryption ([Alternatives rejected](./0001-opt-in-zero-knowledge-sync.md#alternatives-rejected)).
  This ADR narrows that rejection; it does not reverse any other ADR 0001 decision.
- **Tracking:** remote MCP [#101](https://github.com/bestagentkits/ak-vault/issues/101),
  web dashboard [ak-web#628](https://github.com/bestagentkits/ak-web/issues/628), parent
  epic [#1](https://github.com/bestagentkits/ak-vault/issues/1); profile, describe,
  request and run [agentkit#2299](https://github.com/bestagentkits/agentkit/issues/2299)
- **Wire contract:** [protocol v1 spec](../protocol/v1/spec.md) §3.6–§3.8, §5.1,
  §9 item 1, §9.6, §9.7 and §10. This ADR records *why*; the spec owns *what goes on
  the wire*. If they disagree, the spec wins and this ADR is corrected.
- **Rollout:** staging only, behind `VAULT_REMOTE_ACCESS_ENABLED` (Worker) and the
  ak-web flag of the same name. Production stays dark until a later decision.

## Context

ADR 0001 kept every decryption on CLI devices and listed web decryption as rejected.
On 2026-10-19 the owner reversed the epic non-goal "web decryption" for metadata and
writes ([ak-web#628](https://github.com/bestagentkits/ak-web/issues/628)): users want a
web dashboard to browse and edit their vault, and remote MCP clients (hosted agents)
want to search, describe, set and use secrets without a local CLI
([#101](https://github.com/bestagentkits/ak-vault/issues/101)).

Constraints that stay in force: the server stores no plaintext and holds no vault key;
no server-held key or KMS; no raw value reveal to MCP; membership stays owner-signed;
old clients keep verifying every chain they verify today.

## Decision

1. **D1: the browser is an enrolled akv1 device.** The dashboard at `/app` generates
   its own device keys and joins like any device: it produces a join code (`akj1-`,
   spec §3.8) and an existing owner device approves it with SAS
   (`ak secrets devices approve`). Its device record is kind `human` with its
   account's role (`owner` in a personal vault, because spec §11 requires device role
   = account role). Its sync tokens carry the new session kind `browser`, and the
   Worker refuses a `browser` session on genesis, every membership POST, the recovery
   bundle, recovery-identity reads, seal-key publication and the sealed queue
   (spec §9 item 1), and on the relay: the dashboard never answers relay calls. The
   spec's role rule is unchanged. Because v1 join codes enroll only devices of an
   account that owns the vault (spec §3.8), the dashboard is available to vault
   owners; an editor account in a shared vault cannot enroll a browser in v1.
2. **D2: seal key and sealed operations.** Each key epoch has an X25519 seal keypair
   derived from `VK[e]` with HKDF (`akv1/seal-key`). An owner device publishes its
   public half in an owner-signed seal-key document stored beside the vault, not as a
   membership event, so old clients keep verifying the chain. When no device is
   online, the Worker's MCP handler seals a set or delete to that key, but only for
   an account that may write the vault and never while a rekey is pending. The
   operation names the requesting account inside its AAD and queues in the vault
   Durable Object until an opted-in device of that same account drains it into a
   normal signed record. A race is a normal conflict branch (spec §3.6). The seal
   protects queued operations at rest (a later dump or storage leak); it does not
   hide them from a live Worker, which saw the plaintext before sealing (D7).
3. **D3: keyed blind index, device-computed.** Devices send a 16-byte HKDF name tag
   (`akv1/name-tag`, keyed per epoch) beside, not inside, each signed record, and
   `GET /v1/vaults/{vid}/lookup` matches tags. The Worker never holds the index key,
   so it cannot compute a tag for a name it is given. Consequence: with no device
   online, MCP read tools answer `no_device_online` and writes fall back to sealing
   (spec §3.7).
4. **D4: device relay.** Each account has one relay Durable Object (`AccountRelay`).
   A CLI device opts in by holding `GET /v1/relay` open (planned as
   `ak secrets sync now --watch --relay`; the flag does not exist yet). Frames are a
   closed `cjson` set; the device signs `hello` and every `result` with its device
   key; it re-authenticates before its 300 s token expires; the server checks
   revocation and vault membership before every call. The device decrypts, applies its
   own grants, approvals and redaction, and answers (spec §9.7).
5. **D5: profile on the wire.** `meta.profile` is a closed field set; every field
   carries `{value, by, at, src}`. A changed field must name the record author and
   time; an unchanged field keeps its prior provenance. A violating field is dropped
   and audited, and a field another device wrote is shown as `sync` (untrusted).
   The own/local label comes only from the device's own write history: a field is
   its own only if this device wrote it in a record it authored, or carried it
   unchanged with a stored origin (`prevOrigins`) of that same label. Any field kept
   under `prev = null` stays `sync` while it is carried unchanged.
   Profile never widens a grant. This lifts the agentkit#2299 profile decision
   (approved 2026-10-16) onto the wire (spec §5.1).
6. **D6: OAuth resources and token contracts.** ak-web derives two resources from
   `VAULT_TOKEN_AUDIENCE` (`<aud>`, the vault origin that is already the sync tokens'
   audience, spec §9 item 1; the spec writes it `<origin>`). The `/mcp` wire contract
   is spec §9.8:
   - `<aud>/mcp`, scopes `vault-mcp:read`, `vault-mcp:write`, `vault-mcp:use`. The
     access token is ES256 `at+jwt` with exactly `iss`, `aud` = `<aud>/mcp`, `sub`,
     `client_id`, `grant_id`, `sid` = `grant_id`, `scope`, `jti`, `iat`, `nbf`, `exp`
     (at most `iat + 600`). It has no `did` and no `session_kind`, and the `/v1`
     routes refuse it. Only the Worker's `/mcp` endpoint accepts it.
   - `<aud>/app`, scope `vault-app:session`. Same claim set with `aud` =
     `<aud>/app`. Only ak-web's vault token route accepts it, and only to exchange
     it for a sync token bound to the browser device: the usual sync claims plus
     `session_kind` `browser`, TTL 300 s.

   `sid` = `grant_id`, so revoking a grant reuses the existing revocation webhook's
   `sids` list. `/mcp` speaks MCP 2026-07-28
   ([versioning](https://modelcontextprotocol.io/specification/versioning); stateless
   Streamable HTTP, POST only, `server/discover`, `MCP-Protocol-Version` required) and
   also answers 2025-11-25
   `initialize` statelessly, never issuing `Mcp-Session-Id`. It publishes RFC 9728
   protected-resource metadata at `/.well-known/oauth-protected-resource/mcp`; ak-web
   remains the authorization server (PKCE S256, RFC 8707 `resource`, client ID
   metadata documents preferred, dynamic registration kept but not required).
7. **D7: honest boundary.** The Worker stores no plaintext and holds no keys, but
   plaintext transits Worker memory after TLS termination: the `value` argument of an
   MCP set (until it is sealed or relayed), and relayed metadata results (names,
   profile fields, redacted run output) on their way to the MCP client. MCP clients
   do not verify device signatures, so they trust the Worker for what a result says. It is never
   logged, stored or put into an error. The threat model, the consent screen and the
   vault guide state this boundary.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Browser holding only a seal key | No readable metadata, search or edit; the dashboard would be write-only. |
| Worker-held index key (server-computed name tags) | A server-held key, out of scope; it would let the server confirm guessed names offline. |
| Server-held cloud agent key or KMS | Contradicts ADR 0001's zero-knowledge storage; out of scope. |
| Dynamic client registration as the only client path | Deprecated in MCP 2026-07-28; client ID metadata documents are preferred. |
| Browser device with an `editor` role in a personal vault | Needs a change to the spec §11 role rule; the `browser` session kind restricts the device instead. |
| A new membership event type for the seal key | Old clients would refuse the chain; a separate signed document keeps them verifying. |
| Raw value reveal over MCP | Not requested; `run` with device-side redaction covers use without reveal. |

## Consequences

- REVIEW.md hard-rejection rows get an explicit exception scope, owned here:
  - "web decryption": allowed only in the enrolled browser device at `/app`, which is
    static assets under a strict CSP (`script-src 'self'`, SRI, no third-party code).
    Server-side decryption and server-held keys stay rejected.
  - "new endpoint without shared auth": `/app` and
    `/.well-known/oauth-protected-resource/mcp` are static or public metadata like
    the landing page and `/v1/meta`. `/mcp` verifies the MCP token, live revocation
    by `sid` and the account's vault membership; it has no device proof because MCP
    clients hold no device key. `/v1/relay` and the §9.6 routes run the shared token,
    revocation, proof and membership pipeline.
  - "no code path may need server-side plaintext": narrowed to "no code path stores,
    logs or decrypts plaintext on the server"; the D7 transit is the only exception.

  REVIEW.md and AGENTS.md must carry these exception scopes before any implementation
  of this ADR merges.
- The guarantee "the server never sees plaintext" narrows to "the server never stores
  plaintext or holds a key" for accounts that use remote MCP (D7).
- Offline MCP is write-only by sealing; reads need an online opted-in device (D3).
- The seal-key document, sealed queue, name tags, profile layout, `browser` session
  kind, relay and their limits are additive: no membership type, signed-record field
  or existing body changes meaning (spec Revisions).
- New Worker state: an `AccountRelay` Durable Object class and a sealed queue and tag
  index inside the vault object.

## Residual risks

- **Browser XSS = vault compromise for that device.** The browser holds an owner-role
  device key and decrypts in page memory. Mitigations: strict CSP, SRI, no
  third-party code, a separate origin from ak-web, and the `browser` session kind.
- **Offline signing by the browser key.** The session kind stops the Worker from
  accepting membership or recovery changes from a browser session, but the key could
  still sign a membership event that another channel delivers. Removing the browser
  device and rekeying is the response.
- **A compromised Worker can forge relay calls and sealed operations** for devices
  that opted in, within the MCP scopes it fakes, and can answer an MCP client with
  anything, since the client does not verify device signatures. Devices still apply their own grants
  and approvals, `run` needs a pinned `exec` grant, and every drained operation is a
  normal signed record with an audit entry. Device-side verification of the MCP token
  is not in scope.
- **Name-tag leakage.** The server learns which records share a name within an epoch
  and across that epoch's revisions (spec §3.7).
- **Run output redaction is literal.** The device removes exact released values from
  `run` output; a command that prints a value encoded, split or partially still leaks
  it to the MCP client.

## Compatibility

Clients that predate this ADR ignore the seal-key document, the sealed queue, name
tags and the relay; a bare record PUT keeps working. They do not carry
`meta.profile` forward, so an edit by an old client drops that item's synced profile.
A pre-existing `meta.profile` that fails the §5.1 checks is dropped by new readers, not
by the server.
