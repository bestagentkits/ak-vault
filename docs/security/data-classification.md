# Data classification

What the sync server can and cannot see. Field formats are owned by the
[spec](../protocol/v1/spec.md); this page owns the classification and the handling
rules. Rationale is in [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md) and, for
the browser device, relay and remote MCP, [ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md).

## Encrypted (server never stores plaintext; with remote access off it never sees any)

| Data | Protection |
|---|---|
| Secret value | Inside item ciphertext ([spec §3.2](../protocol/v1/spec.md#32-item-payload)) |
| Secret name | Inside item ciphertext; IDs are random and never derived from names |
| Description, tags, profile fields (`when_to_use`, URLs, provider, …) | Inside item `meta` ciphertext |
| Rotation interval, rotation workflow state and dates (`rotate_ttl_days`, `rotated_ms`, `rotation`) | Inside item `meta` ciphertext |
| Sensitivity class | Inside item ciphertext |
| Portable policy | Encrypted item with `meta.kind = "policy"` |
| Private audit entries | Encrypted audit stream ([spec §7](../protocol/v1/spec.md#7-encrypted-audit-stream)) |
| Vault keys | Wrapped to devices, password KEK and recovery KEK only |
| Recovery bundle contents (vault keys, owner anchor, checkpoint) | AEAD under password and recovery KEKs |
| Sealed operation contents (`op`, name, value, sensitivity) at rest | Sealed to the epoch's `seal_pub`; only member devices derive `SealSK[e]` ([spec §3.6](../protocol/v1/spec.md#36-seal-key-and-sealed-operations)). The Worker saw them in plaintext before sealing ([transit table](#transits-worker-memory-never-stored-or-logged-remote-access-only)) |
| Write intent contents (requested name, purpose, sensitivity) at rest | Sealed to the epoch's `seal_pub` under its own context; carries no value; cleared when the request closes, or lazily after it expires ([spec §3.10](../protocol/v1/spec.md#310-write-intents-human-write-requests)). The Worker saw them in plaintext before sealing |
| Value typed into a write-request form | Encrypted and signed by the browser device as a normal item record; never in the MCP client or Worker in plaintext |
| Value typed into an input-request form | Sealed in the browser to the issuing device's one-time `input_pub` ([spec §3.11](../protocol/v1/spec.md#311-input-seals-device-sealed-input-requests)); the Worker relays the ciphertext and never stores or logs it; the device writes it as a normal item record |
| Audit of drained sealed operations and dropped profile fields (`sealed_applied`, `sealed_refused`, `profile_invalid`, `profile_provenance_invalid`) and of dashboard rotation state changes (`rotation_*`: type, item ID, author device, time) | Encrypted audit stream |

## Visible operational metadata (unavoidable)

| Data | Why the server needs it |
|---|---|
| Opaque IDs: `vault_id`, `item_id`, `conflict_id`, event IDs | Routing, CAS and conflict tracking |
| Revisions, `base_revision`, change-log sequence and heads (hashes of stored record digests), cursors | CAS, incremental pull and removal fences |
| Tombstone flag | Refusing resurrection |
| `key_epoch`, `membership_epoch`, `rekey_required` | Refusing stale-epoch writes |
| Membership log in clear (signed): accounts, device IDs, device public keys, roles, device kind, `needs_rotate` item IDs, `device_remove.reason`, recovery signing public keys, removal and `role_set` `log_fence` positions and `log_head` values, `wraps_digest` values | Enforcing membership and roles; the recovery identity may read it |
| Wrap headers: recipient device ID, ephemeral public key, Argon2id salt and `t`/`m`/`p`; which membership event each device wrap set belongs to (kept after its recipients are removed) | Delivering the right wrap to each device and serving each signed set whole |
| Checkpoint fields (sequences, digests, author, timestamp) | Relayed to devices for anti-rollback |
| Timestamps and ciphertext sizes | Inherent to storage; sizes leak approximate value length |
| Token claims: `sub`, `sid`, `did`, `scope`, `jti`, `session_kind` (`email_otp`, `api_key_device`, `machine`, `browser`) | Authentication, authorization and revocation; `browser` restricts the dashboard device |
| MCP token claims: `sub`, `client_id`, `grant_id` (= `sid`), `scope`, `jti` | Authorizing and revoking an MCP grant |
| `name_tag` per record head (16-byte keyed tag and its `key_epoch`) | `lookup`; reveals which records share a name within an epoch, not the name ([spec §3.7](../protocol/v1/spec.md#37-name-tags-keyed-blind-index)) |
| Seal-key document (vault ID, key epoch, membership position, `seal_pub`, author, time, signature) | Serving the key the MCP handler seals to |
| Sealed operation envelope: `sealed_id`, key epoch, queue position, `origin` (`account`, `client_id`, `grant_id`), time, ciphertext size, the `iat` of the MCP token that queued it, and the `applied`/`refused`/`cancelled` outcome (`cancelled`: its grant was revoked) | Queueing, deduplication, expiry and audit attribution |
| Write request row: `request_id`, requesting `account`, `client_id`, `grant_id`, the MCP token's `iat`, operation (`create`/`replace`), state, closed reason, opaque receipt, created, expiry and close times, intent ciphertext size; for an input request also `flow` (`device`), the issuing `device_id` and its public `input_pub` (no intent, no name, no ciphertext) | Binding the request to its account and grant, revocation re-checks, single use, expiry and status for the requesting client; routing the one submission to the device that holds the key |
| `input` session token claims: `sub`, `sid`, `session_kind` (`input`), `jti` ([spec §3.11](../protocol/v1/spec.md#input-sessions-and-routes-worker)) | Binding the input form to the requesting account and revoking it with its sign-in grant |
| Lookup requests: the requested `(key_epoch, tag)` pairs and the hits served | Answering name lookups; reveals which names a reader looks for, not the names |
| Relay connection and call metadata: device ID, vault IDs and tool names from `hello`, `call_id`, vault ID and tool of each call, caller `client_id`/`grant_id`/scopes, result `ok` and error code, timing | Routing calls to a device and enforcing scopes, deadlines and rate limits |
| Quota and rate-limit counters | Abuse protection |
| Durable Object point-in-time bookmarks (operator restore route only) | Positions in a vault object's storage history; they carry no vault contents |
| Client IP and TLS metadata at the Cloudflare edge | Inherent to the platform |

`device_remove.reason` is a closed set (`lost`, `stolen`, `retired`,
`compromised`; [spec §4](../protocol/v1/spec.md#4-membership-log-owner-signed-hash-chained)),
so it carries no free text.

## Transits Worker memory, never stored or logged (remote access only)

While remote access is enabled (staging), these cross the Worker in plaintext after TLS
termination and are held only for the request or relayed call
([ADR 0002 D7](../adr/0002-browser-device-relay-and-remote-mcp.md#decision)):

| Data | Path |
|---|---|
| MCP tool arguments, including a `set` value | MCP client → Worker → relayed to a device or sealed |
| `secrets_prepare_write` name and purpose | MCP client → Worker → sealed into a write intent |
| `secrets_request_input` name and purpose | MCP client → Worker → relayed to the issuing device (`request_input`) and placed in the form link's fragment; never stored |
| Relayed results: names, profile fields, sensitivity, timestamps, request status | Device → Worker → MCP client |
| Redacted `run` output (`stdout`, `stderr`) | Device → Worker → MCP client |

The dashboard at `/app` decrypts in the browser, so its plaintext never reaches the
Worker; its traffic is the same ciphertext and metadata as any device. Its per-item
history, restore and conflict resolution add no field and no route: they read the
change log it already verifies and write ordinary signed records. A restored value
is opened and sealed again in browser memory and is never rendered, copied or sent
in clear.

Opening a write-request link (`/app#write=<request_id>&vault=<vault_id>`) keeps the two
opaque IDs in the browser's `sessionStorage` only for the sign-in redirect, and removes
them when the callback reads them. The request ID authorizes nothing by itself. The
dashboard never stores or logs the typed value, which is cleared on submit and cancel.

The input form (`/input`, served by the same bundle) is the one place a secret
**name** sits in browser storage: the link's name and purpose wait in
`sessionStorage` across the sign-in redirect. They are deleted when the callback, a new
input link or a dashboard load in that tab reads them, or when the tab closes; a
callback more than 10 minutes after the sign-in started is refused, but a tab left on
the sign-in page keeps them until one of those happens. The typed value is cleared from the field before it is sealed
and is never stored, logged or rendered; the `input` token stays in page memory.

## Kept in the browser (dashboard device)

The dashboard at `/app` is a device ([ADR 0002](../adr/0002-browser-device-relay-and-remote-mcp.md)),
so its browser keeps device state locally. Nothing below is a token, a vault key, a
name or a value.

| Data | Where | Why |
|---|---|---|
| Device keys: Ed25519 and X25519 as non-extractable `CryptoKey` objects, join nonce, device label | IndexedDB, one entry per account | The browser is the same device across visits; script cannot export the key bytes, only use them while the page runs |
| Enrollment: vault ID, trust anchor, offer checkpoint, approving device ID, SAS | Same entry | Verifying the chain from the offer, as every device does |
| Sync position: membership and log sequence numbers and heads, key epoch | Same entry | Anti-rollback and fork detection across visits and tabs; never a server value |
| Pending sign-in: `state`, PKCE verifier, creation time, and a write-request link's request and vault IDs | `sessionStorage`, removed when the callback reads it, refused after 10 minutes | Surviving the redirect to the authorization server |
| Pending input-form sign-in: the same, plus the input link's request and vault IDs, public `input_pub`, secret **name** and purpose (from the link fragment) | `sessionStorage` under its own key, removed when the callback reads it or a dashboard page loads, refused after 10 minutes; never sent to a server | Showing the request again after the redirect and binding the seal's AAD ([spec §3.11](../protocol/v1/spec.md#input-form-browser)) |
| Tokens, vault keys, item names, values, metadata, profile fields | Page memory only | Dropped on lock, sign-out and page exit; there is **no** local cache of vault contents, so every visit verifies from the server |

Clearing site data removes the device; an owner should then remove it from the
vault. IndexedDB is readable by script running in the page, which is why the
[strict CSP](./threat-model.md) matters.

## Handling rules

**Logs, traces and metrics**

- Never record request or response bodies, ciphertext, wrap material, tokens,
  proofs, idempotency keys, recovery bundles, or any field from the encrypted table.
  The same applies to MCP request and response bodies, relay frames, sealed
  operations, `name_tag` values and everything in the transit table above.
  The operator restore route's signature and the `VAULT_OPERATOR_SECRET` it is keyed
  with are secrets. Its bookmarks go on the incident issue, not into logs.
- Allowed fields: route template, status, stable error code, vault ID, device ID,
  latency, sizes; for MCP and the relay also tool name, `client_id`, relay close code
  and outcome. Item IDs appear only where the request path already carries them.
- Client IPs are not written to application logs. If a rate limiter keys on them,
  they stay inside its counters.
- Cloudflare platform invocation logs are disabled
  (`observability.logs.invocation_logs: false` in `worker/wrangler.jsonc`) because
  they record full request URLs and request metadata outside this contract. Only
  the Worker's own operational log lines are kept.
- `wrangler tail` and Tail Workers see every request's URL, client IP and headers.
  Cloudflare redacts a header only when its name contains `auth`, `key`, `secret`,
  `token` or `jwt` (or is a cookie), and long ID-like URL segments heuristically
  ([tail events](https://developers.cloudflare.com/workers/runtime-apis/handlers/tail/)),
  so `Authorization`, `Idempotency-Key` and `AKV-Device-Key` are hidden but `AKV-Proof` and `AKV-Webhook-Signature` are shown
  ([#61](https://github.com/bestagentkits/ak-vault/issues/61);
  [platform log scan](./red-team-evidence.md#platform-log-scan)). `wrangler tail`
  is a live view for account members with tail access and stores nothing. A Tail
  Worker, which this project does not configure, could store what it receives and
  can read headers unredacted.
- **Exception to the rule above (owner waiver, 2026-10-16):** proofs (`AKV-Proof`)
  and revocation webhook signatures (`AKV-Webhook-Signature`) are visible in the live
  tail to account operators with Workers Tail permission. This is accepted as
  account-operator access because each proof is single-use (`jti`) and bound to the
  token hash, method, URL and body within a ±60 s window, and each webhook signature
  covers one timestamped body with a single-use `event_id`
  ([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248)).
  Persisted logs, traces, analytics and the Durable Object dump showed none of them.
  **Complement named in the waiver:** grant Workers Tail permission on the
  production Worker's account only to the operators who need it (the production
  deploy token has none). The formerly shared token, still held by the `staging`
  environment and the operator, stays in scope: Cloudflare cannot scope it to one
  Worker. The owner confirmed on 2026-10-16 that Workers Tail access on production
  is restricted ([record on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235)); agents did not inspect the account, so this
  rests on the owner's statement. Do not attach a Tail Worker or Logpush job
  that stores request headers. Renaming the headers so the platform
  redacts them remains open as hardening
  ([#61](https://github.com/bestagentkits/ak-vault/issues/61)).

**Errors**

- Responses use the stable `{"error":{"code","message"}}` shape
  ([spec §10](../protocol/v1/spec.md#10-errors-and-limits)); messages never echo
  bodies, tokens, names or item IDs beyond the path.
- Internal exceptions are mapped to a code before leaving the Worker; stack traces
  are not returned.

**Dumps, backups and exports**

- A Durable Object dump or backup is ciphertext plus the visible metadata above. It
  is still treated as confidential: it reveals membership and usage patterns.
- The release gate requires a dump/log scan with planted plaintext and names that
  finds nothing ([release gates](./release-gates.md)).

**Retention**

- Tombstones are kept for the life of the vault; deleting one would re-open
  resurrection.
- Conflict branches are kept until a record resolves them.
- A write request's intent ciphertext is cleared when it closes. Expiry and purge are
  lazy: an expired request is never served, and its ciphertext is cleared (and rows
  closed more than `write_request_retention_s` ago are purged) the next time the
  vault handles a write request
  ([`worker/src/limits.ts`](../../worker/src/limits.ts)). The row holds no name or
  value.
- Membership events are kept for the life of the vault; the chain is replayed
  from genesis or from a trusted checkpoint.
- Change-log compaction, audit retention and operational-log retention periods are
  not yet decided. Until they are, nothing is compacted and operational-log
  retention is whatever the Cloudflare account is configured for. The decision
  belongs in this file once made.
- Deleting a vault removes its Durable Object storage; point-in-time recovery
  bookmarks expire on the platform's schedule
  ([runbooks](../operations/runbooks.md#durable-object-backup-and-restore)).

**Fixtures and CI**

- Test vectors and fixtures use synthetic values only. No real token, key, account
  identifier or personal data is committed.
