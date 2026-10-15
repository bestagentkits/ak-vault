# Data classification

What the sync server can and cannot see. Field formats are owned by the
[spec](../protocol/v1/spec.md); this page owns the classification and the handling
rules. Rationale is in [ADR 0001](../adr/0001-opt-in-zero-knowledge-sync.md).

## Encrypted (server never sees plaintext)

| Data | Protection |
|---|---|
| Secret value | Inside item ciphertext ([spec §3.2](../protocol/v1/spec.md#32-item-payload)) |
| Secret name | Inside item ciphertext; IDs are random and never derived from names |
| Description, tags, profile fields (`when_to_use`, URLs, provider, …) | Inside item `meta` ciphertext |
| Sensitivity class | Inside item ciphertext |
| Portable policy | Encrypted item with `meta.kind = "policy"` |
| Private audit entries | Encrypted audit stream ([spec §7](../protocol/v1/spec.md#7-encrypted-audit-stream)) |
| Vault keys | Wrapped to devices, password KEK and recovery KEK only |
| Recovery bundle contents (vault keys, owner anchor, checkpoint) | AEAD under password and recovery KEKs |

## Visible operational metadata (unavoidable)

| Data | Why the server needs it |
|---|---|
| Opaque IDs: `vault_id`, `item_id`, `conflict_id`, event IDs | Routing, CAS and conflict tracking |
| Revisions, `base_revision`, change-log sequence and heads (hashes of stored record digests), cursors | CAS, incremental pull and removal fences |
| Tombstone flag | Refusing resurrection |
| `key_epoch`, `membership_epoch`, `rekey_required` | Refusing stale-epoch writes |
| Membership log in clear (signed): accounts, device IDs, device public keys, roles, device kind, `needs_rotate` item IDs, `device_remove.reason`, recovery signing public keys, removal `log_fence` positions and `log_head` values, `wraps_digest` values | Enforcing membership and roles; the recovery identity may read it |
| Wrap headers: recipient device ID, ephemeral public key, Argon2id salt and `t`/`m`/`p`; which membership event each device wrap set belongs to (kept after its recipients are removed) | Delivering the right wrap to each device and serving each signed set whole |
| Checkpoint fields (sequences, digests, author, timestamp) | Relayed to devices for anti-rollback |
| Timestamps and ciphertext sizes | Inherent to storage; sizes leak approximate value length |
| Token claims: `sub`, `sid`, `did`, `scope`, `jti` | Authentication, authorization and revocation |
| Quota and rate-limit counters | Abuse protection |
| Client IP and TLS metadata at the Cloudflare edge | Inherent to the platform |

`device_remove.reason` is a closed set (`lost`, `stolen`, `retired`,
`compromised`; [spec §4](../protocol/v1/spec.md#4-membership-log-owner-signed-hash-chained)),
so it carries no free text.

## Handling rules

**Logs, traces and metrics**

- Never record request or response bodies, ciphertext, wrap material, tokens,
  proofs, idempotency keys, recovery bundles, or any field from the encrypted table.
- Allowed fields: route template, status, stable error code, vault ID, device ID,
  latency, sizes. Item IDs appear only where the request path already carries them.
- Client IPs are not written to application logs. If a rate limiter keys on them,
  they stay inside its counters.
- Cloudflare platform invocation logs are disabled
  (`observability.logs.invocation_logs: false` in `worker/wrangler.jsonc`) because
  they record full request URLs and request metadata outside this contract. Only
  the Worker's own operational log lines are kept.

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
