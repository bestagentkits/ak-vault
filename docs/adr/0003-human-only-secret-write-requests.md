# ADR 0003: Human-only secret write requests

- **Status:** Proposed
- **Proposed:** 2026-10-26
- **Builds on:** [ADR 0002](./0002-browser-device-relay-and-remote-mcp.md) (browser
  device, seal key, remote MCP). It adds no exception to the zero-knowledge boundary
  beyond the ones ADR 0002 scopes.
- **Tracking:** [#119](https://github.com/bestagentkits/ak-vault/issues/119), remote MCP
  [#101](https://github.com/bestagentkits/ak-vault/issues/101)
- **Wire contract:** [protocol v1 spec](../protocol/v1/spec.md) §9.9. This ADR records
  *why*; the spec owns *what goes on the wire*. If they disagree, the spec wins and
  this ADR is corrected.
- **Rollout:** behind `VAULT_REMOTE_ACCESS_ENABLED`, like the rest of remote access.

## Context

`secrets_set` (spec §9.8) takes the value as an MCP argument. That value is then in the
AI client's context and conversation transcript, at its model provider, and in Worker
memory (ADR 0002 D7). For the common case, an agent that needs a credential the user
holds, none of those parties needs the value: the agent needs only to know that the
secret now exists under a name it can use with `run`.

The vault already has an enrolled device that a human drives and that can encrypt and
sign on its own: the dashboard at `/app` (ADR 0002 D1). What is missing is a way for
the agent to ask the user to type a value there, and to learn the outcome, without the
value or a credential passing through the agent.

## Decision

1. **The agent asks; the user writes.** `secrets_prepare_write` takes a name, an
   operation (`create` or `replace`) and an optional sensitivity, never a value. It
   returns a request ID and a dashboard URL. `secrets_write_status` returns only the
   request's status. Both need `vault-mcp:write` and an `owner` or `editor` account,
   the same authority `secrets_set` needs.
2. **The browser device performs the write.** The user opens the URL, signs in as the
   enrolled browser device, sees the name and operation, and types the value. The
   browser writes an ordinary signed, encrypted item record through the existing item
   PUT. No new write path exists, so CAS, tombstones, conflicts and the signed log apply
   unchanged.
3. **The request ID is a lookup key, not a capability.** It rides in the URL fragment,
   which browsers send to no server and no `Referer`. Possessing it grants nothing:
   every browser call needs the `browser` sync token, live revocation, a single-use
   device proof and current `owner`/`editor` membership in the request's vault, and the
   request exists only in the asking account's relay object.
4. **The name is stored sealed.** The Worker seals the name to the vault's seal key with
   the existing sealed-op format (spec §3.6) and stores only that ciphertext. The browser
   opens it with the seal key it derives from the vault key. The format and primitives
   are unchanged, so there are no new vectors.
5. **The request binds one outcome.** It is bound to the asking grant and client;
   revoking the grant cancels it. A claim binds one device, item and base revision.
   Completion is read from the vault's durable head, not taken from the browser's word,
   and a moved head is a conflict. Requests expire, are capped per account, and are
   purged after a retention period ([`worker/src/limits.ts`](../../worker/src/limits.ts)).
6. **`secrets_set` stays.** It remains for low-sensitivity or non-interactive use; its
   description and the server instructions steer agents to `secrets_prepare_write` for
   real secrets.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Signed URL capability (a bearer link that authorizes the write) | The agent receives the link, so the agent holds the authority, and links leak through transcripts, history and screenshots. A lookup key plus device authentication keeps the authority with the enrolled browser. |
| Value or name in the URL (query or fragment) | Either would land in the agent's transcript, browser history and, for a query, server and proxy logs. |
| A Worker-served form that posts the value for the Worker to seal | Plaintext would transit Worker memory, widening ADR 0002 D7; the browser device already encrypts and signs on its own. |
| Name stored in the clear in the request | The server would store secret names, which data classification forbids. Sealing to the existing seal key costs nothing new. |
| Prompting on an online CLI device through the relay | The relay never prompts (spec §9.7), it needs a device online with a terminal, and it would add a new relayed tool. |
| Queueing the request as a sealed operation for any device to apply | A sealed operation applies without a human; the point is that a human enters the value. |

## Consequences

- REVIEW.md and AGENTS.md list `/v1/write-intents/*` and the two tools in the
  remote-access exception scope, with the auth above.
- New Worker state: a `write_intent` table in the account relay object, classified in
  [data classification](../security/data-classification.md).
- The agent no longer sees values it asks the user to store, but it still chooses the
  name and operation, so a hostile agent can send misleading requests; the user must
  read the form and trust the dashboard origin
  ([threat model](../security/threat-model.md#explicit-limitations)).
- The name still transits Worker memory in the MCP arguments, as any MCP argument does
  (ADR 0002 D7).
- The flow needs an enrolled browser device. v1 join codes enroll only owner-account
  devices (ADR 0002 D1), so an editor account can ask but cannot finish in the
  dashboard until it can enroll one.
- `queued` is a reserved status for a later write that waits for a device; nothing
  produces it.
