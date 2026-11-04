# ADR 0006: Remote approval of secret-access requests

- **Status:** Proposed. An agent drafted it; the owner has not approved it.
- **Proposed:** 2026-11-04
- **Amends:** the new-endpoint row of the [REVIEW.md](../../REVIEW.md) hard rejection
  criteria and the remote-access route list in
  [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable), both widened in the same
  pull request by the `approval-requests` routes only.
- **Tracking:** [#230](https://github.com/bestagentkits/ak-vault/issues/230); CLI half [agentkit#2995](https://github.com/bestagentkits/agentkit/issues/2995)
- **Wire contract:** [spec §3.13](../protocol/v1/spec.md#313-access-approvals-remote-approval-of-a-secret-use),
  the routes in §9.6 and the MCP tools in §9.8. The spec wins if they disagree.

## Context

When an agent asks a device for a secret it has no grant for, the device asks the
person at its own terminal. A person away from that machine (a long hosted run, a
background job, a phone in hand) cannot answer, so the run stalls or the person widens a
grant in advance. We want them to answer from any of their enrolled devices, the
dashboard or a remote MCP client, without weakening local approval.

## Decision

1. **D1: A request is a signed, sealed object.** The requesting device signs it with its
   device key; the subject (secret name, agent, fingerprint, project, purpose, reason,
   longest allowed TTL) is sealed under HKDF(VK[e]). The server sees no name, agent or
   project, and no value ever travels on the channel.
2. **D2: Only an enrolled human device allows.** A decision (`deny`, `allow_once`,
   `allow_ttl` with `ttl_s ≤ max_ttl_s`) is signed by a human `owner`/`editor` device of
   the same account other than the requester and names the request by digest. Remote
   approval is therefore at least as strongly authenticated as local approval: it needs
   an enrolled device key, not a session alone.
3. **D3: The requester decides whether to trust the answer.** It re-verifies the decision
   against its own membership view and accepts one decision per open request before it
   writes a local grant. The server enforces the same checks and single use (`409` on a
   second decision), so a replay is refused twice; it can withhold an answer but not
   forge or upgrade one, and a withheld answer fails closed at expiry.
4. **D4: MCP may deny, never allow.** `secrets_approvals_list` shows metadata only;
   `secrets_approvals_deny` closes a request unsigned, recorded with `source:"mcp"` and
   the client ID, which can only refuse access; `secrets_approvals_allow` returns the
   dashboard link so an enrolled browser signs the allow.
5. **D5: History.** Closed rows stay seven days and list who answered, when, how and from
   where (`device`, `browser`, `mcp`).
6. **D6: Gated.** The routes and tools exist only where remote access is enabled.

## Consequences

- The CLI half (publish, poll, verify, write the local grant, `ak secrets approvals
  list|approve|deny`) lives in agentkit and is tracked there; until it ships nothing
  publishes requests in production.
- A machine device may publish a request (a background job is the main use) but never
  decide one.

## Open questions

- Should `secrets_approvals_allow` stay link-only, or may an MCP client with a stronger
  grant allow directly?
- Should a machine device be allowed to publish requests at all?
- Should the CLI's agent-ancestor guard (refuse approval when an agent is in the process
  tree) also apply to `ak secrets approvals approve`?
