# ADR 0003: Owner-signed member invitations for shared vaults

- **Status:** Proposed
- **Proposed:** 2026-10-26
- **Amends:** nothing. It adds a layer next to [ADR 0001](./0001-opt-in-zero-knowledge-sync.md)
  and [ADR 0002](./0002-browser-device-relay-and-remote-mcp.md) and reuses their
  precedents (SAS enrollment, owner-signed documents stored beside the chain).
- **Tracking:** [#126](https://github.com/bestagentkits/ak-vault/issues/126); dashboard
  [#120](https://github.com/bestagentkits/ak-vault/issues/120); CLI
  [agentkit#2730](https://github.com/bestagentkits/agentkit/issues/2730) and
  [agentkit#2731](https://github.com/bestagentkits/agentkit/issues/2731); parent epic
  [#1](https://github.com/bestagentkits/ak-vault/issues/1)
- **Wire contract:** none yet. This ADR records *why* and fixes the shape; the
  [protocol v1 spec](../protocol/v1/spec.md) will own *what goes on the wire* once the
  implementation issues land. Until then the spec is unchanged and no route, code or
  document named here exists.
- **Rollout:** staging only, behind a new flag, after the owner accepts this ADR.

## Context

Protocol v1 defines an owner-signed `member_add` ([spec §4](../protocol/v1/spec.md#4-membership-log-owner-signed-hash-chained))
that carries the new account's device records and their wraps. It has no invitation
state: nothing records that an owner invited someone, that the invitee answered, or
that the offer timed out. Three gaps follow:

1. **Key delivery.** An owner device must learn the invitee's device public keys
   before it can sign `member_add`. Today that is out-of-band copying with no format.
2. **Join codes cannot carry an invitee.** An `akj1` join code enrolls only a
   `human` device with role `owner` of an account that already owns the vault
   ([spec §3.8](../protocol/v1/spec.md#38-enrollment-codes), rule 5). A new account's
   device is an editor or reader of another account.
3. **No visibility.** The dashboard Vault access tab ([#120](https://github.com/bestagentkits/ak-vault/issues/120))
   cannot show pending or timed-out invitations, and the CLI ([agentkit#2731](https://github.com/bestagentkits/agentkit/issues/2731))
   has nothing to build member commands on.

Constraints that stay in force: the server never adds a member, device or recipient
and never learns secret material; membership stays owner-signed; every refusal is
closed (REVIEW.md, [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable)); the
browser session is refused on every membership POST (ADR 0002 D1); old clients keep
verifying every chain they verify today.

## Decision

1. **D1: an invitation is an owner-signed document stored beside the chain, not a
   membership event.** Modelled on the seal-key document (ADR 0002 D2). An owner
   device signs it with context `akv1/invite`; exactly these keys:
   `{"v":1,"vault_id","invite_id","role":"editor"|"reader","inviter":device_id,
   "iat":unix_ms,"exp":unix_ms,"secret_hash":"<b64 sha256 of the invite secret>","sig"}`.
   The Worker stores it and cannot forge one: the invitee and every owner device
   verify `sig` against a current owner device of the membership chain. The chain,
   its verifier and every old client are unchanged. Roles `owner` and device kind
   `machine` are not invitable in v1 (a co-owner needs the recovery and browser
   analysis of ADR 0002 D1 first; a machine is not a person).
2. **D2: an invite code carries the vault coordinates and a spam-gate secret.**
   Prefix `aki1-` followed by `b64(cjson({"v":1,"ctx":"agentkit/akv1-invite",
   "vault_origin","vault_id","invite_id","secret":"<b64 16B>","trust_anchor"}))`,
   parsed like the codes in spec §3.8 (whitespace removed, size bound, canonical
   JSON, exact keys, context check, every failure `bad_request` except `v`). The
   `secret` only gates who may post a join (D4). It authenticates nothing: the SAS
   does (D5). Because it is a bearer for that gate, treat the code like a token:
   never log it, never put it in a URL or a fixture. The owner shares it over any
   channel they choose; the role shown beside it is display text, the signed
   document is authoritative.
3. **D3: a member join code replaces `akj1` for invitees.** The invitee's device
   produces a join request with the same SAS inputs as `akj1` (device record, nonce,
   label) but with `role` equal to the invited role. A fresh joiner generates its own
   device keys, so no secret leaves the invitee device. The device record's `account`
   MUST equal the token `sub` of the request that posts it, which ak-web authenticates;
   the Worker enforces it. The owner does not type an account ID: the account is the one
   that answered, shown on the owner device with the joiner-chosen label.
4. **D4: bounded server-side pending state is acceptable.** The Worker may hold, per
   vault, the signed invitation documents and the join requests posted against them.
   Nothing in it is secret, nothing in it lets the server add a member, and all of it is
   public key material, IDs, timestamps and one 64-byte ASCII label (the same class as
   a join code, which spec §3.8 already treats as non-secret). Bounds (limits owned by
   `worker/src/limits.ts` and published by `/v1/meta`, not copied here): a small cap of
   open invitations per vault, at most a few join attempts per invitation (after the
   last the invitation is void), one live join request per account per invitation, an
   invitation lifetime default of 24 hours and never above 72 hours, and a join request
   that expires 15 minutes after it is posted. Posting a join is allowed only to an
   account outside the vault, for an `email_otp` session (the recovery-identity
   precedent in spec §3.5: `api_key_device`, `machine` and `browser` sessions are
   refused), with a device-key proof like the recovery reads, and only when the posted
   `secret` hashes to `secret_hash`. Unknown vault, unknown invitation, wrong secret,
   expired and void invitations all answer the same `forbidden`, so a probe learns
   nothing. Reads run through the shared pipeline.
5. **D5: the SAS is mandatory and typed, not clicked.** Both devices display the
   six-digit SAS of the transcript `cjson({"ctx":"akv1/sas","vault_id","initiator",
   "joiner","nonce_i","nonce_j"})` ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)).
   The owner device refuses to approve until the owner types the digits the invitee
   reads out, so a rubber-stamp "yes" cannot approve. The server sees both nonces and
   the invitee's device keys and could swap in its own device; the SAS mismatch is what
   catches that, which is why no flow may skip it. An invite secret never substitutes for
   it. Approval authors a normal `member_add` carrying the invited role, the joiner's
   device record and the signed wrap set for every retained epoch the owner chooses to
   share (default: all, per the spec §4 SHOULD). The wraps travel only inside that
   event, as today.
6. **D6: the SAS binding lives beside the chain.** `member_add` has no `sas` field
   and adding one would change what old verifiers accept. The owner device instead signs
   an `invite_accept` document (context `akv1/invite-accept`) over the transcript hash,
   the `invite_id` and the joiner device ID, after the owner confirmed the digits. The
   joiner trusts wraps only when the chain carries a `member_add` for its own device
   record, whose `role` equals the signed invitation's role, **and** a valid
   `invite_accept` for the same transcript. If the owner later prefers an in-chain `sas`,
   that is a spec revision with its own vectors and old-client analysis, and it replaces
   D6; it is not needed for the guarantees here.
7. **D7: states are derived, never server-asserted.** `pending` = a verified
   invitation, `exp` not passed, no join. `joined` = a join request exists and awaits
   the owner. `accepted` = the chain holds a `member_add` for that account. `cancelled`
   = an owner-signed cancellation of the `invite_id`. `expired` = `exp` or the join
   expiry passed by the reader's clock. `void` = the attempt cap was reached. A reader
   (owner CLI device or the dashboard) verifies each invitation signature and recomputes
   the state; a document that fails verification is shown as unverifiable and never as
   an invitation. The server's clock only decides when to delete. Owner devices also
   refuse to approve after `exp` or the join expiry by their own clock (no skew beyond
   the ±60 s that transport proofs already allow).
8. **D8: who may do what.** Create, cancel and approve need an owner human device,
   signed on the owner device; the Worker refuses a `browser` session on all three, in
   the same way as membership POSTs (spec §9 item 1). Reading the list of invitations
   and join requests is allowed to current owner devices and, read-only, to the browser
   session, so the dashboard can show `pending`, `joined` and `expired` without ever
   holding the power to change them. Editors and readers see nothing of it.
9. **D9: honest limits.** The server can withhold, delay or drop an invitation or a
   join (availability, not confidentiality). A leaked invite code lets a stranger take a
   join slot until the cap, which blocks the intended invitee until the owner cancels and
   reissues (denial of service of one invitation; no membership). An owner who approves
   digits they did not compare enrolls the joiner: the SAS is the control, the UX must
   make skipping it impossible, and the threat model must say so. A member who joins
   holds the vault-wide key (ADR 0001): an invitation grants vault access, not per-secret
   access, and removing the member later does not recall what they read.

## Alternatives rejected

| Option | Why not |
|---|---|
| No server state; out-of-band codes only (today's `akj1` model) | Safe, and the fallback this ADR keeps (D2 and D3 codes work offline). But the owner learns nothing about a pending invite or a timeout, the dashboard stays blind, and members cannot be added without copying a long code both ways. |
| An invitation as a new membership event type | A new event type changes what old verifiers accept; ADR 0002 and the seal-key precedent already show the beside-the-chain route works. |
| A server-authored invitation or acceptance state | The server must not author membership state. Derived state (D7) removes the temptation. |
| The owner adds the invitee by typing their account ID and device keys | No SAS, no proof that the keys belong to the person invited; the server could substitute them. |
| Mailing invitations from the Worker | Needs addresses the Worker does not hold and widens what it knows about people. Delivery of the code stays with the owner. |
| Letting the dashboard create or approve invitations | ADR 0002 D1 keeps the browser out of membership writes; D8 keeps it read-only here. |

## Classification (lands with the implementation)

To be added to [data classification](../security/data-classification.md) when the
Worker work lands; not claimed before:

| Data | Class |
|---|---|
| Invitation document: `invite_id`, role, inviter device ID, `iat`, `exp`, `secret_hash`, signature | Visible operational metadata |
| Join request: account, device record (public keys), nonces, joiner label, expiry | Visible operational metadata, deleted on acceptance, cancellation or expiry; the label is untrusted display text |
| `invite_accept` document | Visible operational metadata |
| Invite code and `secret` | Credential-like: never logged, never in a URL, never in a fixture or error. Only `secret_hash` is stored |
| Join and invite requests per route | Route template, status, stable code, vault ID, device ID, sizes only |

## Consequences

- New routes (a sketch, not a contract): create, list and cancel invitations; post a
  join; fetch the `invite_accept` document. Each one is listed under the hard rejection
  rule for new endpoints in [REVIEW.md](../../REVIEW.md) and runs the shared token, proof,
  live-revocation and membership pipeline, except the join post, whose outsider path is
  stated in D4. REVIEW.md and [AGENTS.md](../../AGENTS.md) gain these routes only when
  this ADR is accepted and the implementation ships.
- The joiner label and every field of a join request are untrusted text: owner devices
  and the dashboard escape it, bound it to 64 printable ASCII bytes (the `akj1` rule) and
  never feed it to a policy, profile or command.
- [agentkit#2689](https://github.com/bestagentkits/agentkit/issues/2689) proposes pending
  join requests for a user's own new device. The mechanism in D4 to D8 (a signed
  invitation, a pending join, a typed SAS) is the same shape, so the Worker should build
  one pending-join store used by both, with the owner-device case needing no invitation
  document. This ADR does not decide that flow.
- Removal, role change and rekey stay as in spec §4 and
  [key lifecycle](../security/key-lifecycle-and-recovery.md#member-removal-shared-vaults).
  Rekeying never revokes provider keys already disclosed to a removed member, and the
  UI says so.

## Implementation, in order

Each step is its own reviewed pull request and follows the spec-change procedure in
[AGENTS.md](../../AGENTS.md#spec-and-vector-changes) where the wire changes.

1. Spec, vectors, TypeScript and Go: the invitation, `invite_accept` and `aki1-`
   formats with parse, sign and verify rules and rejection vectors (expired, wrong
   role, signature by a non-owner, wrong vault, extra key, non-canonical JSON); threat
   model rows for the attacks in D9. Tracked in
   [#127](https://github.com/bestagentkits/ak-vault/issues/127).
2. Worker: the routes and limits behind a flag, negative tests for every refusal in
   D4 and D8, dump and log scans for the new fields, data classification update.
   Tracked in [#128](https://github.com/bestagentkits/ak-vault/issues/128).
3. CLI: owner commands to invite, list, cancel and approve with typed SAS, and the
   invitee join command, refusing to run under an AI agent
   ([agentkit#2731](https://github.com/bestagentkits/agentkit/issues/2731)).
4. Dashboard: read-only pending, joined, accepted, cancelled and expired invitations
   ([#120](https://github.com/bestagentkits/ak-vault/issues/120) follow-up).

## Open questions for the owner

- Accept D4: bounded, non-secret pending state on the Worker. If not, only the
  offline code path (D2 and D3) ships and the dashboard stays blind.
- Accept D6 (document beside the chain) over a `sas` field on `member_add`.
- Show the owner the invitee's AgentKit account email, or only the account ID and
  label? An email reveals personal data to the owner and needs an ak-web lookup.
- Default history sharing: every retained epoch (the spec's SHOULD) or the current one
  only.
