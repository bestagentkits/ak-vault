# ADR 0003: Owner-signed member invitation for shared vaults

- **Status:** Proposed (design only; no code, wire or Worker change lands with this ADR)
- **Proposed:** 2026-10-26
- **Tracking:** [#126](https://github.com/bestagentkits/ak-vault/issues/126); dashboard
  UX [#120](https://github.com/bestagentkits/ak-vault/issues/120); CLI member commands
  [agentkit#2731](https://github.com/bestagentkits/agentkit/issues/2731); parent epic
  [#1](https://github.com/bestagentkits/ak-vault/issues/1)
- **Builds on:** [ADR 0001](./0001-opt-in-zero-knowledge-sync.md) (owner-signed
  membership, no server-authored members) and
  [ADR 0002](./0002-browser-device-relay-and-remote-mcp.md) D1 (the browser session is
  refused on membership POSTs).
- **Wire contract:** [protocol v1 spec](../protocol/v1/spec.md) §3.5, §3.8 and §4. This
  ADR records *why*; if the spec disagrees, the spec wins and this ADR is corrected.

## Context

`member_add` (spec §4) is owner-signed and carries the new account's device records and
a wrap of the vault keys to each. Nothing tells an owner device what those device
records are. Today the owner would have to copy the invitee's public keys out of band,
the `ak` CLI has no member commands, and the dashboard's Vault access tab can list only
members already on the verified chain. There is no state for *pending*, *accepted* or
*timed out*.

The existing device join (`akj1-`/`ako1-`, spec §3.8) cannot be reused as is: a join
code enrolls only another device of an account that already owns the vault, with role
`owner`.

Constraints that stay in force: the server never adds a member, never sees a vault key
or secret material, and never authors membership; old clients keep verifying every
chain they verify today; every unknown or unverifiable input is refused.

## Decision

1. **D1: the membership chain stays the only authority.** An invitation is never a
   membership event. `member_add`, unchanged, is what makes someone a member. Adding a
   `sas` field to `member_add` is rejected: verifiers require exact body keys, so it
   would break chains older clients verify today. Consequence: the chain does not record
   that a SAS check happened; the owner's human comparison is the control (D3).
2. **D2: two public, non-secret codes, modelled on §3.8.** Like `akj1-`/`ako1-` they
   hold only public keys, IDs, nonces, times and a signed checkpoint, so exposing one
   leaks no secret. New formats (contexts use the `akv1/` prefix; only the shipped
   device codes keep `agentkit/`):
   - **invite** (owner device → invitee), `aki1-` + `b64(cjson(…))`, context
     `akv1/member-invite`: `vault_origin`, `vault_id`, `initiator` (the owner device),
     `role` (`editor` or `reader`; never `owner`, see D6), `nonce_i`, `issued_ts`,
     `expires_ts`, `trust_anchor`, `checkpoint`. `expires_ts - issued_ts` is at most 24 h
     and the CLI default is 1 h.
   - **join** (invitee → owner device), `akm1-` + `b64(cjson(…))`, context
     `akv1/member-join`: `vault_id`, `account`, `device` (`device_id`, `sign_pub`,
     `kx_pub` only; the owner chooses `role` and `kind` is always `human`), `nonce_i`
     echoed from the invite, `nonce_j`, `label`.
   Both parse under the §3.8 rules: whitespace stripped, size cap, canonical `cjson`,
   exact keys, own `ctx`, every failure `bad_request` except `v`
   (`unsupported_version`).
3. **D3: SAS authenticates the keys, as for devices.** The SAS transcript is the §3.5
   construction over `vault_id`, the initiator, the joiner device and both nonces. The
   owner device `member add` refuses to sign until the owner confirms that the six digits
   shown on the invitee's screen match, over a channel other than the one that carried
   the codes. A swapped join code therefore fails the comparison instead of receiving a
   wrap. The invitee, before trusting any wrap, verifies the chain from `trust_anchor`,
   the checkpoint and non-rollback (§6), and that the `member_add` carries exactly its
   device record and a wrap at the current key epoch.
4. **D4: timeout is a client rule, enforced where the decision is made.** The owner
   device refuses a join whose invite is past `expires_ts` (allowing 5 minutes of clock
   skew) and refuses a second join for one `nonce_i`; the invitee refuses an expired
   invite. An owner can always still sign a `member_add`, because the owner is the
   authority; the timeout bounds how long an unauthenticated code stays usable, not what
   an owner may decide. A join for an account that is already a member is refused.
5. **D5: pending state lives on the inviting owner device first (Stage A).** The owner
   device keeps a local record of invites it issued (`nonce_i`, role, expiry, state
   `pending`/`accepted`/`expired`/`cancelled`) in its local vault state, never on the
   server and never synced. No Worker, wire-chain or limits change is needed for Stage
   A; it needs the new code formats in spec §3.8 with `enroll-codes.json` vectors and Go
   and TypeScript parsers. The dashboard cannot list local state, so it continues to say
   no pending invitations are shown until Stage B.
6. **D6: server-side pending state is acceptable, under conditions (Stage B).** A
   Worker-held invitation mailbox is allowed only if all of these hold, and is not
   authorized to be built until this ADR is accepted by the owner and a reviewed spec
   change exists:
   - The server stores only the two documents of D2 as signed objects: the invite signed
     by an owner device (checked against the verified chain) and the join signed by the
     invitee device key over its own contents. It stores no key material beyond public
     keys, and it can never author or complete a membership event: a document it forges
     or substitutes fails signature or SAS, and the owner device still re-verifies
     everything.
   - A join is accepted only for a live, unexpired, unused invite, under a token whose
     `sub` equals the join's `account`. That binds the account claim to the identity
     provider, which Stage A cannot do.
   - Caps per vault on open invites (initial proposal: 16), a hard maximum TTL of 24 h,
     purge at expiry plus a short display window (initial proposal: 7 days), then
     deletion. The server learns the invitee account ID, role and times of pending
     invitations; that is new visible metadata and is classified in
     [data classification](../security/data-classification.md) in the same change as the
     endpoint, never before.
   - Routes run the full shared auth pipeline; invite creation and cancellation require
     an owner device proof, join submission requires a non-member token, and the
     `browser` session kind is refused on every write, as for membership POSTs. Reads
     for the dashboard stay read-only.
   - Failure of any lookup is a refusal, and the kill switch disables the routes.
   Dropped or withheld mailbox entries are an availability loss only; the out-of-band
   code path of Stage A keeps working.
7. **D7: invitee shape in v1.** One device per invitation. The owner approves further
   devices of an existing member account with `device_add`, which the chain already
   allows once the account is a member. A non-owner account cannot enroll a browser
   device in v1 (spec §3.8, ADR 0002 D1); this ADR does not change that. `owner` is not
   an invitable role: promotion is an explicit `role_set` after the member exists.

## Consequences

- An owner can add a member account without copying keys by hand, and a swapped code is
  caught by the SAS, as for devices.
- Stage A leaves the Worker and the membership wire untouched, so it widens no stated
  guarantee. Its limit: the account ID in a join code is unauthenticated, so a mistyped
  or lying claim at worst yields a member that can never sync (the server refuses a
  token whose `sub` does not match). The invitee still holds a wrap and thus the vault
  key, which is exactly what the owner consented to by passing the SAS check with a
  person they identified.
- The membership chain does not prove a SAS happened (D1).
- Pending and timed-out invitations are visible on the dashboard only after Stage B.
- Removing a member later rekeys the vault but cannot revoke what the member already
  saw (vault-wide key, no clawback), as in ADR 0001.

## Alternatives rejected

- **A `member_invite` membership event.** Makes the chain depend on unverified
  intent, forces every verifier to know a new event, and turns an expired or cancelled
  invite into permanent log entries.
- **Server-authored invitations or auto-accept.** Violates "server never adds a
  member".
- **Email-derived keys or a link that carries a key.** Introduces key material in a
  channel the server or a mail provider sees; custom cryptography is out.
- **Out-of-band copying of raw keys.** The status quo; error-prone and with no TTL.
- **Reusing `akj1-` with a relaxed role rule.** Would let a device of an unrelated
  account pass the owner-only join check and conflates device enrollment with
  membership.

## Spec-change procedure

Stage A and Stage B each follow the procedure in [AGENTS.md](../../AGENTS.md#spec-and-vector-changes):
spec text, regenerated vectors, green TypeScript and Go suites, and a threat-model
update (invite replay, code substitution, mailbox spam, account-claim forgery, and the
availability limit above). Stage B additionally needs data classification, Worker tests
with negative cases for every check in D6, a red-team scenario and the release-gate
entry. Neither stage starts before the owner accepts this ADR.

## Open questions

- Whether invitation TTL and the open-invite cap belong in the limits owner (`/v1/meta`)
  or stay client-only for Stage A.
- Whether the CLI should print the SAS only on the invitee side and have the owner type
  it, instead of both comparing, to resist a hurried confirm.
