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
   `sas` field to `member_add` is rejected: verifiers require exact body keys
   (`membership-rules.ts`), so older clients would refuse any chain that contains the
   new shape. Consequence: the chain does not record that a SAS check happened; the
   owner's human comparison (D3) is the control.
2. **D2: two public, non-secret codes, modelled on §3.8.** They hold only public keys,
   IDs, nonces, times and a signed checkpoint. Formats (contexts use the `akv1/` prefix;
   only the shipped device codes keep `agentkit/`). Times are `unix_ms`:
   - **invite** (owner device → invitee), `aki1-` + `b64(cjson(…))`, context
     `akv1/member-invite`: `vault_origin`, `vault_id`, `initiator` (the owner device),
     `nonce_i_commit` (D3), `issued_ts`, `expires_ts`, `trust_anchor`, `checkpoint`. The
     role is **not** in the code: it lives in the owner's local invite record and in the
     SAS (D3), so it cannot be altered in transit unnoticed. `expires_ts - issued_ts` is
     at most 24 h; the CLI default is 1 h.
   - **join** (invitee → owner device), `akm1-`, context `akv1/member-join`:
     `vault_id`, `account`, `device` (`device_id`, `sign_pub`, `kx_pub`; `kind` is
     always `human`), `nonce_i_commit` echoed, `nonce_j`, `label`.
   - **reveal** (owner device → invitee), `akr1-`, context `akv1/member-reveal`:
     `vault_id`, `nonce_i`. Sent only after the owner device holds the join (D3).
   All three parse under the §3.8 rules: whitespace stripped, size cap, canonical
   `cjson`, exact keys, own `ctx`, every failure `bad_request` except `v`
   (`unsupported_version`). `owner` is never an invitable role; promotion is an explicit
   `role_set` after the member exists.
3. **D3: a SAS authenticates the keys, with a commitment so it cannot be ground.** The
   §3.5 SAS is six digits of a hash and the shipped device flow sends both nonces in the
   clear, so an attacker who sees one side's nonce can try nonces in a forged code until
   the six digits match (about 10^6 hashes, milliseconds). The member flow therefore
   commits first:
   `nonce_i_commit = b64(sha256(cjson({"ctx":"akv1/member-invite-nonce","nonce_i":…})))`
   goes in the invite; the joiner chooses `nonce_j` knowing only the commitment; the owner
   device reveals `nonce_i` only after it holds the join; the invitee checks the reveal
   against the commitment and refuses a mismatch before showing its digits. An attacker
   who substitutes the join must fix its key and `nonce_j` before `nonce_i` is known, so
   each attempt matches with probability 10^-6 and costs a fresh invite and a visible
   mismatch; the CLI counts mismatches and stops after three. The transcript uses its own
   context `akv1/member-sas` (never confusable with a device SAS) over `vault_id`,
   `vault_origin`, `trust_anchor`, the initiator, the joiner device record built as
   `{device_id, sign_pub, kx_pub, account, role, kind:"human"}` with `role` from the
   owner's local record, and both nonces. A tampered account, role, origin or anchor
   therefore changes the digits. The owner device refuses to sign `member_add` until the
   owner confirms the six digits match those on the invitee's screen over a channel other
   than the one that carried the codes. The invitee, before trusting any wrap, verifies
   the chain from `trust_anchor`, the checkpoint and non-rollback (§6), that the
   `member_add` author equals `initiator` and is an owner device on that chain, and that
   it carries exactly the invitee's device record and a wrap at the current key epoch.
   The same weakness exists in the shipped §3.8 device flow; it is tracked separately
   ([#136](https://github.com/bestagentkits/ak-vault/issues/136)) and is not changed here.
4. **D4: timeout and consumption are client rules, decided where the choice is made.**
   The owner device checks its own local record, not echoed fields: it refuses a join
   after `expires_ts`; the invitee refuses an expired invite, allowing 5 minutes of clock
   skew. An invite is *consumed* only when the owner signs `member_add` or rejects the
   SAS; a join that arrives first does not consume it, so someone who saw the invite
   cannot lock the real invitee out by submitting first, but can force the owner to
   decline. The owner can cancel and reissue. An owner can always still sign a
   `member_add`, because the owner is the authority; the timeout bounds how long an
   unauthenticated code stays usable. A join for an account that is already a member is
   refused.
5. **D5: pending state lives on the inviting owner device first (Stage A).** The owner
   device keeps a local record per invite (`nonce_i`, role, expiry, state `pending`,
   `accepted`, `expired` or `cancelled`) in its local state, never synced. Limitation:
   only the issuing device can complete an invite; losing it ends its open invites, and
   other owner devices and the dashboard cannot see them. No Worker or chain change is
   needed; it needs the three code formats in spec §3.8 with `enroll-codes.json`
   vectors (including a ground SAS and a wrong reveal being rejected) and parsers in Go
   and TypeScript.
6. **D6: server-side pending state is acceptable under conditions (Stage B).** A
   Worker-held mailbox is allowed only if all of these hold, and is not authorized until
   the owner accepts this ADR and a reviewed spec change exists:
   - The server stores signed documents, not codes: the invite signed by an owner device
     (context `akv1/member-invite-doc`, checked against the verified chain) and the join
     signed by the invitee device key over its own contents (`akv1/member-join-doc`). The
     invitee signature proves possession of the key it introduces, not identity or
     account ownership. No key material beyond public keys is stored.
   - The server cannot add a member: a substituted join must commit to its key and
     `nonce_j` before `nonce_i` is revealed (D3), so the mailbox, as a code channel,
     gets the same 10^-6 per-attempt bound as any other, and the owner device still
     re-verifies everything.
   - The join route serves a device that is not on the chain, so the membership check
     cannot apply as written. It uses the non-member proof of spec §3.5: `AKV-Device-Key`
     with `kid(sign_pub) == did` and a valid `AKV-Proof`, session kind `email_otp` only
     (`api_key_device` and `machine` refused with `403`), token `sub` equal to the
     join's `account`, and a live, unexpired invite. The `sub` check is enforced by the
     server and cannot be verified by an owner device, so it limits accidental
     squatting, not a malicious server.
   - Invite creation and cancellation need an owner device proof; the `browser` session
     kind is refused on every write. Reads of pending invites are limited to owner
     devices, so invitee account IDs do not reach editors or readers.
   - Per-vault cap on open invites, a maximum TTL, a per-invite join-attempt cap and a
     display window after expiry, then deletion. Values belong to the single limits owner
     and `/v1/meta`; the ADR fixes none. The server learns the invitee account ID, times
     and state; this is new visible metadata and is classified in
     [data classification](../security/data-classification.md) in the same change as the
     endpoint.
   - Any lookup failure is a refusal, and the kill switch disables the routes.
   - AGENTS.md lists the only permitted new routes and REVIEW.md rejects an endpoint
     without a membership check. Stage B therefore also needs an owner-reviewed amendment
     of both in the same change; no agent makes that change on its own.
   Dropped or withheld mailbox entries are an availability loss only; Stage A keeps
   working.
7. **D7: invitee shape in v1.** One device per invitation. v1 has no enrollment path for
   a member's further device: `akj1-` refuses non-owner records (§3.8) and D4 refuses a
   join for an existing member. A later ADR may let an `akm1-` join from a current member
   produce a `device_add`, whose `sas` field can record the check. A non-owner account
   cannot enroll a browser device in v1 (ADR 0002 D1); this ADR does not change that.

## Consequences

- An owner can add a member account without copying keys by hand, and a substituted join
  is caught by a SAS that cannot be ground, as long as the owner does the comparison.
- Stage A leaves the Worker and the membership wire untouched.
- The membership chain does not prove a SAS happened (D1).
- Account claim: the account in a join is unauthenticated in Stage A. An honest server
  serves wraps only to a token whose `sub` equals the device's account, so a lying
  invitee cannot read the vault through it; a malicious or colluding server could hand
  the wrap over, which the owner accepted by passing the SAS with a person they
  identified. A claim naming a real third party's account still makes that account a
  member on every dashboard, blocks inviting it later, and takes a `member_remove` and a
  rekey to clear.
- A seen invite can be used to force the owner to decline once; it cannot lock out the
  real invitee (D4).
- Pending and timed-out invitations are visible on the dashboard only after Stage B.
- Removing a member later rekeys the vault but cannot revoke what the member already saw
  (vault-wide key, no clawback), as in ADR 0001.

## Alternatives rejected

- **A `member_invite` membership event.** Makes the chain depend on unverified intent,
  forces every verifier to know a new event, and turns an expired or cancelled invite
  into permanent log entries.
- **Server-authored invitations or auto-accept.** Violates "server never adds a member".
- **Email-derived keys or a link that carries a key.** Puts key material in a channel the
  server or a mail provider sees; custom cryptography is out.
- **Out-of-band copying of raw keys.** The status quo; error-prone and with no TTL.
- **Reusing `akj1-` with a relaxed role rule.** Conflates device enrollment with
  membership.
- **A plain six-digit SAS over both nonces in the clear.** Can be ground (D3).

## Spec-change procedure

Stage A and Stage B each follow [AGENTS.md](../../AGENTS.md#spec-and-vector-changes):
spec text, regenerated vectors, green TypeScript and Go suites, and a threat-model
update (invite replay, code substitution, SAS grinding, mailbox spam, burned invite,
account-claim forgery and squatting, lost issuing device). Stage B additionally needs
data classification, Worker tests with negative cases for every check in D6, the
AGENTS.md and REVIEW.md amendment, a red-team scenario and the release-gate entry.
Neither stage starts before the owner accepts this ADR.

## Open questions

- Whether a third message (the reveal) is acceptable UX, or the comparison should be a
  full key fingerprint instead of six digits.
- Whether a Stage B invite should name the invitee account up front so the server can
  refuse any other account.
- Whether the Stage A invitation TTL belongs in the limits owner or stays client-only.
