# ADR 0003: Owner-signed member invitations for shared vaults

- **Status:** Proposed
- **Proposed:** 2026-10-26
- **Amends:** nothing in force today. On acceptance and implementation it **widens**
  the outsider exception in [spec §9 item 4](../protocol/v1/spec.md#9-transport-authentication-worker)
  (today only the recovery reads and recovery enrollment), the new-endpoint row of the
  [REVIEW.md](../../REVIEW.md) hard rejection criteria and the remote-access exceptions
  in [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable). Those three change in
  the implementation pull requests, not here. It reuses the precedents of
  [ADR 0001](./0001-opt-in-zero-knowledge-sync.md) and
  [ADR 0002](./0002-browser-device-relay-and-remote-mcp.md): SAS enrollment and
  owner-signed documents stored beside the chain.
- **Tracking:** [#126](https://github.com/bestagentkits/ak-vault/issues/126); protocol
  [#127](https://github.com/bestagentkits/ak-vault/issues/127); Worker
  [#128](https://github.com/bestagentkits/ak-vault/issues/128); dashboard
  [#137](https://github.com/bestagentkits/ak-vault/issues/137); CLI
  [agentkit#2730](https://github.com/bestagentkits/agentkit/issues/2730); parent epic
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
3. **No visibility.** The dashboard cannot show pending or timed-out invitations and
   the CLI ([agentkit#2730](https://github.com/bestagentkits/agentkit/issues/2730)) has
   nothing to build member commands on.

Constraints that stay in force: the server never adds a member, device or recipient
and never learns secret material; membership stays owner-signed; every refusal is
closed; the browser session is refused on every membership POST (ADR 0002 D1); old
clients keep verifying every chain they verify today.

## Why the server must not be the only channel

In SAS enrollment ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment))
the six digits are a hash of a transcript holding both nonces. If a relay that sees
the joiner's nonce can still choose the other nonce after it knows the target digits,
it can grind about 10^6 values and force a match while the owner and the joiner hold
different devices. A relay Worker is exactly that. Every design below therefore makes
each side **commit before the other reveals**, and the joiner authenticates the owner's
offer with a key that reached it outside the Worker.

## Decision

1. **D1: an invitation is an owner-signed document stored beside the chain, not a
   membership event** (the seal-key precedent, ADR 0002 D2). Signing context
   `akv1/invite`; exactly these keys: `{"v":1,"vault_id","invite_id","role":"editor"|
   "reader","inviter":device_id,"iat":unix_ms,"exp":unix_ms,"secret_hash":"<b64 sha256
   of the invite secret>","sig"}`. The inviter MUST be a human owner device that is
   current when the document is verified (removing that device voids its invitations),
   and the Worker refuses an `inviter` other than the token `did`, as for the seal-key
   document. The Worker stores the document and cannot forge one. Roles `owner` and
   device kind `machine` are not invitable in v1: a co-owner needs its own analysis of
   the recovery bundle, which is limited to `owner_account`
   ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)),
   and a machine is not a person.
2. **D2: the invite code carries what the invitee needs to authenticate the owner
   outside the Worker.** Prefix `aki1-` and `b64(cjson({"v":1,"ctx":
   "agentkit/akv1-invite","vault_origin","vault_id","invite_id","secret":"<b64 16B>",
   "trust_anchor","inviter_sign_pub"}))`, parsed like the codes in spec §3.8
   (whitespace removed, size bound, canonical JSON, exact keys, context check, every
   failure `bad_request` except `v`). `vault_origin` MUST equal the client's configured
   vault origin or the code is refused. `inviter_sign_pub` is the key every later
   owner signature (offer, `invite_accept`) is verified against before membership.
   `secret` only gates who may post a join (D4); it authenticates nothing. The code is a
   bearer for that gate and the root of the invitee's trust in the owner, so treat it
   like a token: never log it, never put it in a URL or fixture, and send it over a
   channel that is authentic from owner to invitee (D9). The role beside it is display
   text; the signed document is authoritative.
3. **D3: join is commit-reveal.** The invitee's device generates its own keys. It
   posts `commit = b64 sha256(cjson({"device":<device record>,"nonce_j":<b64 16B>,
   "label":…}))` and reveals nothing else. The device record's `role` equals the invited
   role, its kind is `human`, its `device_id` equals the token `did` and its `sign_pub`
   equals `AKV-Device-Key`; the account is the token `sub`, which ak-web authenticates
   and the Worker enforces. The device is neither a current nor a removed device of the
   vault.
4. **D4: bounded server-side pending state is acceptable.** The Worker may hold, per
   vault, signed invitations, join commitments, offers, reveals and the documents of D5
   to D7. All of it is public key material, IDs, timestamps and one 64-byte ASCII label
   (the same class as a join code, which spec §3.8 treats as non-secret); none of it
   lets the server add a member. Limits live in `worker/src/limits.ts` and `/v1/meta`:
   a small cap of open invitations per vault, an invitation lifetime defaulting to 24
   hours and never above 72, a join that expires 15 minutes after its commit, one live
   join per account per invitation, and **an attempt cap** counting only joins that
   carried the right secret (a wrong secret never spends an attempt, so a stranger
   cannot void someone's invitation without the code). A join post is allowed only to an
   account outside the vault, for an `email_otp` session (the recovery-identity
   precedent in spec §3.5, with the `browser` refusal from spec §9 item 1), with a
   device-key proof, and only when the secret hashes to `secret_hash`. Unknown vault,
   unknown invitation, wrong secret, expired and void invitations answer the same
   `forbidden`, and the refused-request budget is per `sub` because an outsider can
   mint new `did`s. A timing difference between an unknown and a known vault must not
   exist. Reads run through the shared pipeline.
5. **D5: the owner answers with a signed offer, and the joiner reveals second.** An
   owner device that sees a commit publishes an owner-signed **offer** (context
   `akv1/invite-offer`): `{"v":1,"vault_id","invite_id","initiator":device_id,
   "nonce_i":<b64 16B>,"commit":<the commit it saw>,"checkpoint":<signed checkpoint>,
   "ts","sig"}`. The joiner verifies the signature against `inviter_sign_pub`, that
   `commit` is its own and the checkpoint signature, and only then reveals `device`,
   `nonce_j` and `label`. The owner device checks the reveal against the commit before
   it shows any digit. The server therefore has to fix its substituted device and nonce
   before it learns `nonce_i`, and it cannot change the commit afterwards because the
   offer is signed over it. A forced match succeeds with probability about 10^-6 per
   attempt; with the attempt cap `a` and the open-invitation cap `c`, a malicious
   Worker's chance of enrolling its own device is at most about `a * c * 10^-6` per
   vault lifetime of invitations, a bound the threat model states and a vector tests.
6. **D6: the SAS is mandatory and typed.** Both devices display the six digits of
   `cjson({"ctx":"akv1/sas","vault_id","initiator","joiner","nonce_i","nonce_j"})`
   ([spec §3.5](../protocol/v1/spec.md#35-owner-recovery-signing-key-and-sas-enrollment)).
   The owner device refuses to proceed until the owner types the digits the invitee
   reads out; a wrong entry spends an attempt and is recorded by an owner-signed
   cancellation. The owner then signs an `invite_accept` document (context
   `akv1/invite-accept`: transcript hash, `invite_id`, joiner device ID, `ts`) and
   **afterwards** a normal `member_add` with the invited role, the joiner's device
   record and the signed wrap set. The order makes a stopped approval resumable:
   `invite_accept` alone grants nothing. The wrap set MUST hold the current epoch
   ([spec §4](../protocol/v1/spec.md#4-membership-log-owner-signed-hash-chained)) and
   SHOULD hold every retained epoch.
7. **D7: the SAS binding and cancellation live beside the chain.** `member_add` has no
   `sas` field and adding one would change what old verifiers accept. The cancellation
   document (context `akv1/invite-cancel`: `v`, `vault_id`, `invite_id`, `author`,
   `ts`, `sig`) is owner-signed and ends an invitation.
8. **D8: the invitee verifies in two stages and trusts nothing early.** Before
   membership it can check only what `inviter_sign_pub` covers (the invitation, the
   offer and its checkpoint); it cannot read the membership log, because spec §9 item 4
   keeps that read from outsiders and this ADR adds no such read. After the `member_add`
   it reads the chain, verifies it from `trust_anchor`, checks that the signers were
   current owner devices, that the added device and role are its own, and the checkpoint
   against the chain ([spec §3.8](../protocol/v1/spec.md#38-enrollment-codes) and §6).
   Any failure means it discards what it unwrapped and refuses. A server showing an old
   chain prefix is caught by the checkpoint the owner signed into the offer.
9. **D9: states, and who may do what.** A reader (owner CLI device or the dashboard)
   verifies every document and derives `pending`, `joined`, `accepted` (the chain holds
   the `member_add`), `cancelled` and `expired` (by its own clock, with no skew beyond
   the ±60 s that transport proofs allow). `void` and the join expiry are reported by the
   server as availability state; an owner device also enforces the signed `exp` and the
   offer `ts` itself. A document that fails verification is shown as unverifiable, never
   as an invitation. Create, offer, approve and cancel need an owner human device; the
   Worker refuses a `browser` session on all of them, as on membership POSTs (spec §9
   item 1). Reading invitations and joins is allowed to owner devices and, read-only, to
   the browser session. Editors and readers see nothing of it.

## Limits stated plainly

- The server can withhold, delay or drop an invitation or a join (availability, not
  confidentiality).
- The digits prove that the owner compares them with whoever reads them out, not who
  that person is. The account the owner sees is asserted through the Worker and the
  label is chosen by the joiner, so neither is verified. The owner MUST compare the
  digits over a channel that already authenticates the invitee (a call with a known
  person) and that is not the channel that carried the code. A stranger who holds a
  leaked code and reaches the owner on the same channel can be enrolled by an owner who
  does not do this: the code is not enough for membership, the owner's own comparison is.
- A leaked code lets a stranger spend attempts and block the intended invitee until the
  owner cancels and reissues.
- A browser device is a human owner device; a compromise of the dashboard origin (ADR
  0002) could sign invitation documents that another channel delivers.
- A member who joins holds the vault-wide key (ADR 0001): an invitation grants vault
  access, not per-secret access, and removing the member later recalls nothing it read.
- An invited editor or reader cannot enroll a second device in v1: `akj1` enrolls only
  owner-role devices (spec §3.8 rule 5). That needs the follow-up in
  [agentkit#2689](https://github.com/bestagentkits/agentkit/issues/2689).

## Alternatives rejected

| Option | Why not |
|---|---|
| No server state; out-of-band codes only (today's `akj1` model) | Safe, and the offline fallback this ADR keeps. But the owner learns nothing about a pending invite or a timeout, the dashboard stays blind, and members cannot be added without copying long codes both ways. |
| Reveal both nonces in the join and the offer, as `akj1` and `ako1` do | A relay can grind the second nonce and force a matching SAS (see above). The commit step closes it for invitations; the same weakness in the existing codes is tracked separately. |
| An invitation as a new membership event type | A new event type changes what old verifiers accept; the seal-key precedent shows the beside-the-chain route works. |
| A server-authored invitation or acceptance state | The server must not author membership state; derived state (D9) removes the temptation. |
| The owner adds the invitee by typing an account ID and device keys | No SAS, no proof the keys belong to the person invited. |
| Letting the invitee read the membership log before joining | A new outsider read of the member list for any holder of a code; D8 avoids it. |
| Mailing invitations from the Worker | Needs addresses the Worker does not hold. Delivery of the code stays with the owner. |
| Letting the dashboard create or approve invitations | ADR 0002 D1 keeps the browser out of membership writes. |

## Classification (lands with the implementation)

To be added to [data classification](../security/data-classification.md) with the Worker
work; not claimed before:

| Data | Class |
|---|---|
| Invitation, offer, `invite_accept` and cancellation documents; join commitment and reveal (account, device record, nonces, label, expiry) | Visible operational metadata, deleted on acceptance, cancellation or expiry; the label is untrusted display text |
| Invite code and `secret` | Credential-like: never logged, in a URL, fixture or error. Only `secret_hash` is stored |
| Invitation and join requests per route | Route template, status, stable code, vault ID, device ID and sizes only |

## Consequences

- New routes (a sketch, not a contract): create, list and cancel invitations; post a
  commit; post an offer; post a reveal; fetch `invite_accept`. They are added to spec §9
  item 4 and §9.6-style route tables in the same pull request as the Worker work, and to
  REVIEW.md and AGENTS.md when they ship.
- The joiner label and every join field are untrusted text: owner devices and the
  dashboard escape it, bound it to 64 printable ASCII bytes (the `akj1` rule) and never
  feed it to a policy, profile or command.
- [agentkit#2689](https://github.com/bestagentkits/agentkit/issues/2689) proposes pending
  joins for a user's own new device. The shape is the same, so the Worker should build one
  pending-join store for both. This ADR does not decide that flow. The same
  commit-reveal weakness in the existing `akj1` and `ako1` exchange is tracked in
  [#138](https://github.com/bestagentkits/ak-vault/issues/138).
- Removal, role change and rekey stay as in spec §4 and
  [key lifecycle](../security/key-lifecycle-and-recovery.md#member-removal-shared-vaults).
  Rekeying never revokes provider keys already disclosed to a removed member, and the UI
  says so.

## Implementation, in order

Each step is its own reviewed pull request and follows the spec-change procedure in
[AGENTS.md](../../AGENTS.md#spec-and-vector-changes) where the wire changes.

1. Spec, vectors, TypeScript and Go ([#127](https://github.com/bestagentkits/ak-vault/issues/127)):
   the invitation, offer, `invite_accept`, cancellation and `aki1-` formats; the join
   commit and reveal; the §9 item 4 outsider text; rejection vectors (expired, wrong
   role, non-owner signer, wrong vault, extra key, non-canonical JSON, reveal that does
   not match its commit, nonce sent before the commit, old checkpoint); threat-model rows
   with the D5 bound.
2. Worker ([#128](https://github.com/bestagentkits/ak-vault/issues/128)): routes and limits
   behind a flag, a negative test for every refusal in D4 and D9, dump and log scans for
   the new fields, data classification, REVIEW.md and AGENTS.md route lists.
3. CLI ([agentkit#2730](https://github.com/bestagentkits/agentkit/issues/2730)): owner
   invite, list, cancel and approve with typed SAS, and the invitee join command, all
   refusing to run under an AI agent.
4. Dashboard ([#137](https://github.com/bestagentkits/ak-vault/issues/137)): read-only
   states.

## Open questions for the owner

- Accept D4: bounded, non-secret pending state on the Worker. If not, only offline
  codes ship and the dashboard stays blind.
- Accept D7 (documents beside the chain) over a `sas` field on `member_add`.
- Show the owner the invitee's AgentKit account email (verified by ak-web), or only the
  account ID and label? An email reveals personal data and needs an ak-web lookup; it
  would shrink the impersonation limit above.
- Default history sharing: every retained epoch, or the current one only.
