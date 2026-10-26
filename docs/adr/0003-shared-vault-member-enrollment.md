# ADR 0003: Shared-vault member enrollment

- **Status:** Proposed
- **Proposed:** 2026-10-26
- **Tracking:** owner-device membership commands
  [agentkit#2730](https://github.com/bestagentkits/agentkit/issues/2730),
  [#120](https://github.com/bestagentkits/ak-vault/issues/120),
  [#5](https://github.com/bestagentkits/ak-vault/issues/5), parent epic
  [#1](https://github.com/bestagentkits/ak-vault/issues/1)
- **Wire contract:** [protocol v1 spec](../protocol/v1/spec.md) §3.8 (a new member
  join code) and Revisions. §3.5 (SAS transcript), §4 (`genesis`, `member_add`,
  `device_add` bodies), §9 item 4 and §11 are reused unchanged. This ADR records
  *why*; the spec owns *what goes on the wire*. If they disagree, the spec wins and
  this ADR is corrected.

## Context

Protocol v1 already defines shared vaults: `genesis` accepts `vault_kind` `shared`,
and `member_add`, `member_remove` and `role_set` are owner-signed events (spec §4,
§11). No client uses them. The agentkit CLI's genesis always writes
`vault_kind: personal`, and no client can bring another account's device into a
vault, because:

- v1 join codes (`akj1-`, spec §3.8 step 5) require a device record with role
  `owner`, kind `human` and `account` equal to the code's account: they enroll
  another device of an owner account only;
- `member_add.body` is exactly `{"account","role","devices","wraps_digest"}`
  (spec §4; Go `applyMemberAdd` uses `exactKeys`). Unlike `device_add` it has no
  `sas`, yet a joiner MUST check that the event adding it carries its SAS digest
  (spec §3.8, last paragraph), which a `member_add` cannot satisfy;
- v1 has no pending-invitation state, and the server must never add a member
  (REVIEW.md, "Server can add a device, member or recipient").

agentkit#2730 needs this decision before it ships an invitation flow.

## Decision

1. **D1: out-of-band, owner-confirmed enrollment; no server invitation state.** An
   invitee's device prints a member join code; a human owner device of the vault
   approves it with a SAS comparison and posts `member_add`. The Worker stores
   nothing before that event: no invitation record, token or route. Every
   membership change stays an owner-signed event (spec §4).
2. **D2: a new member join code, additive to §3.8.** Prefix `akm1-`, context
   `akv1/member-join`, the same keys as a join code
   (`v`, `ctx`, `account`, `device`, `nonce_j`, `label`). Step 5 differs only in the
   role: the device record's `account` equals `account`, `kind` is `human`, and
   `role` is any of `owner`, `editor`, `reader`. The `akj1-` format, its context and
   its vectors stay byte-identical, so shipped CLIs keep producing and accepting
   them; a shipped CLI refuses an `akm1-` code (`bad_request`, wrong prefix), which
   fails closed. New contexts use the `akv1/` namespace; the `agentkit/` prefix is
   kept only for codes shipped CLIs already produce (§3.8). The offer code (`ako1-`)
   is reused unchanged.
3. **D3: the invitee states the role and the SAS binds it; the owner accepts or
   refuses, never edits.** The SAS transcript embeds the joiner's full device record,
   role included (§3.5, Go `SASTranscript`). If the owner changed the role, the two
   devices would hash different records and the SAS would not match. So the owner
   tells the invitee the role out of band, the invitee's code carries it, and the
   owner's approve screen shows account, role and label before the SAS. The
   `member_add` carries `role` = that device record's role and exactly that record
   (Go `applyMemberAdd` already requires device role = account role, §11). A wrong
   role means a new code. `device_id` derives from `sign_pub` only, so the joiner
   MUST check every field of its record in the event, not just its ID.
4. **D4: SAS binding without a body change (option b).** `member_add` keeps its v1
   body. The joiner of a member join code, after verifying the chain from
   `trust_anchor` and the offer checkpoint (§3.8, §6), MUST find a `member_add` with
   seq above the checkpoint's, authored by the offer's `initiator`, whose `account`
   is its own and whose `devices` contain its exact device record, before it trusts
   any wrap. For `device_add` (D5) the existing `sas` check applies unchanged.
5. **D5: further devices of a member account use `device_add`.** Only human owner
   devices author events (§4, §11), so a member cannot enroll its own second device.
   It prints a member join code with its account's current role, and an owner device
   approves it with a normal `device_add` carrying `sas`; Go `applyDeviceAdd`
   already accepts a non-owner account's device when its role equals the account
   role. Only the code format was missing.
6. **D6: no Worker authorization change.** Spec §9 item 4 already admits any current
   member account: `sub` must be a member and `did` a current device of it (Worker
   `memberDevice`); role decides the rest. ak-web's vault token request names no
   vault, so a member account already gets tokens. Before its `member_add` lands,
   the joiner is outside membership and gets `403` on every route, as today; it
   retries for a bounded time after the SAS confirmation. The recovery identity and
   recovery enrollment stay limited to `owner_account` (§3.5); a member that loses
   every device is re-enrolled by an owner. `browser` sessions stay refused on every
   membership POST (ADR 0002 D1), and the browser dashboard stays owner-only: member
   join codes are not a dashboard enrollment path in this ADR.
7. **D7: creating a shared vault is in scope; converting one is not.** The missing
   client path is a genesis with `vault_kind` `shared` (spec §4), which the Worker
   already accepts from the owner account's device. `vault_kind` is set only at
   genesis (Go `applyGenesis`) and no event changes it, so a personal vault cannot
   become shared in v1. Sharing existing secrets means creating a shared vault and
   copying items into it on a device, which is a client feature, not a protocol one.
8. **D8: already possible without this ADR.** `member_remove`, `role_set` and the
   rekey a removal requires (`rekey_required`, §4) need no new protocol; agentkit#2730
   implements them on owner devices now. They act on members a future client adds;
   until D2 ships, a shared vault has only owner-account devices.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Server-held pending invitations (invite link, accept route) | The server would decide who joins; violates REVIEW.md and needs a new authenticated route and state. Out-of-band codes need neither. |
| (a) Add `sas` to `member_add` | Go and TS verifiers refuse unknown body keys (`exactKeys`), so the first such event makes the chain unverifiable for every older client, the owner's own older devices included. It needs a new event version or revision plus an upgrade window. Kept as a later option if third-party SAS evidence is wanted. |
| (c) `member_add` with no devices, then `device_add` with `sas` | `member_add` needs at least one device (Go `applyMemberAdd`, `bad_request`), so this is a body-rule change with the same compatibility cost as (a). |
| Owner picks the role at approval, joiner accepts any role | The SAS transcript covers the role, so the joiner's record would differ from the event's; letting the joiner accept a changed record means a SAS over a record that was never added. |
| Widen `akj1-` to non-owner roles | Changes the meaning of a shipped format and its vectors; a shipped CLI would refuse codes it used to treat as one class. A separate prefix fails closed with a clear error. |
| Convert a personal vault to shared | No event can change `vault_kind`; adding one breaks every older verifier, and a personal vault's history and recovery bundle belong to one account. |

## Consequences

- Spec: a §3.8 member join code (`parseMemberJoinCode`, encoder checks), the D4
  joiner rule beside the existing `device_add` rule, and a Revisions entry. New
  `enroll-codes.json` vectors: round trip for each role; machine device, account
  mismatch, `akj1-` context under `akm1-` and vice versa → `bad_request`; `v` 2 →
  `unsupported_version`. TS and Go green.
- Clients (agentkit#2730 and follow-ups): shared-vault genesis, `akm1-` code output,
  owner approval with role display, joiner verification of D4.
- No Worker change, no new route, no new stored state; data classification gains
  nothing new (accounts and roles in `member_add` are already server-visible, §4).

## Residual risks

- **No on-chain SAS evidence for `member_add`.** The SAS is compared by the two
  humans and checked locally on both devices; the joiner confirms the event's author,
  position and its exact record, but a buggy or malicious owner client that skipped
  the comparison leaves no trace in the chain. The owner device signing the event is
  already fully trusted to add members; option (a) can add evidence later.
- **Shared vault key.** A member reads every item, and removal needs a rekey and
  rotation of the values it saw (no clawback, ADR 0001). Separate vaults remain the
  answer for separate trust.

## Compatibility

`akj1-`/`ako1-` codes, every event body and every route keep their meaning. Older
clients cannot produce or accept `akm1-` codes and do not create shared vaults; they
verify a shared vault's chain, `member_add` events included, because no body changes.
