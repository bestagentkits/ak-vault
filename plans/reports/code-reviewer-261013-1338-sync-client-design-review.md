# Design review: `ak secrets sync` E2EE client (agentkit#2298)

Reviewer: code-reviewer (isolated context, no implementation history). Read-only.
Subject: `plans/261013-1320-8-client-web-gates/agentkit-sync-client-design.md` (cited `D:<line>`).
Evidence: ak-vault worktree HEAD `b22eb5c` (Worker/spec identical to `544ebcf` for every cited path; Go module tag `go/v0.1.0` = `544ebcf`); agentkit `c7c7c097e` (the design's pin; `origin/dev` is now `52a16d1c3`, one unrelated CI commit ahead).

## Code Review Summary

### Scope
- Design doc (1293 lines) vs spec, threat model, key lifecycle, REVIEW.md, `worker/src/**`, `worker/test/**`, `go/akv1` exported API, agentkit `runtime/secrets`, `commands/secretscmd`, `runtime/auth`, `docs/code-standards.md`.
- Focus: security soundness, wire conformance, gates, feasibility, C1-C3 verification.

### Overall assessment
Thorough and mostly well grounded; most Worker routes, bodies and status codes are cited correctly and the local-state model (HMAC'd names, ciphertext-only `sync.db`, outbox with fixed idempotency keys) is sound. It is **not decision-complete for security**: several flows as written either cannot work against the real Worker/Go API, raise permanent false alarms on benign races, or have real confidentiality/integrity gaps (VK substitution to joiners, removed-author forgery, agent-driven device approval). Three local-store issues can silently lose or overwrite secret values, which violates the "no LWW / no silent overwrite" rule. Fix the blockers below before porting the plan.

---

## Blockers

**B1. VK substitution on device enrollment: joiner trusts unauthenticated wraps** (D:757-758, D:741-744)
- Joiner "`GET /wraps?rcpt=<did>`; `UnwrapFromDevice` each into the keystore" with no authenticity check of the unwrapped VK. Wraps posted with `device_add` are not covered by any signature: `handleMembershipPost` only runs `validateWraps` (recipient/epoch shape) for non-rekey events (`worker/src/vault/membership-handlers.ts:39-43`); `wraps_digest` exists only on `rekey` (spec §4 L159). `kx_pub` is public, so a malicious server (threat-model actor, `threat-model.md:27`) can wrap an attacker-chosen `VK'` to the joiner. The joiner's first write at an epoch with no member-authored record yet (e.g. right after a rekey, or a vault whose items are all `needs_rotate`) is then readable by the server. Detection only happens after the fact, when an honest device hits `decrypt_failed`.
- Fix (client, now): never seal under `VK[e]` unless it came from genesis, own rekey, the recovery bundle, a verified rekey wrap set (B3), or it has opened at least one record at epoch `e` signed by another verified member. Otherwise `rekey_pending`-style refusal of writes.
- Fix (spec, proper; new ak-vault item, call it **C6**): add `wraps_digest` to the `device_add` body (owner-signed digest over the wraps delivered with the event, all epochs, sorted by `(key_epoch, rcpt)`); Worker requires posted wraps to match (same as rekey); vectors + both impls; threat-model row S2 extended to "substituted key for a new recipient".

**B2. Trust-anchor substitution via the offer code** (D:738-740, D:751-756)
- The SAS transcript binds only `{vault_id, initiator, joiner, nonce_i, nonce_j}` (spec §3.5 L135-138; `go/akv1/wrap_recipients_and_sas.go:100-120`). `trust_anchor` and `checkpoint` in the offer are **not** SAS-protected. An attacker controlling the copy-paste channel plus the server can supply a fake genesis whose device list includes the real initiator's public record, then author the joiner's `device_add` from its own device. Step 8 only requires "a `device_add` for itself whose `sas == SASDigest(in)`", and the digest is computable by anyone from public fields.
- Fix: require `device_add.author == offer.initiator`, the initiator must be an owner device in the verified prefix state, and `offer.checkpoint.author == offer.initiator`. The attacker cannot sign as the initiator, and cannot splice the real event into a fake chain because the event's signature covers `prev`.

**B3. Rekey wrap verification as written cannot succeed; Worker cannot serve historical rekey sets** (D:796-798)
- `GET /wraps?rcpt=<did>&key_epoch=<e>` returns only this device's wrap, but `VerifyRekeyWraps` recomputes `wraps_digest` over the **full** set (`go/akv1/rekey_wraps.go:72-77`), so it always fails with `bad_request`. That raises an alarm on every rekey.
- Even fetching `?key_epoch=e` without `rcpt` is insufficient. `listWraps` drops wraps whose `rcpt` is no longer a current device (`worker/src/vault/wrap-store.ts:33-39`), and later `device_add`s add more wraps at epoch `e`. A device that was offline across "rekey to e, later remove X" can never reconstruct the signed set.
- Fix (client): fetch `?key_epoch=e`, keep wraps whose `membership_seq == rekey.seq` (the field is returned, `wrap-store.ts:39`), and run `VerifyRekeyWraps(event, set, &stateAfterEvent)`.
- Fix (Worker, new ak-vault item, call it **C5**): add `GET /wraps?key_epoch=e&membership_seq=s` (or a `rekey_seq` filter) that returns the stored set for that event **without** the current-device filter. The wraps are ciphertext to their recipients, so this exposes nothing new. Add a test with "rekey, then remove a recipient, then verify from a third device".

**B4. Permanent false alarms from benign races and a wrong `CheckRollback` call** (D:799-803, D:819-824, D:832-834)
- Alarms are permanent and require `disable --purge` plus re-enroll (D:832). Three paths raise them without any attack:
  1. `CheckRollback(witnessed, {…log_seq, key_epoch})` is called **before** replay, with no `state_digest`. `CheckRollback` returns `rollback` whenever `LogSeq` is equal and the digests differ (`go/akv1/checkpoints.go:136-137`), so every idle cycle (head unchanged) alarms. Compute the digest after replaying the page(s), then call `CheckRollback`.
  2. "`head.membership_seq` must equal the verified chain's seq": another owner appending between this device's `GET /membership` and `GET /changes` makes it larger. Only `<` is rollback; on `>`, re-pull membership.
  3. "Peer `log_seq` above our `head.log_seq` → withheld": `GET /checkpoints` runs after `GET /changes`, so a peer can push and post a checkpoint in between. Reorder to fetch `/checkpoints` **first**. The Worker only stores a checkpoint with `log_seq <= currentLogSeq` (`worker/src/vault/checkpoint-store.ts:17`) and the log is append-only, so a later `/changes` head below a peer checkpoint is then a real contradiction. Apply the same to `membership_seq`.
- Also: comparing a peer's `state_digest` only "at a log_seq passed in this replay" misses checkpoints at log positions replayed in earlier cycles. Persist a `state_digest_at(log_seq)` history (one row per applied record) so any peer checkpoint ≤ cursor can be checked. The joiner must also check `offer.checkpoint.state_digest` at its `log_seq` during the first full replay (D:757, not stated).

**B5. Forged records from a removed device are accepted indefinitely (interim C3 rule is too weak)** (D:805-808, D:1223-1226, D:1249)
- The rule "former author: signature with historical `sign_pub` and `key_epoch <= max_epoch_while_member`" lets a stolen-then-removed device, colluding with the server, inject a **new head** for any item still at an old epoch (every item not yet rotated after the rekey). The forged record is validly signed and encrypted under a key the thief holds. Per-item epoch monotonicity does not block it, because the head is already at that epoch. This is an integrity attack (for example, swapping a webhook URL or a credential), not covered by `needs_rotate`.
- Fix: see the C3 verdict below (removal fence). Until the spec settles, the client should fail closed: do not apply as head any record by a removed author whose `log_seq` is greater than the first checkpoint by another device with `membership_seq >= removal_seq`. The remover should also post a checkpoint immediately after `device_remove` is accepted (before the rekey; `postCheckpoint` has no `rekey_required` check, `checkpoint-store.ts:14-30`), not only after the rekey (D:873).

**B6. Local last-writer-wins in `ApplySynced` / `DeleteSynced`** (D:508-516, D:815-817, D:640-644)
- The pull decides "no unsynced local change" from the snapshot, commits, and only later calls `ApplySynced(ref, value, meta)` with no precondition. A `set` from the user, the GUI or `import-env` landing in between is overwritten without notice. If that value was never pushed, it is lost (it existed nowhere else). `DeleteSynced` can likewise delete a value re-set in that window.
- Fix: `ApplySynced(ctx, ref, value, meta, expectEntrySeq)` and `DeleteSynced(ctx, ref, expectEntrySeq)` check `entry.Seq == expect` (absent ⇒ `expect == 0`) inside the index lock. Return `ErrSyncPreconditionFailed` and leave the ref to the next cycle's push, which preserves a branch. Add a race test.

**B7. Mixed-version index rewrite triggers "rollback repair" that overwrites local edits** (D:526-533)
- An older binary (an older Desktop-bundled `ak`, which the design itself anticipates at D:529-533) saves the index without `seq`/`deleted`. The next new-binary `Set` makes `doc.Seq = 1 < S.index_seq`, so step 1 enters repair and "re-applies the remote head of every synced item". Edits made by the old binary (for example a rotated credential) are overwritten with stale remote values and lost.
- Fix: (a) give `runtime/secrets` its own monotonic sidecar (an `index.seq` high-water mark, the same pattern as `agefile.go` `.hwm`), so `Seq` resumes above the sidecar after a legacy rewrite; (b) add an index `generation` ID so "restored" (same generation, lower seq) is distinguishable from "rewritten by legacy" (generation missing); (c) in any repair mode, never overwrite a ref whose current `value_mac` differs from the snapshot. Report it as `needs attention` instead.

**B8. Store/keystore target is not pinned; per-run backend/index overrides corrupt sync** (D:380-408, D:562)
- agentkit picks the backend and paths per run from `--backend`/`--index-path`/`--vault-path`, `AGENTKIT_SECRETS_BACKEND`, then config (`commands/secretscmd/backend.go:33-46`). The keystore "follows the secrets backend" (D:407). A `sync now` run with a different index or backend makes every ref look vanished (mass repair writes all vault secrets into that store) or makes its values look like edits (pushed vault-wide as new revisions). A backend switch also loses the device keys (`ErrNoDeviceKeys`).
- Fix: pin `backend`, `index_path`, `vault_path` and `keystore_backend` in `sync/config.json` at enable time. Every sync command refuses (exit 2) when the resolved Store config differs. The keystore opens the pinned backend, not the current one.

**B9. `enable` crash window loses the recovery signing key, and the stated resume is impossible** (D:704-720)
- `rs` and `rk` exist only in memory until step 8. A crash after genesis (step 5) and before step 8 leaves a vault whose `recovery_sign_pub` has no recoverable secret and no recovery kit. The resume claim "the sealed bundle sits in the outbox" is false, because the bundle is sealed only at step 8.
- Fix: seal the bundle **before** `PUT /v1/vaults/{vid}`, using a genesis-time checkpoint (`membership_seq 0`, `membership_head = hash(genesis)`, `log_seq 0`, `state_digest` of the empty list, `key_epoch 1`; all locally computable and accepted by `SealRecoveryBundle`). Persist the sealed bundle in the outbox and write or print the recovery kit before uploading genesis. Only then upload.

**B10. Device approval (and other Tier-2 ops) is drivable by an agent** (D:288-297, D:299-306, D:257-269)
- The scripted two-step `approve <J> --json` then `approve --confirm <prefix> --sas <digits>` lets a prompt-injected agent read the SAS from the first output and confirm an attacker's join code. Enrolling a device grants read access to every value (spec §3 L58-60). agentkit's own grant approval "refuses to run at all when an agent adapter sits above it in the process tree" (`commands/secretscmd/approve.go:290-291`), and the threat model lists prompt-injected agents as an actor (`threat-model.md:33`).
- Fix: `devices approve`, `devices remove`, `devices rotate`, `sync recover`, `sync disable --purge` and `sync settle` apply the same process-tree agent refusal plus audit row. `approve` requires an interactive TTY confirmation with no `--json`-only path. Keep the two-step scripted mode only for test builds or behind an operator-only mechanism.

## Should-fix

S1. **Membership append race code is 400, not 409** (D:745, D:876). A stale `seq`/`prev` fails `checkChainLink` → `bad_request` (`go/akv1/membership_log.go:160-168`; `membership-store.ts:39-44`). Retry on 400 after re-pull, rebuilding with a **new** idempotency key (the stored outbox body is now invalid).

S2. **File-backend lock contention breaks the 50 ms gate under real traffic** (D:968-971, D:977-989). The claim "Get does not take the index lock" is true, but `AgeFileBackend.Get` and every write take the age vault lock and run scrypt (2^18) under it (`agefile.go:165-189`, `:272-288`, `:340-349`, `:403-430`). Per-ref `ApplySynced` plus per-candidate value reads mean one scrypt per item while holding the lock that `resolve` waits on. Add batch Store APIs (`ApplySyncedBatch`, `ReadValues(refs)` in one lock/one decrypt), and state the invariant that no Store or backend lock is held across any HTTP call. Add a benchmark arm in which a peer pushes changes every interval; the current arm (b) has no remote changes, so it never exercises contention.

S3. **Joiner must not trust `offer.vault_origin`** (D:738). Derive the origin from the registry (D:907-913) and require equality. Otherwise a pasted code can direct token/proof traffic to an arbitrary host.

S4. **Freeze attack visibility.** The server controls `/checkpoints` relay (`checkpoint-store.ts:33-40`) and can drop peer checkpoints, so `withheld` detection is best-effort. Add `status.peer_checkpoint_age` and warn when no fresh peer checkpoint has arrived for N days while other devices exist. State the residual risk in the docs-impact list (D:1259-1261).

S5. **Recovery-path abuse visibility and a spec gap.** `recovery_sign_pub` can never be rotated: there is no event for it (`membership_rules.go` replay has only the genesis value), so a leaked password or recovery key plus a live owner session permanently allows recovery-authored `device_add`. Reseal with a new RK (D:902) does not revoke it, and old bundle ciphertext stays valid. Client: surface every recovery-authored `device_add` not performed by this device as `needs attention`. Spec: track as an ak-vault issue (`recovery_key_rotate` event). Also document that a fresh recovering device cannot detect bundle rollback (`KnownBundleSeq: 0`, D:888-889), which undercuts acceptance criterion 6's "bundle rollback" claim.

S6. **Settle on a tombstoned head with an older open branch is impossible.** A tombstone of a deleted item is `bad_request` before `resolves` is checked (`go/akv1/record_state.go:101-103`), so "keep remote" (the tombstone) cannot resolve the branch (D:845-846). Either define the client path (re-create then delete, with two records) or propose a spec rule allowing a resolves-only tombstone on a deleted item.

S7. **Rate limits on enable/join merge.** 120 requests/min/device (`worker/src/limits.ts:42`). Uploading hundreds of items is many minutes of PUTs. Honor `Retry-After` (`request-guard.ts:24-25`), resume from the outbox, and show progress.

S8. **Define "unsynced local change"** for D:815-817 and D8. After a pushed-and-branched edit, the outbox row is done, so the next remote head change would apply over the kept local value. Use "`value_mac` differs from the head's mac, or an open branch authored by this device exists".

S9. **Zero-HTTP sweep contradiction** (D:962-964). `enable`, `devices add` and `sync recover` must use the network with sync off locally. Specify that they are tested for zero connections until arguments and preconditions validate, rather than "exit 6".

S10. **Fake Worker scope** (D:1126-1136). It reimplements membership, wraps, items, checkpoints, recovery and idempotency, which is effectively a second server that will drift. Prefer a fault-injecting proxy in front of `wrangler dev` for most knobs, and keep the in-process fake minimal. P5's 4 days is likely underestimated.

S11. **Docs drift** (beyond D:1229-1231). `key-lifecycle-and-recovery.md:32-33` still says the SAS transcript is undefined, but spec §3.5 L135-138 defines it. Also `:61-63` versus spec §4 L163-165, as the design notes.

S12. **Phase gating.** P5 (pull verification) depends on decisions for C3/B5 and C5/B3, not only P1/P3/P4. P7 depends on C6 (B1) as well as C1. Add these to the dependency table (D:1049-1060).

## Nits

- Key on the error `code`, not the status: `quota_exceeded` is 413 for the envelope cap (`item-store.ts:110`, `errors.ts:24`) and 403 elsewhere. Proof `invalid_signature` is 401 (`request-guard.ts:51`). Removed devices get 403 `forbidden` on every read (`request-guard.ts:61-66`), so map that to `device_removed` (D:794-795 assumes the chain shows the removal, but a removed device cannot read it).
- Page `GET /membership` (max 1000/page, `limits.ts:28`; D:752, D:791).
- Derive conflict resolution from replay, not from the server's `resolved_revision` (D:812).
- Recovery bundle cap of 16 KiB (`limits.ts:32`) bounds retained epochs to roughly 200+. Note it, because every removal and rotation adds an epoch.
- `devices rotate` with `reason:"retired"` and locally destroyed keys can rekey with `needs_rotate: []` rather than flagging every item (D:869-870 applied to D:424).
- Alarm text says the exit is "purge + re-enroll, **or** `sync recover`" (D:832-833), but `recover` requires not-enabled (D:262). Say purge then recover.
- The deletion journal keeps up to 1000 deleted ref names in `index.json` for all users, sync or not. This is a small v1 privacy behavior change; mention it in the P1 PR.
- Citation drift: `RegisterUniversal` is in `flags/register.go:30` (not `universal.go`); `EmitError` is in `render/renderer.go:82` (`json.go:113` is the envelope).
- `decrypt_failed` on a validly member-signed record halts the whole vault. Consider per-item quarantine (an owner decision).

---

## Wire-conformance check (route / status / body)

| Flow | Design | Worker | Verdict |
|---|---|---|---|
| Genesis `PUT /v1/vaults/{vid}` `{event,wraps}` | 201 | 201 `{membership,wraps_stored}` (`membership-handlers.ts:21-27`); Idempotency-Key required (`api-handler.ts:39`) | OK |
| `POST /membership` | 201; 409 on seq race | 201; stale seq = **400** | S1 |
| `GET /membership?from` | full chain | paged, `has_more`, `membership` summary; non-member 403 | OK (page it); C1 |
| `GET /wraps?rcpt&key_epoch` | per-rcpt verify | `{wraps:[{membership_seq,wrap}],key_epoch}`, current devices only | B3/C5 |
| `PUT /items/{iid}` | 200 / 409 conflict+id / 409 tombstoned / 409 rekey_required / 422 | matches (`item-store.ts:116-145`, `errors.ts`) | OK (quota status nit) |
| `GET /changes?cursor&limit` | cursor exclusive, `head` | `log_seq > cursor`, `next_cursor`, `has_more`, `head{log_seq,membership_seq,membership_head,key_epoch,rekey_required}` (`changes-feed.ts:27-60`) | OK, ordering B4 |
| `POST /checkpoints` | 201 | 201 `{stored:true}`; 400 ahead; 409 rollback (`checkpoint-store.ts:14-30`) | OK |
| `GET /checkpoints` | peer list | latest per **current** device | OK (S4) |
| `PUT /recovery` | 200 `{bundle_seq}` | 200; equal seq 409, lower 409 rollback (`recovery-store.ts:11-25`) | OK |
| `GET /recovery` + `AKV-Device-Key` | fresh device | `authorizeRecoveryFetch` (`vault-authorization.ts:108-122`) | OK |
| `GET /audit?cursor` | inclusive cursor | `seq >= cursor`, `next_cursor = last+1` (`audit-store.ts:61-79`) | OK |
| Kill switch | exit 7 | 503 `sync_disabled` before auth (`api-handler.ts:28`) | OK |

## Gates

- **Sync off = zero HTTP.** Structurally sound: one constructor behind `config.json`, a `go list -deps` import guard, no `init()` I/O. Fix the S9 wording.
- **Resolve never waits on the network.** Holds only if "no lock held across HTTP" is stated and tested (S2). Today's design does not hold locks across HTTP, but nothing forbids it.
- **<50 ms p95.** Not structurally guaranteed with the file backend under remote traffic (S2). The proposed rig cannot observe the contention.

## Feasibility and phases

Feasible. The Go API covers everything used: `CreateDeviceKeys`, `BuildGenesisEvent`, `NextMembershipEvent`, `VerifyMembershipChain` (prefix replay works by slicing), `VerifyCheckpoint`, `CheckRollback`, `ApplyRecord`, `ComputeStateDigest`, `VerifyRekeyWraps`, `SealRecoveryBundle`/`OpenRecoveryBundle`, `BuildProof`, `SASCode`/`SASDigest`. The module is public. agentkit is on Go 1.25 with x/crypto 0.50, above ak-vault's 1.24 / 0.48, so MVS is fine. The vendored vectors are 16 files / 368 KB, as claimed. The phase table needs S12's extra dependencies, and P1 must include the B6/B7 Store changes.

---

## C1-C3 verdicts

**C1: a fresh recovering device cannot read the membership log. REAL.**
- Evidence: `authorize` bypasses `memberDevice` for a non-member only on `recovery.get` (`worker/src/vault/vault-authorization.ts:124-129`). Every other op goes through `memberDevice`, which returns 403 (`worker/src/vault/request-guard.ts:61-66`). Spec §9.4 limits non-member requests to the bundle fetch and the recovery `device_add` (`docs/protocol/v1/spec.md:260-261`). Building that `device_add` needs the current `seq`/`head`/`key_epoch` (`go/akv1/membership_log.go:52-64`). The bundle checkpoint goes stale after any `device_add`, because approval does not reseal (D:741-746), so the event fails `checkChainLink` (400). The Worker test builds the event from fixture-held state (`worker/test/membership.test.ts:142`).
- Fix: extend `authorizeRecoveryFetch` to `membership.get` with the identical predicate (owner account, did neither current nor removed, `AKV-Device-Key` with `kid == did`, proof against that key, `vault:read`). Update spec §3.5 (L123-133) and §9.4 (L260-261) to list "membership read" as the third non-member request, and threat-model I4 (exposure is device public keys and account IDs, to the owner-account holder only). Add worker tests mirroring `recovery-fetch.test.ts` (wrong account, removed did, kid mismatch, replayed proof, read scope) plus an end-to-end "device added after the bundle, then recover" test.

**C2: the spec does not say which key encrypts audit entries. REAL, and wider than stated.**
- Evidence: spec §7 defines only the AAD and chaining, not the key (`docs/protocol/v1/spec.md:217-224`). §11 says vault-key-derived envelopes use the tag `e<epoch>` but defines no audit derivation (`:286-288`). The vector uses a free-standing 32-byte `"key"` with kid `"e1"` (`protocol/v1/vectors/audit.json`). The Go API takes a caller key and caller kid (`go/akv1/audit.go:50`), and `VerifyAuditChain` takes **one** key for the whole chain (`audit.go:83-108`), so a chain spanning a rekey cannot be verified at all.
- Fix: define `AuditKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id), info=utf8("akv1/audit-key\n") || cjson({"key_epoch":e}), L=32)`, mirroring ItemKey §3. Entry `kid = e<epoch>`. The verifier selects the key by kid, requires kid epochs to be non-decreasing along the chain and ≤ the current key epoch, and rejects otherwise with `bad_request`. Change `VerifyAuditChain` (TS and Go) to take a per-epoch key map or lookup. Regenerate `audit.json` with a two-epoch chain plus "epoch decreases" and "unknown epoch" invalid cases. Update threat-model R1 to note that removed devices cannot read entries after a rekey.

**C3: no rule for verifying old records whose author was later removed. REAL; the design's interim rule is unsafe (B5).**
- Evidence: `VerifyRecord` requires a current device (`go/akv1/records.go:130-141`). Only `VerifyRecordSignature` (explicit key) exists for history (`records.go:114-125`). The change feed returns every record including those by removed authors (`worker/src/vault/changes-feed.ts:30-48`). Spec §5/§6 (`spec.md:171-215`) say nothing about historical authors. §4 covers membership replay only (`:166-169`).
- Fix (spec §5, new normative paragraph plus vectors): a record whose author is not a current device is accepted only if (a) it verifies under the `sign_pub` from that device's `device_add`, (b) `key_epoch` ≤ the highest key epoch while it was a member, and (c) a **removal fence** holds: its `log_seq` ≤ the `log_seq` of the first checkpoint signed by a different device with `membership_seq >= removal_seq`. Records past the fence are `forbidden` and raise an alarm. Before a fence exists, clients do not apply such records as heads. Remover devices MUST post a checkpoint immediately after `device_remove` is accepted. Add Go/TS `VerifyHistoricalRecord(record, history, fence)` and vectors (accepted pre-fence, rejected post-fence, wrong key, epoch above membership). Update the threat model with the residual window between removal and fence.

**New ak-vault items found by this review:** C5 (historical rekey wrap sets hidden by the current-device filter, B3), C6 (`device_add` wraps unauthenticated, B1), and the `recovery_sign_pub` non-rotation gap (S5).

---

### Recommended actions (order)
1. Resolve B1/C6, B3/C5 and B5/C3 in ak-vault (spec, vectors, Worker) before P5 merges. Land C1 before P7.
2. Rewrite D 6.5 (pull ordering, digest-after-replay, digest history, race tolerance) and D 6.3 (author == initiator, origin pinning, VK authentication).
3. Add the B6/B7/B8 Store and config changes to P1/P2. Fix the B9 enable ordering. Add the B10 agent refusal.
4. Address S1-S12. Re-review.

### Metrics
- Type coverage / test coverage / lint: n/a (design document; no code).

### Unresolved questions
- Is the Desktop app shipped with its own bundled `ak`/Go runtime (it determines how likely B7 is)?
- Does ak-web restrict the vault-token `aud` to known origins (it bounds S3)?
- Owner decision: per-item quarantine versus a vault-wide halt on member-signed `decrypt_failed`.
- Should C6 use `device_add.wraps_digest` or a per-epoch VK commitment in `genesis`/`rekey`? The former is simpler and matches the rekey pattern.

Status: DONE_WITH_CONCERNS
Summary: The design is broadly sound and mostly wire-accurate, but has 10 blockers: VK substitution to joiners, offer-code anchor substitution, unworkable rekey wrap verification, permanent false alarms from ordering and a wrong CheckRollback call, removed-author forgery, local LWW in ApplySynced, mixed-version repair data loss, unpinned store target, enable crash losing the recovery key, and agent-drivable approval.
Concerns: C1, C2 and C3 are all real (C2 also needs a multi-epoch verifier). New ak-vault items C5 and C6 plus the recovery-key rotation gap must be scheduled before the client phases that depend on them.
