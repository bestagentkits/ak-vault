# Security review: PR #23, protocol v1 revision (issue #20)

- Reviewer: isolated code-reviewer context, no implementation history
- Date: 2026-10-13 (Asia/Saigon)
- Code: worktree `protocol-revision-20`, branch `fix/protocol-v1-revision-20`, head `a29a535`, diff vs `origin/main` (65 files, +7132/-1023)
- Judged against: REVIEW.md, AGENTS.md security rules, spec §3.3–§11 + Revisions, threat model
- Read-only. Nothing edited, committed, pushed or commented. No caches created (`packages/protocol/dist` predates this review, 15:31).

## Evidence (run at a29a535)

| Command | Result |
|---|---|
| `cd go && go test -count=1 ./...` | `ok github.com/bestagentkits/ak-vault/go/akv1 0.871s` |
| `pnpm --filter ./packages/protocol test` | 8 files, 342 tests passed (includes generator-determinism) |
| Worker suite | not run (machine load, per instructions); new Worker tests read, not executed |

Vectors: `device-add-wraps.json` (8 valid / 13 invalid incl. `injected_key_for_joiner`, `dropped_wrap_from_signed_set`, `missing_current_epoch`), `removal-fence.json` (8 / 9 incl. `removed_author_after_fence`, `readded_device_old_epoch_after_fence`, `removed_author_newer_key_epoch`), `audit.json` (4 / 11 incl. `epoch_relabeled`, `vault_key_used_directly`), `membership.json` (rotation, fence, `wraps_digest` refusals). Go harness and TS tests both load them.

## Per-gap verdict (malicious-server attacks attempted)

| # | Gap | Verdict | Notes |
|---|---|---|---|
| 1 | Unauthenticated key distribution on add | **Closed** | Substituted wrap → digest mismatch; injected rcpt → `forbidden`; dropped wrap → digest; wrap from another event → digest of chosen event `n` fails; withheld set → `not_found` (DoS only, fail-closed). Joiner's own `device_add` pins chain prefix, so a forked/replayed chain cannot carry the joiner's event. Owner-authored `sas` must be 32-byte b64, so the `sas==""` "recovery" completeness relaxation in `verifyDeviceWraps` cannot be triggered by an owner event. |
| 2 | Rekey sets not re-verifiable | **Closed** | `wrap_sets` keyed `(membership_seq, rcpt, key_epoch)`, served unfiltered by `?membership_seq`; `POST /wraps` removed. |
| 3 | Recovering device can't read membership | **Closed, scope tight** | Only `recovery.get`, and `membership.get` *with* `AKV-Device-Key`, take the recovery path (`vault-authorization.ts:136-137`); `wraps.get`, `changes.get`, etc. fall to `memberDevice` → `forbidden`. Removed IDs refused; `kid(key)==did` + proof. Exposure (owner-token holder reads membership metadata) is stated in I4. |
| 4 | Audit key rule | **Closed for decryptable entries; opaque-entry contract fails open** | Per-epoch HKDF, epoch in kid + AAD, monotonic epochs, `epoch ≤ current`. See S1 below on `null`. |
| 5 | Records by later-removed authors | **Partially closed (as stated)** | Above-fence records refused by `verifyLoggedRecord`; Worker 409/400 fence and contiguous `MAX+1` positions; no `DELETE FROM records` anywhere, so no position reuse. Below-fence substitution remains (#21); the documented victim set is too narrow (S3). |
| 6 | Recovery key rotation | **Closed for the chain; bundle freshness is honest-race fragile** | Old key `forbidden` after rotate; rotate requires owner device; never-reused / no device collision both directions; event+bundle in one `transactionSync` (test shows chain stays at seq 0 on bundle conflict). Rollback to a pre-rotate bundle → recovering device gets `forbidden` (DoS only). Stale-sealer race: S2. |

Fence manipulation attempts:
- Server shows remover a short head → removed author's legit pre-removal records above the fence become unverifiable: fail-closed DoS, not a bypass.
- Reorder/rewrite positions ≤ fence: undetected by any client that does not hold those positions (#21). Clients that do hold them detect only if they keep a per-position record digest (spec §5 obligation; agentkit client must implement).
- Re-added same device ID: removal rows retained, epoch-bounded; vectors cover old-epoch-after-fence refusal and newer-epoch acceptance.
- Ahead fence signed by an honest owner is impossible unless the owner saw those positions; anything the still-member device signed before removal is legitimately pre-fence (stated limitation).

Cross-implementation: contexts/info strings unique (`akv1/audit-key\n` vs `akv1/item-key\n`, etc.); `ParseEpochTag` regex/limits identical; member_remove removal order TS `<` vs Go `utf16Less` agree; `WrapsDigest` sort rcpt-then-epoch agree (rcpt is ASCII so byte vs UTF-16 order identical); `log_fence` min 0 both; recovery-key mismatch `forbidden` both. No divergence found.

Secrets/logging: Worker error messages are static strings; no names/values/keys in errors or smoke output; data-classification updated for new metadata (`log_fence`, recovery pubs, set membership).

## Findings

### Blockers
None for merging this PR as a revision **behind `VAULT_SYNC_ENABLED=false`**, provided S1–S3 are fixed or explicitly accepted by the user.

### Should-fix

**S1. Audit verifier returns success with `null` where a key is mandatory (fail-open contract, normative vector).**
`packages/protocol/src/audit.ts:117-129`, `go/akv1/audit.go:159-172`, vector `every_entry_opaque_without_keys` (`packages/protocol/scripts/vectors/checkpoints-audit.ts:141`, `key_epoch: 2`, no keys), spec `docs/protocol/v1/spec.md:310-315`.
A current device always holds `VK[current]` (rekey sets are `requireAll`), yet `verifyAuditChain` silently returns `null` for current-epoch entries when the lookup misses. With no witnessed audit checkpoint, a server can serve a fully fabricated or truncated opaque chain and the verifier reports success with zero verified content. AGENTS.md fail-closed rule covers this ("any … epoch … is a refusal"). The hash chain does stop hiding entries *before* a decryptable entry (its AAD binds `prev`), so the risk is limited to (a) a missing current-epoch key and (b) an all-opaque or opaque-tail chain.
Fix: require a key for `keyEpoch` (or take a `minKeyEpoch` = epoch the device joined at / bundle covers, and refuse a missing key at or above it); replace the `every_entry_opaque_without_keys` valid case with an invalid one; return a typed opaque marker (`{seq, key_epoch, opaque:true}`) instead of bare `null`/nil map — Go callers reading a nil `map[string]any` get zero values silently.

**S2. Stale owner device can silently break recovery after a `recovery_rotate`.**
`worker/src/vault/recovery-store.ts:14-31`, spec `docs/protocol/v1/spec.md:473-475`.
`PUT /recovery` only checks `bundle_seq` monotonicity. Owner B that has not replayed A's rotate reseals with the old recovery key and a higher `bundle_seq`; the Worker accepts it and the next recovery fails `forbidden` at the worst moment (all devices lost). Spec relies on a client MUST that the server cannot check. Not a confidentiality break, but a durable availability failure of the only recovery path.
Fix: carry the sealer's verified `membership_seq` (or the recovery author ID) in the cleartext bundle header / request, and have the Worker refuse a `PUT /recovery` whose sealer state predates the latest `recovery_rotate` (`409`, pull and reseal). Add a Worker test.

**S3. Threat-model/spec understate who is exposed by the position-only fence.**
`docs/security/threat-model.md:130-138`, `docs/protocol/v1/spec.md:255-261`.
Text says the victims are devices that "first read those positions later (new or recovered)". Any existing device that had not pulled up to the fence before the removal (long-offline, or simply behind) is equally exposed, and detection for devices that *do* hold the positions depends on the client keeping per-position digests. Per AGENTS.md "never widen a stated guarantee", state the full victim set.

**S4. Threat model claims test evidence that does not exist.**
`docs/security/threat-model.md:76` (S2 row) cites `worker/test/` "`POST /wraps` gone". No Worker test asserts that route is refused (grep of `worker/test` finds none). Add a test (`POST /v1/vaults/{vid}/wraps` → 404/405) or drop the claim.

**S5. Rekey audit-epoch closure is only SHOULD.**
`docs/protocol/v1/spec.md:317`. The removed-device audit-forgery window closes only when an entry at the new epoch lands. Make it MUST for the rekeying device (and ideally its audit checkpoint), or the R1 mitigation depends on optional behavior.

### Nits

- N1. Pre-revision staging vaults half-work: cached `meta.membership_state` lacks `removals`; reads/writes continue, appends fail, old `wraps` table is orphaned (`worker/src/vault/vault-schema.ts:10`). Runbook says abandon them; a stored schema-revision marker that refuses old vaults would make that fail-closed instead of partial.
- N2. `wraps_digest` has no domain tag (`wrap-recipients.ts:52-55`, `wrap_recipients_and_sas.go`). Safe today because it is only consumed inside a typed signed body; note it if digests ever get reused elsewhere.
- N3. `verifyLoggedRecord` does not bound a *current* author's `record.key_epoch` by `state.key_epoch` (`removal-fence.ts:47-48`, `removal_fence.go:37-38`). Harmless for fence logic; cheap consistency check.
- N4. Recovery-identity reads are rate-limited by `did`, which the caller mints freely (pre-existing for `recovery.get`, now also `membership.get`). Consider an `ai-handle` issue for per-account limiting.
- N5. `wrap_sets` grows per device-adding event without its own quota (bounded only by `membership_events_per_vault` × `wraps_per_request`). Owner-only, low risk.

## Recommendation on #21 (fence binds position, not contents)

**#21 should block GA** (release gates), not this PR.
- The issue's motivating threat is "stolen device + colluding server". The fence is meant for exactly that, and under the stated limitation the attacker can still show a split view to every device that had not already fetched positions ≤ fence — including the new/recovered device that typically follows a theft. That is an integrity break of secret values for those devices.
- Protocol v1 has no production data, so a wire change is cheap now and expensive after GA (another reset or a v2).
- A small fix exists without a full log hash chain: sign the post-fence state into the removal itself (e.g. `fence_state_digest` = checkpoint-style `state_digest` at `log_fence`, or a running change-log hash), and have new readers verify reconstructed state against it, failing closed. The remover already must post a checkpoint at that point (spec §5); binding its digest in the signed removal removes the "server keeps the checkpoint" dependency.

#22 (role history) is server-enforced today and can stay a post-GA follow-up if the threat model keeps saying so.

## Unresolved questions

1. Does the agentkit client actually persist per-position record digests (required for the "position it already holds" detection)? Not verifiable from this repo.
2. Was the Worker suite run green at `a29a535`? Not run here; PR evidence should include it.
3. Is S2 acceptable as a documented limitation, or should the Worker enforce sealer freshness? Product decision for the user.

---

Status: DONE_WITH_CONCERNS
Summary: Gaps 1, 2, 3 and 6 close as claimed; TS/Go agree and Go + protocol suites pass at a29a535. Gap 4 has a fail-open `null` contract for current-epoch keys, gap 5 is partial by design (#21) with an understated victim set, and recovery bundle freshness after rotation is unenforced.
Concerns/Blockers: no merge blockers behind the sync flag; should-fix S1 (audit null fail-open, `audit.ts:117-129`, `audit.go:159-172`, vector `every_entry_opaque_without_keys`), S2 (`recovery-store.ts:14-31` stale reseal), S3 (`threat-model.md:130-138` victim set), S4 (`threat-model.md:76` nonexistent test evidence), S5 (`spec.md:317` SHOULD→MUST); nits N1–N5. #21 should block GA.

---

## Re-review at 940c707 (2026-10-13 16:15 Asia/Saigon)

Scope: `git diff a29a535 940c707` (37 files). Read-only; one throwaway scratch script outside the repo (deleted).

### Evidence

| Command | Result |
|---|---|
| `cd go && go test -count=1 ./...` | `ok github.com/bestagentkits/ak-vault/go/akv1 0.874s` |
| `pnpm --filter ./packages/protocol test` | 8 files, 347 tests passed (was 342; generator-determinism green, so committed vectors match the generator) |
| Scratch `tsx` probe: `verifyAuditChain` on the `e1` entries of `audit.json` with key for epoch 2 only, `keyEpoch: 2`, no witness | accepted, `[{"seq":0,"key_epoch":1,"opaque":true},{"seq":1,"key_epoch":1,"opaque":true}]` (see R1) |
| Worker suite | not run (load); new Worker tests read only |

### Finding-by-finding

| Finding | Status | Verification |
|---|---|---|
| S1 audit null fail-open | **Closed, with a doc overclaim (R1)** | TS `audit.ts` / Go `audit.go`: current-epoch key required before any entry (`keyFor(keyEpoch)`), every entry epoch ≥ `minKeyEpoch` requires a key, `minKeyEpoch ∈ 1..keyEpoch`, all `bad_request`. Typed result: TS discriminated union `{seq,key_epoch,opaque:false,event}` / `{seq,key_epoch,opaque:true}`, Go `AuditChainEntry{Seq,KeyEpoch,Opaque,Event}`; no more bare nil maps. Old valid case `every_entry_opaque_without_keys` is now an invalid vector; added `tail_opaque_without_current_key`, `all_opaque_without_current_key`, `older_key_missing_at_or_above_min`, `min_key_epoch_above_key_epoch`; Go harness passes `min_key_epoch` explicitly. TS default `minKeyEpoch = keyEpoch` is the conservative choice for callers that do not know their join epoch. TS and Go semantics match line for line. |
| S2 stale reseal | **Closed (honest-race guard, as documented)** | `recovery-store.ts`: `PUT /recovery` = `{bundle, membership_seq}`; `> state.seq` → 400, `< latest recovery_rotate seq` → 409; equal to rotate seq allowed (correct: state at that seq already holds the new key). Test covers 409 stale, 400 ahead, 400 missing field, stored bundle unchanged, then success. **Bypass:** the seq is client-declared, so a lying or buggy owner passes; threat model now says exactly that ("cannot stop an owner device that declares a current position yet seals the wrong key"). Acceptable: the guard targets honest stale devices, and any owner device could already break recovery. **Lockout:** none found. An honest owner that replayed the chain always declares ≥ rotate seq; only a device whose declared seq is ahead of the server gets 400, which is a server-rollback case that should alarm anyway. `json_extract` scan over ≤10k events per PUT is fine. |
| S3 victim set | **Closed** | Spec §5 and threat model now name offline/behind devices and the per-position-digest requirement; #21 added to `release-gates.md` as an unchecked gate. |
| S4 missing test | **Withdrawn: my finding was wrong** | `worker/test/authorization.test.ts:74-82` "wraps are accepted only inside a signed event" (`POST /wraps` → 404 for owner and editor) exists unchanged at `a29a535`. My first-pass grep searched for `POST` and missed the `fx.post` helper. The threat-model row now cites the file. |
| S5 SHOULD→MUST | **Closed** | Spec §7, key-lifecycle doc and R1 row say MUST. |
| N1 pre-revision vaults | **Closed** | `membership-store.ts` `state()` throws `unsupported_version` (400) when the cached state has no `removals`; test covers read and write. Note: the check uses the state's shape, so it would not catch a vault created at `a29a535` (has `removals`, untagged `wraps_digest`). That only matters for local/test vaults: deploys run only from `main` and this branch never reached staging. A stored revision marker would be sturdier; nit only. |
| N2 domain tag | **Closed** | TS `wrap-recipients.ts:57` `utf8Encode('akv1/wraps\n')`, Go `wrap_recipients_and_sas.go:93` `[]byte("akv1/wraps\n")`, spec §11 `utf8("akv1/wraps") \|\| 0x0A`: identical bytes. Tag is unique among contexts; no other call site computes a wraps digest (Worker uses library functions only); all wrap-bearing vectors regenerated and both suites pass. Spec rekey row and `verifyRekeyWraps` text now point to §11 instead of the old untagged formula. |
| N5 wrap quota | **Closed, but it adds a new availability trap (R2)** | `wraps_per_vault: 20_000`, published via `/v1/meta` (`meta-routes.ts` returns `LIMITS`); enforced in `storeWrapSet` inside the append transaction; test shows the chain does not advance on `quota_exceeded`. |

### New issues from the fixes

**R1 (should-fix, doc/comment accuracy). "The chain's tail is always decrypted" is false.**
`docs/protocol/v1/spec.md:316`, `packages/protocol/src/audit.ts:108`, `go/akv1/audit.go:128`. The verifier requires the *key* of the current epoch, not an *entry* at an epoch ≥ `minKeyEpoch`. A server that truncates the chain before the first new-epoch entry, or a chain read between a rekey and the rekeyer's required audit append, returns only opaque entries and passes (probe above, no witnessed checkpoint). The threat-model wording ("a reader without the current epoch's key is refused") is accurate; the spec sentence and both code comments claim more. Impact is low (opaque entries assert nothing, and truncation without a witnessed checkpoint is the stated freeze limitation), but per AGENTS.md a stated guarantee must not exceed what is proven. Fix: reword to "an entry at an epoch ≥ `minKeyEpoch` is always decrypted; a chain with no such entry can be entirely opaque and is bounded only by a witnessed audit checkpoint". Optionally, have callers treat an all-opaque result as "unverified" in UI.

**R2 (should-fix, availability). `wraps_per_vault` can permanently brick a vault in `rekey_required`.**
`worker/src/vault/wrap-store.ts:13-17`, `worker/src/limits.ts:41-42`. The cap applies to `rekey` sets as well as device-adding sets, and sets are never deleted. Once a vault is near the cap, a `device_remove`/`member_remove` (no wraps, so it still lands) sets `rekey_required`; the following `rekey` fails `quota_exceeded`. Writes stay refused forever, and there is no path out except operator surgery. Reachable by honest use in a large shared vault: rekeys store one wrap per current device, so 200 devices × 100 removals reaches 20,000; device adds with all older epochs add up to 256 each. Fix: reserve headroom. Refuse device-adding events above a soft threshold (e.g. cap minus `wraps_per_request`) but always admit a `rekey` up to the hard cap. Alternatively, refuse the *removal* when the following rekey could not fit. Add a test that a removal near the cap is still followed by a successful rekey (or is itself refused). Mention the behavior in the runbook.

**R3 (nit).** `putRecovery` scans `membership_events` with `json_extract` on every PUT. Cheap at 10k events, but `recovery_rotate`'s seq could instead live in `MembershipState` (or `meta`) alongside `recovery_author`, avoiding parsing JSON in SQL.

No new trust-boundary, secret-exposure or cross-implementation issues found. Error messages stay static; `membership_seq` and bundle data never appear in errors.

### Re-review verdict

- Blockers: none.
- Should-fix remaining: **R1** (spec/comment overclaim about the audit tail; text-only fix) and **R2** (wrap quota can lock a vault in `rekey_required`; small Worker fix plus test). Neither affects confidentiality. R2 should land before the staging soak, because the soak is where a large shared vault would first exercise the cap.
- Nits: N1 shape-based detection, N3, N4 (unchanged from the first pass, not in scope of this fix round), R3.
- #21 is now an explicit release gate; recommendation unchanged (must close before GA).

Status: DONE_WITH_CONCERNS
Summary: S1, S2, S3, S5, N1, N2 and N5 are fixed and verified in TS, Go, vectors and Worker tests; S4 was my error (the test existed at a29a535). Go and protocol suites pass at 940c707 (347 tests).
Concerns/Blockers: no blockers. Should-fix remaining: R1 (`spec.md:316`, `audit.ts:108`, `audit.go:128` claim the audit tail is always decrypted; a truncated chain can be all-opaque) and R2 (`wrap-store.ts:13-17` quota also blocks `rekey`, so a removal near the cap leaves the vault permanently in `rekey_required`).

---

## Re-review 2 at f946747 (2026-10-13 16:40 Asia/Saigon)

Scope: `git diff 940c707 f946747` (10 files: limits, membership handlers/store, recovery store, wrap store, storage-limit tests, spec §7/§10, threat model, audit comments). Read-only; no caches left (`.wrangler`/coverage absent after the run, `git status` clean).

### Evidence

| Command | Result |
|---|---|
| `cd go && go test -count=1 ./...` | `ok github.com/bestagentkits/ak-vault/go/akv1 0.773s` |
| `pnpm --filter ./packages/protocol test` | 8 files, 347 passed |
| `cd worker && pnpm exec vitest run test/vault-storage-limits.test.ts` | 1 file, 12 passed (load avg ~247 at the time) |

### R2: deadlock-freedom

The required rekey has three possible ways to fail. Each is ruled out:
1. **Wrap cap.** Exempt when `before.rekey_required` (`membership-handlers.ts`, `before` is the cached pre-event state, since neither `verifyAppend` nor the recovery authorize path persists).
2. **Request size.** Owner `device_add`/`member_add` are refused when `next.devices.length > 255`; a recovery enrollment may reach 256. A rekey needs one wrap per current device, so at most 256 = `wraps_per_request`. Byte budget: a wrap is ~237 bytes cjson (measured from `rekey-wraps.json`), so 256 × 237 ≈ 61 KB, plus `needs_rotate` ≤ `items_per_vault` 2000 × ~25 B ≈ 50 KB, total ≈ 112 KB. That is under `request_body_max_bytes` 256 KB with about 2× margin.
3. **Event slot.** `verifyAppend` gives non-rekey events seqs ≤ 9998 and only a rekey while `rekey_required` the last seq 9999. A removal cannot land at 9999, so `rekey_required` can never be set with no slot left. The pre-verification `type` sniff only selects the bound; chain verification still forces a real rekey.

Repeated removals: each removal needs a slot ≤ 9998 and sets the flag. Several removals in a row (or `member_remove` of many devices) are still cleared by one rekey of ≤256 devices. No sequence I could construct reaches `rekey_required` with no admissible rekey. The boundary tests cover cap-full removal + required rekey + refused voluntary rekey + recovery enrollment, the reserved last slot, and the 255+1 device bound.

Recovery into a full vault:
- **At the wrap cap:** works (exempt, tested).
- **At 255 owner-added devices:** works (256th place, tested).
- **Two narrow refusals**, both stated or accepted. (a) At seq 9999 recovery is refused, because that slot is reserved for the rekey (implementer's unresolved question; the vault is "full" either way). (b) **A second recovery into a vault already at 256 devices** (255 owner-added + an earlier recovery whose device has not yet removed any lost device) is refused `quota_exceeded`, a permanent recovery lockout for that vault. This needs about 255 devices and back-to-back total loss, so it is a nit. Spec §10's "never blocks … recovery" is slightly too strong; a clause like "while fewer than `devices_per_vault + 1` devices are current" would make it exact.

**Verdict: deadlock-free for the required rekey. R2 closed.**

### R2: exemption abuse and storage bound

Only an owner device (or holder of the recovery key) can author these events. So the actor is a vault's own owner exhausting its own vault, plus operator cost. There is no cross-tenant or confidentiality impact.
- **Without the recovery key:** after the cap, re-adding devices is quota-counted and refused, so cycles of remove + required rekey only spend existing devices: at most ≈ Σ(255…1) ≈ 32.6k extra wraps. Small.
- **With the recovery key (owner holds it by design):** cycle = recovery `device_add` (exempt, up to min(256, key_epoch) wraps) → `device_remove` → required rekey (exempt, ≤256). That is ≤ ~512 wraps per 3 events, so ≈ 1.7M rows over 10k events. The implementer's 10,000 × 256 = 2.56M figure is a valid loose upper bound. At ~240–300 B per row that is roughly 0.5–0.8 GB per vault, well under the Durable Object SQLite size limit. The 120 req/min/device rate limit makes it about an hour of sustained effort per vault.
- `wrap_sets` has no byte budget, unlike records (`record_bytes_per_vault` 512 MB). Total exposure therefore scales with how many vaults one account may create, which this PR does not bound.

Assessment: acceptable for the staging soak. A tighter fix that stays deadlock-free is hard: any hard cap on required rekeys reintroduces the lockout, and refusing removals near a cap is worse for security. I recommend an `ai-handle` issue: (1) count exempt wraps against the vault's overall storage/cost budget and alert, (2) confirm a per-account vault cap exists, (3) put the per-vault worst case in the [cost model](../../docs/operations/cost-model.md). Nit, not should-fix.

### R1: wording vs code

The spec §7 text, `audit.ts` JSDoc, `audit.go` doc comment and threat-model limitation now say exactly what the code does. Every entry at an epoch ≥ `minKeyEpoch` is decrypted; holding the current key does not prove such an entry exists; a truncated chain can be all-opaque and pass without a witnessed checkpoint; clients MUST NOT present that as verified. This matches the probe from Re-review 1. **R1 closed.**

### R3: stored rotate seq

`recordRecoveryRotate` writes `meta.recovery_rotated_seq` in the same `transactionSync` as `store.persist` and `storeRecoveryBundle`. A failure anywhere (bundle conflict, quota, fence) rolls back the meta write with the event. An idempotent replay returns the stored response without re-running the mutation, and a re-run would fail chain verification (stale `prev`) before reaching the write. So the key cannot diverge from the event log through retries or failures. A corrupt value fails closed (`internal`, every PUT refused). Missing key → 0 is correct for vaults with no rotate. One edge: a vault created at 940c707 that already had a `recovery_rotate` has no key and reads 0, so the stale-sealer guard is off for it. The N1 shape check does not catch that revision, but such vaults exist only in local tests (deploys run from `main`). **R3 closed**; that edge is a nit.

### Re-review 2 verdict

- Blockers: none.
- Should-fix: none remaining. R1, R2 and R3 are closed.
- Nits (non-blocking): second-recovery lockout at 256 devices and the spec §10 "never blocks recovery" wording; exempt-wrap storage bound (~0.5–0.8 GB per vault, owner-self-inflicted) for the cost model or a follow-up issue; vaults from the 940c707 revision miss `recovery_rotated_seq`; earlier N3, N4 unchanged.
- #21 remains a release gate; recommendation unchanged.

Status: DONE
Summary: The R2 exemption design is deadlock-free for the required rekey (wrap cap exempt, ≤256 devices fit one request with about 2× body-size margin, last event slot reserved). R1 wording matches the code, and the R3 meta key is transactional with the event. Go, protocol (347) and storage-limit Worker tests (12) pass at f946747.
Concerns/Blockers: none; no should-fix remains. Nits only: 256-device second-recovery lockout and the §10 wording; exempt-wrap storage bound (owner-only, ≈1.7M rows reachable, 2.56M loose bound) worth a cost-model note or an `ai-handle` issue.
