---
title: "ak secrets sync: local-first E2EE sync client (agentkit#2298)"
description: "Opt-in akv1 sync for the ak CLI secrets vault: device keys, SAS enrollment with authenticated key delivery, CAS push/pull with preserved conflicts, tombstones, checkpoints, removal fence, recovery and recovery-key rotation, plus the sync-off/offline/latency gates."
status: pending
priority: P1
effort: 24.5d
branch: "<to be created from dev, e.g. feat/2298-secrets-sync-client>"
tags: [security, cli, secrets, sync, e2ee]
created: 2026-10-13
issue: https://github.com/bestagentkits/agentkit/issues/2298
related: [ak-vault#1, ak-vault#8, ak-vault#20, ak-web#568, agentkit#2299, agentkit#2300, agentkit#1543]
---

# ak secrets sync: local-first E2EE sync client (agentkit#2298)

## Revision 3 notes (2026-10-13, from P1 and P2 implementation)

These amend the sections below; the engine phase (P5) must follow them.

- **Expected seq (P1, agentkit#2323).** Expected seq `0` means "absent" only. Entries written by an older binary carry a distinct "seq-less" expectation, so always pass `IndexSnapshotEntry.ExpectEntrySeq()`, never the raw `Seq`. The current binary stamps seq-less entries on its next write, so take a fresh snapshot between batches. `index.seq` is written before `index.json`. A missing or corrupt `index.seq` self-heals from the index maximum and assigns a new generation, which the engine treats as a rewrite.
- **Restore detection (P5).** An entry seq lower than the one recorded in the sync snapshot signals a restore, even when the generation is unchanged.
- **Replay order (P5).** Replay `apply_pending` before local change detection. Otherwise a crash between the batch and the `local_map` update is pushed back as a false conflict.
- **Precondition failure with an unchanged value (P5, §5.4).** Re-apply rather than drop the row, or the remote value is never applied.
- **Keystore (P2, agentkit#2322).**
  - The akv1 pin is `v0.2.0` directly, which folds P4b into P2.
  - The file layout uses lists rather than maps, and the keychain backend adds an `/epochs` index.
  - The keychain save writes the index first, then the entry.
  - The passphrase cache must already hold a passphrase the vault has accepted before any keystore call.
  - A recovery unlock does not yet re-seal `keys.age` (agentkit#2321, recovery phase).
  - A purge needs vault IDs from sync state.
- **Value written before index commit (pre-existing store behavior).** `Set` writes the backend value before committing the index, so a crash in between changes a value without a seq bump. P5 detection must not rely on seq alone for values written by a crashed `Set`; tracked as an agentkit issue linked from agentkit#2323.
- **Guide (P10).** Note that `index.json` keeps up to 1000 deleted secret names, and give the fix-it step for a corrupt `index.seq`.

## Revision 2 (2026-10-13)

Revised after an independent design review
(`plans/reports/code-reviewer-261013-1338-sync-client-design-review.md`, 10 blockers,
12 should-fix items) and the owner's decisions.

- **Protocol gaps moved to ak-vault#20** (one v1 revision, being implemented):
  - `device_add.wraps_digest`, which the joiner verifies before using any key;
  - full rekey and `device_add` wrap sets served by the Worker;
  - `membership.get` for the recovery identity;
  - an HKDF audit key per key epoch;
  - the removal fence;
  - the `recovery_rotate` event.

  Flows in sections 6.3, 6.5, 6.8, 6.9, 6.11 and 6.12 now use the #20 design. The interim removed-author rule is gone. Phases that depend on #20 say so and need akv1 `go/v0.2.0`.
- **Client blockers fixed:**
  - Joiner requires its `device_add` to be authored by `offer.initiator`, and `offer.checkpoint` by the initiator (6.3).
  - Pull fetches peer checkpoints first. Only strictly lower values are rollback. A membership append between reads triggers a re-read. `CheckRollback` runs after replay with the computed state digest. Per-position state digests are persisted (6.5).
  - `ApplySynced`/`DeleteSynced` take an expected entry sequence (4.4).
  - An index without the sequence field is a legacy rewrite, never a rollback. The index gets a generation ID and a sidecar high-water mark. Repair never overwrites a ref whose value differs from the last synced value (4.4).
  - Store target (backend, index path, vault path, keystore backend, index generation) is pinned at enable; a mismatch is refused (5.1).
  - `enable` seals the recovery bundle against a genesis-time checkpoint before uploading genesis, writes the kit first, and is resumable (6.2).
  - Agent-ancestry refusal, the same as `approve.go:566`, on `devices approve`, the SAS confirmation of `devices add`, and every other Tier 2 sync command (2.2).
- **Should-fix items applied:**
  - Membership race is 400 with a new idempotency key.
  - File-backend lock contention: batch Store APIs, no lock held across HTTP, and a benchmark arm with concurrent remote changes.
  - Joiner origin comes from its own environment.
  - Peer-checkpoint age shown in status.
  - Recovery-key rotation command.
  - Settle on deleted items.
  - Zero-HTTP wording.
  - Phase dependencies.
  - Error mapping keyed on code; `Retry-After`; membership paging.
  - Conflict resolution derived from replay.
  - Recovery-bundle size bound.
  - Fake Worker narrowed to a fault proxy.
- **Exit codes renumbered.** Rev 1 reused 6 to 9, which secretscmd already uses (`resolve.go:22-42`). Sync now reuses 6 and 7 with their existing meanings and adds 10 to 14.
- **Owner decisions recorded as decided** (section 11), including per-item quarantine on `decrypt_failed` and the ak-web token contract.

Design only. Written in the ak-vault worktree for review; to be ported into
agentkit as `plans/<YYMMDD-HHMM>-secrets-sync-client-issue-2298/plan.md` (one
file or split per phase). Evidence: agentkit `origin/dev` `c7c7c097e`, ak-vault
`main` `544ebcf` (tag `go/v0.1.0`). Citations are `path:line` at those commits;
ak-vault paths are prefixed `akv:`. Names marked **[#20]** come from ak-vault#20's
fix direction and must be re-checked against the merged spec and `go/v0.2.0` API
before the dependent phase starts.

## 1. Outcome, scope, non-goals, acceptance

### Outcome

A user runs `ak secrets sync enable` on one machine and enrolls a second machine with `ak secrets devices add` / `approve`. Both machines then see the same secrets.

- Values, names and metadata are encrypted on the device before upload (akv1, `akv:docs/protocol/v1/spec.md` sections 3 and 5).
- Concurrent edits are kept as conflict branches and settled explicitly.
- Deletes cannot be resurrected.
- A rolled-back, forked or withholding server is detected and halts sync.
- A user who loses every device recovers with the vault password or recovery key.

With sync off, every vault v1 command behaves as today and makes zero network requests. `resolve` never waits on the network, even with sync on.

### In scope

- Commands: `ak secrets sync enable|status|now|settle|disable|recover|rotate-recovery` and `ak secrets devices list|add|approve|remove|rotate` (section 2).
- Device identity and keystore (3), item mapping and change detection (4), local state (5), all protocol flows (6), gates (7), dependency and vectors (8), phases (9) and tests (10).
- Additive `runtime/secrets` changes so sync can:
  - tell a real local edit or delete from a restored or legacy-rewritten index;
  - write without overwriting a concurrent local change (4.4).
- Docs: a decision-ledger entry superseding the v1 cross-device non-goal, the secrets guide, the operational-data surface registry, and the `ak:ak` command reference.

### Non-goals

- **Desktop UX and a desktop-hosted sync loop** (agentkit#2300). GUI writes go through the shared `secrets.Store` (`gui/api/secrets_api.go:220`, `:258`) and are synced because detection reads the shared index.
- **Discovery, `exec`, portable policy enforcement, machine/CI devices and shared vaults** (agentkit#2299, ak-vault#5/#7). Pulled `meta.kind = "policy"` items are cached as ciphertext and never applied.
- **Syncing device-local state:** grants, trust pins, pending approvals, the release ledger or `secrets-audit` (`sync_eligibility: never` in `docs/conformance/operational-data-surfaces.yaml`).
- **An OS service installer.** The "active sync service" is `ak secrets sync now --watch`, run by the user or a service manager, and later by Desktop.
- **Server restore re-seed** (ADR 0001 open item). v1 halts on an alarm.
- **A vault pointer stored in ak-web** (owner decision; see O1 in section 12).
- **Production enablement.** The Worker kill switch stays off and the commands stay hidden until ak-vault#8 records the external review.

### Supersession of the vault v1 non-goal

`plans/260816-0710-secrets-vault-v1-issue-1543/plan.md:101` lists "Cross-device
sync, team-shared vault, org RBAC, remote policy admin" as v1 non-goals. The v1
plan is a record and is **not edited**. agentkit keeps durable decisions in the
`docs/system-architecture.md` decision ledger (ADR files were removed), so P10
adds an entry next to "Secrets vault v1 limits" (`docs/system-architecture.md:1784`):

> **Secrets sync (opt-in E2EE, akv1).** Decision (date, owner): the v1 non-goal
> "cross-device sync" is superseded for a single owner's personal vault by opt-in
> end-to-end encrypted sync using ak-vault protocol v1 (ak-vault ADR 0001, spec).
> Team-shared vaults, org RBAC and remote policy admin remain non-goals. Sync off
> means zero network requests and v1 behavior; `resolve` reads only the local
> backend; grants and trust pins never sync; every v1 limit still applies. Not GA
> until ak-vault#8 records external review.

### Acceptance criteria (measurable)

1. **Sync off.** The zero-HTTP sweep (7.1) passes for every `ak secrets` leaf command. The existing `runtime/secrets`, `commands/secretscmd` and `gui/api` secrets suites pass unchanged.
2. **Offline resolve.** With sync on and the Worker unreachable, `ak secrets resolve` succeeds with no dial attempt from the resolve process (7.2).
3. **Latency.** Warm `resolve` p95 overhead with sync on is below 50 ms in all arms of 7.3, including the arm with concurrent remote changes.
4. **Propagation.** Two devices run `sync now --watch` against staging. A `set` on A is visible on B within 60 s in at least 99% of soak samples.
5. **Conflicts and deletes.**
   - Simultaneous writes produce a preserved branch on both devices, and `sync settle` resolves it, including when the head is a tombstone.
   - A stale offline write after a delete is refused (`tombstoned`), and the local ref is removed with a warning.
6. **Alarms.** Fault-injection tests (10.2) prove exit 13 for each of these:
   - membership rollback and fork;
   - change-log rollback;
   - state-digest fork against a peer checkpoint;
   - withheld log against a peer checkpoint;
   - forged record signature;
   - a removed-author record past the fence **[#20]**;
   - an injected wrap recipient;
   - a substituted `device_add` wrap **[#20]**;
   - a wrong-epoch envelope;
   - bundle rollback for a device that knows a higher `bundle_seq`.

   A member-signed record that fails to decrypt quarantines only that item.
7. **No false alarms.** An idle cycle, a membership append between reads, and a peer checkpoint posted during a pull all complete without an alarm (10.2).
8. **No silent local loss.** A local `set` racing a pull is never overwritten. A legacy-binary index rewrite never reverts local values (4.4 tests).
9. **Enrollment and recovery end to end** against a local Worker on `go/v0.2.0`: device add with SAS, remove plus fence plus rekey, self rotation, recovery-key rotation, and recovery into an empty `AGENTKIT_HOME` after a later `device_add`.
10. **Grants untouched.** A full sync including policy items leaves `grants.json` byte-identical.
11. **Vectors.** The vendored akv1 vectors pass inside agentkit's build (8.2).
12. **Redaction.** No secret value, token, proof, key or recovery material appears in stdout, stderr, logs or fixtures, and no secret name outside the allowlisted `ref` fields of 2.3.
13. **Agent refusal.** Every command listed in 2.2 refuses with exit 6 and writes an audit row when an agent adapter is above it.

## 2. CLI UX contract

### 2.1 Command tree and visibility

New commands live in `apps/cli/internal/commands/secretscmd/`. Each one:

- calls `flags.RegisterUniversal(cmd)` (`flags/register.go:30`; `--json --yes --no-interactive --quiet --verbose`);
- sets `SilenceUsage` and `SilenceErrors`;
- declares a full `cliui.HelpSpec` with `Effects`, `ExitCodes` and `Agent`.

All literals are ASCII.

```
ak secrets sync
  enable           create a new synced vault from this device's secrets
  status           show local sync state (never uses the network)
  now              run one sync cycle, or keep running with --watch
  settle           resolve a sync conflict for one secret
  disable          stop syncing on this device (local secrets stay)
  recover          restore the vault on a fresh device with the password or recovery key
  rotate-recovery  replace the recovery key (and optionally the password)
ak secrets devices
  list             list the vault's devices
  add              enroll this device into an existing vault (joiner)
  approve          approve a device that is enrolling (owner)
  remove           remove a device and rekey the vault
  rotate           replace this device's keys
```

Both parents are `Hidden: true` until ak-vault#8 passes (owner decision); they stay runnable. Production is additionally refused by the Worker kill switch (503 `sync_disabled`, `akv:worker/src/routes/api-handler.ts:28`).

### 2.2 Exit codes

secretscmd already uses 0, 2, 3, 4, 5, plus:

- 6 `exitRefused`
- 7 `exitPassphraseUnavailable`
- 8 `exitApprovalPending`
- 9 `exitRateLimited`

These are defined at `resolve.go:22-42`. Sync reuses 6 and 7 with their meaning and adds codes from 10:

| Code | Meaning | Typical causes |
|---|---|---|
| 0 | success | |
| 1 | command failure | `quota_exceeded`, `unsupported_version`, SAS not confirmed |
| 2 | invalid flags, arguments or invocation | missing `--recovery-kit-out` in non-TTY, malformed code, ambiguous prefix, **store target differs from the one pinned at enable**, `devices approve` without a TTY |
| 3 | not found | unknown ref/device/conflict, vault 404 on recover |
| 4 | already exists | `enable` when enabled, `devices add` when already a member |
| 5 | local storage failure | Store, keychain, `sync.db` |
| 6 | refused: an agent adapter is above this process | the commands listed below |
| 7 | the file-backend passphrase is unavailable | non-TTY `--watch` with no cached passphrase |
| 10 | sync is not enabled on this device | `now`, `settle`, `devices *`, `disable`, `rotate-recovery` before enable |
| 11 | vault server unavailable or busy (retryable) | network, 5xx, `sync_disabled`, `rate_limited`, lock busy, ak-web unreachable |
| 12 | needs attention | open conflicts, discarded local change, rekey pending, quarantined item, recovery enrollment by another device, repair skipped a locally changed ref |
| 13 | integrity alarm, sync halted | rollback, fork, withheld, bad signature on verified data, membership violation, injected or substituted wrap, post-fence record |
| 14 | authentication | not logged in, session without `sessionId`, token refused, this device removed (403 `forbidden`) |

**Agent-ancestry refusal (exit 6).** These commands call the existing `refuseSelfApproval(ctx, cmd, "<command>", "")` (`secretscmd/approve.go:566`) before anything else. It writes the same audit row and gives the same warning on hosts where the process tree cannot be read.

- `devices approve`
- `devices add` when it accepts an offer and confirms the SAS
- `devices remove`
- `devices rotate`
- `sync recover`
- `sync rotate-recovery`
- `sync disable --purge`
- `sync settle`

`enable`, `now`, `status`, `devices list` and join-code generation stay usable by agents. An agent can start an enrollment but cannot complete one.

**Error output.** Errors use `render.EmitError` (`render/renderer.go:82`; envelope at `render/json.go:113`). Add an optional `Sync *SyncErrorInfo {reason, server_code}` beside `Auth`. `reason` values:

- transport and server: `offline`, `server_disabled`, `rate_limited`, `busy`, `quota`, `protocol_unsupported`
- setup: `not_enabled`, `store_target_changed`
- auth: `not_logged_in`, `session_without_sid`, `token_refused`, `device_removed`
- integrity: `rollback`, `fork`, `withheld`, `bad_signature`, `membership_violation`, `wrap_substituted`, `post_fence_record`
- attention: `conflicts_open`, `rekey_pending`, `item_quarantined`
- `agent_refused`

`server_code` is the Worker `error.code`. Messages never contain names, values, item IDs, tokens or bodies.

### 2.3 Commands in detail

**Secret input rule** (`docs/code-standards.md` "Secret handling"):

- A password or recovery key never comes from a flag value or an environment variable.
- Input is a non-echo TTY prompt or a `*-file PATH|-` flag. Trailing `\n` or `\r\n` is trimmed.
- The password minimum is 12 characters. There is no breached-password check (owner decision).

**`ak secrets sync enable`**

- **Flags:** `--password-file`, `--recovery-kit-out PATH`, `--resume`, hidden `--vault-origin URL` (tests only).
- **Preconditions:**
  - email-OTP CLI session with `sessionId` (exit 14);
  - backend `keychain` or `file` (`memory` is exit 2);
  - not enabled (exit 4);
  - `GET /v1/meta` reports `sync_enabled:true` with `akv1` (exit 11 or 1).
- **Recovery kit:** vault origin, vault ID and the recovery key in 13 groups of 4.
  - TTY without `--json`: printed once.
  - With `--recovery-kit-out` (0600, refuses to overwrite with exit 4): also written to the file.
  - `--json` or non-TTY: `--recovery-kit-out` is required (exit 2) and the key is never printed.
  - The kit is produced **before** anything is uploaded (6.2).
- **Second-vault guard:** see 6.2 step 1 and open item O1.
- **Stderr hint:** "If this account already syncs on another device, stop and run `ak secrets devices add` here instead."
- **JSON `secrets.sync.enable`:** `{vault_id, vault_origin, device_id, items_uploaded, items_local_only:{reason: count}, recovery_kit_path, resumed}`.

**`ak secrets sync status`**

- Local only, never constructs an HTTP client, exits 0 even when disabled.
- **JSON `secrets.sync.status`:**

  ```
  {enabled, vault_id, vault_origin, device_id, role, store_target_ok,
   membership_seq, key_epoch, rekey_required, cursor, last_pull_at, last_push_at,
   last_error:{reason, server_code, at}|null,
   alarm:{reason, at}|null,
   peer_checkpoint_age_s|null, peer_checkpoint_warning,
   pending_outbox,
   conflicts:[{ref, branches:[{conflict_id, author_device_id, ts, tombstone, same_as_local, same_as_head}]}],
   needs_rotate:[ref], quarantined:[ref],
   unapplied:[{ref, reason}],
   attention:[{reason, device_id?, seq?}]}
  ```

- `peer_checkpoint_age_s` is the age of the newest checkpoint signed by another current device. `peer_checkpoint_warning` is true when other devices exist and that age is over 7 days (freeze-attack visibility; review S4).
- `attention.reason` includes `recovery_enrollment` for a recovery-authored `device_add` this device did not perform (review S5), and `repair_skipped_local_change`.
- `ref` values are the user's own names, already in `index.json` and `ak secrets list --json`. Values never appear.
- `unapplied.reason` is one of `too_large_for_backend`, `invalid_name`, `policy_item`.

**`ak secrets sync now`**

- **Flags:** `--watch`, `--interval DURATION` (default 15s, range 5s to 5m), `--pull-only`, `--allow-mass-delete`, `--wait-lock DURATION` (default 30s).
- **One cycle (6.5):** pull, push, pull, checkpoint.
- **`--watch`:**
  - loops until SIGINT/SIGTERM;
  - stats the local index every 2 s and polls the remote every `--interval`;
  - backs off from 15 s to 5 min on exit-11 errors, honoring `Retry-After`;
  - stops on exit-13 or exit-14 errors;
  - with `--json`, emits NDJSON (one envelope per cycle).
- **File backend:** prompts once at start in a TTY and caches the passphrase in-process. Non-TTY without a cache is exit 7.
- **JSON `secrets.sync.now`:** `{pulled, applied_locally, pushed, conflicts_open, discarded:[{ref, reason}], repaired:[{ref, reason}], skipped_repair:[ref], quarantined:[ref], checkpoint:{log_seq, membership_seq}, duration_ms}`.
- Exits 12 when anything needs attention.

**`ak secrets sync settle <ref> --keep local|remote|branch:<conflict_id>`**

- Flow in 6.6. Exit 3 if the ref has no open conflict.
- **JSON `secrets.sync.settle`:** `{ref, revision, resolved:[conflict_id], records_written}`.

**`ak secrets sync disable [--purge]`**

- **Without `--purge`:** sets `enabled:false`, makes no network calls and keeps state. Re-enable with `ak secrets sync enable --resume`.
- **`--purge`:** Tier 2. Deletes device keys and sync state; local secrets stay. Asks for TTY confirmation unless `--yes`; non-interactive without `--yes` is exit 2.
- The hint names `devices remove` on another device.

**`ak secrets sync recover`**

- **Flags:**
  - `--recovery-kit PATH` (or `--vault-id ID` with the origin from the environment);
  - `--use password|recovery-key`, `--password-file`, `--recovery-key-file`;
  - `--new-password-file`, `--recovery-kit-out`;
  - `--remove-others` (default true), `--yes`.
- **Preconditions:** not enabled in this home (exit 4); owner account email session (exit 14).
- **Flow:** 6.9. It always rotates the recovery key and the recovery signing key, and prints or writes the new kit.
- **JSON `secrets.sync.recover`:** `{vault_id, device_id, removed_devices, key_epoch, items_restored, recovery_kit_path}`.

**`ak secrets sync rotate-recovery [--change-password]`**

- **Flags:** `--password-file`, `--new-password-file`, `--recovery-kit-out`, `--yes`.
- **Use it when** the recovery key or password may have leaked, or a recovery enrollment appeared that the user did not perform.
- **Effect** (6.12): a `recovery_rotate` event **[#20]** with a new recovery signing key, and a bundle resealed with a new recovery key and the current or new password. The old kit stops working.
- Tier 2: TTY confirmation unless `--yes`.
- **JSON `secrets.sync.rotate_recovery`:** `{bundle_seq, membership_seq, recovery_kit_path}`.

**`ak secrets devices list [--refresh]`**

- Lists local cached membership; `--refresh` pulls first.
- **JSON `secrets.devices.list`:** `[{device_id, short_id, label|null, role, kind, this_device, added_seq, added_by_recovery}]`.

**`ak secrets devices add`** (joiner)

- **Flags:** `--label TEXT` (default hostname, ASCII printable, max 64), `--offer CODE|-`, `--confirm-sas DIGITS`, `--wait DURATION` (default 10m).
- **Step 1, `devices add`:**
  - creates keys if absent and prints the join code `akj1-...`;
  - `--json` returns `{status:"awaiting_offer", join_code, device_id}`;
  - allowed for agents.
- **Step 2, `devices add --offer O`:** agent refusal applies.
  - TTY: shows the SAS and asks "Does the approving device show the same 6 digits? [y/N]".
  - Non-TTY: requires `--confirm-sas` equal to the computed SAS, else exit 1.
  - Then waits for its `device_add` (6.3).
- **JSON `secrets.devices.add`:** `{status, join_code?, vault_id?, device_id, membership_seq?}`.
- Join and offer codes carry only public keys, nonces, identifiers and a signed checkpoint; they are not secret.

**`ak secrets devices approve <join-code|->`** (owner)

- Agent refusal applies, and an interactive TTY is required (exit 2 otherwise). There is no `--json` or scripted confirmation path (review B10). `--json` with a TTY is exit 2 because `--json` never prompts.
- Shows the offer code and the SAS, then asks "Does the other device show 123456? [y/N]". On `y`, posts `device_add` with wraps.
- Output: plain text only. Test builds drive the flow through the engine API (10.3), not the CLI.

**`ak secrets devices remove <device-prefix> --reason lost|stolen|retired|compromised`**

- **Flags:** `--password-file`, `--recovery-key-file` | `--new-recovery-key`, `--recovery-kit-out`, `--yes`, `--resume`.
- Tier 2: TTY confirmation unless `--yes`.
- **Flow** (6.8): remove, fence checkpoint, rekey, reseal.
- Prints the needs-rotate list and a reminder to revoke that device's ak-web session.
- **JSON `secrets.devices.remove`:** `{device_id, key_epoch, needs_rotate_count, bundle_seq, recovery_kit_path?}`.

**`ak secrets devices rotate`**

- Self key rotation (3.4). Takes the same inputs as `remove`.
- **JSON `secrets.devices.rotate`:** `{old_device_id, device_id, key_epoch}`.

### 2.4 Help text (Short and Details, ASCII)

- **sync:** "Sync secrets across your devices with end-to-end encryption (preview)". Details: "Opt-in. Values, names and metadata are encrypted on this device before upload; the server cannot read them. With sync off, ak secrets makes no network requests. resolve always reads this device's local store and never waits for the network. Changes sync when `ak secrets sync now` runs, or continuously under `--watch`."
- **enable:** "Create a synced vault from this device's secrets. You choose a vault password and receive a recovery key; keep both offline. Losing both, with no enrolled device left, makes the vault unrecoverable. Use `ak secrets devices add` instead if the account already syncs elsewhere."
- **status:** "Show this device's sync state from local records only, including open conflicts, secrets to rotate at their provider, and how long since another device last confirmed the vault state."
- **now:** "Pull remote changes, push local changes, and record a signed checkpoint. With --watch, keep syncing until interrupted."
- **settle:** "Resolve a sync conflict by keeping this device's value, the current remote value (which may be a delete), or a specific conflict branch. Other branches stay in history."
- **disable:** "Stop syncing on this device. Local secrets stay. --purge also deletes this device's sync keys and state."
- **recover:** "Restore the vault on a fresh device with the vault password or recovery key, remove lost devices, rotate the vault key and issue a new recovery key. Revoke your other ak-web sessions first."
- **rotate-recovery:** "Replace the recovery key, and optionally the password. The old recovery kit stops working."
- **devices add/approve:** "Enroll a device. Both devices show a 6-digit code; continue only if they match. Approval must be done by you in a terminal, never by an agent."
- **remove:** "Remove a device and rotate the vault key so it cannot read new writes. Rotate every listed secret at its provider: anything that device could read before removal is exposed."

Help goldens go in `commands/secretscmd/testdata/help/secrets_sync*.txt` and `secrets_devices*.txt`.

## 3. Device identity and keystore

### 3.1 Keys

- **Device keys:** `akv1.CreateDeviceKeys(account, akv1.RoleOwner, akv1.KindHuman, nil, nil)` (`akv:go/akv1/device_keys.go:13`), and `did = akv1.DeviceIDFromSignPub(signPub)`.
- **`account`:** the `sub` claim decoded from this device's first vault-token payload. The ak-web token response carries `did` but not `sub` (owner decision on the response shape), and the CLI session stores email, not user ID (`auth/store.go:18-31`).
- **Local state key `LSK`:** 32 random bytes. It is used only as a local HMAC-SHA256 key, so `sync.db` never stores names or value fingerprints in the clear.

### 3.2 Storage

`apps/cli/internal/runtime/secretsync/keystore`:

```go
type DeviceSecrets struct{ SignSeed, KxSecret, LSK []byte } // 32 bytes each
type Keystore interface {
    LoadDevice(ctx context.Context) (DeviceSecrets, error) // ErrNoDeviceKeys when absent
    SaveDevice(ctx context.Context, d DeviceSecrets) error
    DeleteDevice(ctx context.Context) error
    LoadVaultKeys(ctx context.Context, vaultID string) (map[int64][]byte, error)
    SaveVaultKey(ctx context.Context, vaultID string, epoch int64, vk []byte) error
    DeleteVault(ctx context.Context, vaultID string) error
}
func Open(cfg Config) (Keystore, error)
type Config struct {
    Backend    string                   // the keystore_backend PINNED in sync/config.json, never the current run's backend
    InstallID  string                   // 16 random bytes, b64, from sync/config.json
    Dir        string                   // AGENTKIT_HOME/secrets/sync
    Passphrase *secrets.PassphraseCache // file keystore only
}
```

**`keychain`** uses go-keyring with service `"agentkit"` (`keychain.go:15`). Account names contain `/`, which `validateRef` forbids in refs (`store.go:466-478`), so they cannot collide with a user secret.

- `akv1/<install_id>/device` holds `cjson({"v":1,"sign_seed","kx_secret","lsk"})` in b64, about 170 bytes. That is under the Windows cap of 1920 (`keychain.go:25`).
- `akv1/<install_id>/vk/<vault_id>/<epoch>` holds b64(VK), one entry per epoch.
- `install_id` isolates temp homes from the real home.

**`file`** uses `secrets/sync/keys.age` (0600, directory 0700). It is an age scrypt file using the vault's `PassphraseCache`, holding `cjson({"v":1, device, vaults:{vault_id:{epoch:b64}}})`. Writes go through `fsutil.WriteFileAtomicDurable`. No new crypto is involved.

**`memory`** is for tests only. `enable` refuses it.

The keystore backend is chosen at enable from the secrets backend in effect and **pinned** (5.1). Later runs open the pinned keystore regardless of `--backend`, `AGENTKIT_SECRETS_BACKEND` or config (review B8).

### 3.3 Lifetime

- **Device keys** are created by `enable`, `devices add` or `recover`. They are deleted by `sync disable --purge`, and by `devices rotate` (the old keys, after the new keys are enrolled).
- **VKs** are kept for every epoch received.

### 3.4 Rotation (`devices rotate`)

1. Generate `K2`. As the current device, sign `device_add{device: K2.record, sas: SASDigest(self transcript with two local nonces), wraps_digest}` **[#20]** with wraps for every retained epoch. Post it.
2. Switch the keystore to K2.
3. As K2:
   - sign `device_remove{device_id: old, reason: "retired"}` and post it;
   - post the fence checkpoint (6.8 step 3);
   - rekey with `needs_rotate: []`. The old keys never left this device and are destroyed, so no item needs provider rotation.
   - reseal.
4. Delete the old keys.

`--resume` continues from the outbox state.

## 4. Mapping vault v1 secrets to akv1 items

### 4.1 Item identity

- **One ref is one item.** `item_id = akv1.RandomID()` at first upload (spec section 2).
- **`local_map`** maps `name_mac = b64(HMAC-SHA256(LSK, "akv1-name\n" || ref))` to `item_id`.
- **Concurrent create of the same name.** The lexicographically smaller `item_id` is canonical.
  - The device whose `local_map` points at the other item pushes its payload onto the canonical item with `base_revision = 0`. CAS fails, so the server preserves it as a branch.
  - That device then tombstones its duplicate item and remaps.
  - Other devices never apply a non-canonical duplicate.

### 4.2 Plaintext inside the ciphertext

The payload is `akv1.ItemPayload` (`akv:go/akv1/item.go:20`), up to 65 536 bytes of plaintext.

| akv1 field | Source (v1) | Rule |
|---|---|---|
| `name` | `Metadata.Ref` | must pass `validateRef` on pull, else `unapplied: invalid_name` |
| `value` | backend `[]byte` | UTF-8 as-is; otherwise base64 with `meta.value_encoding = "base64"` |
| `sensitivity` | none in v1 | `"normal"` on create; carried forward on update |
| `meta.schema` | constant | `"agentkit.secret/v1"` |
| `meta.created_ms` / `rotated_ms` / `rotate_ttl_days` / `creator` | `Metadata` | omitted when zero or empty |
| `meta.value_encoding` | derived | only `"base64"` |

- v1 has no description field, so `meta.description` is reserved.
- Unknown `meta` keys from the previous head are carried forward.
- Oversize payloads stay local-only.

### 4.3 What the server sees, and what never syncs

**The server sees** only akv1 public fields: `vault_id`, `item_id`, `base_revision`, `key_epoch`, `tombstone`, `author`, `ts`, `resolves`, sizes and timing (ak-vault data classification).

**Never synced:** grants, trust pins, pending approvals, throttle state, release manifests and `secrets-audit`.

**Policy items** (`meta.kind = "policy"`) are cached as ciphertext and never written to the Store or read by the resolver. A test asserts `grants.json` is unchanged.

### 4.4 Change detection and safe local writes (Store changes, P1)

Sync diffs the shared index against its last synced snapshot, so every writer is covered without hooks: CLI, GUI, `import-env`, and older binaries. Three properties are required:

- a restore must not look like edits;
- a legacy rewrite must not look like a restore;
- a pull must not overwrite a concurrent local write.

**Index fields.** These are additive. Older binaries ignore and drop them.

```go
type indexDocument struct {
    SchemaVersion int            `json:"schemaVersion"`
    Generation    string         `json:"generation,omitempty"` // random 16-byte b64, created once per index
    Seq           int64          `json:"seq,omitempty"`        // bumped on every Set/Delete
    Refs          []indexEntry   `json:"refs"`
    Deleted       []deletedEntry `json:"deleted,omitempty"`    // newest 1000 deletions
}
type indexEntry   struct{ /* existing */ ; Seq int64 `json:"seq,omitempty"` }
type deletedEntry struct{ Ref string `json:"ref"`; Seq int64 `json:"seq"` }
```

**Sidecar high-water mark.** `index.seq` sits next to `index.json` (0600) and holds `{"generation","seq"}`. It follows the same pattern as the age-file `.hwm` (`agefile.go:48`, `:358`). It is written under the index lock after every save.

**Writing `Seq`.** On `Set` or `Delete`:

```
doc.Seq = max(doc.Seq, sidecar.Seq) + 1
```

If `doc.Generation` is empty, the sidecar's generation is adopted, or a new one is created. So `Seq` resumes above the high-water mark after a legacy rewrite.

**Deletion journal.** `Set` removes the ref from `Deleted`. `Delete` appends `{ref, seq}` and keeps the newest 1000.

- This keeps up to 1000 deleted ref **names** in `index.json` for every user, synced or not.
- It is a small v1 privacy change. The P1 PR states it and the guide documents it.
- Names are not values, and `index.json` already holds every live name.

**New Store methods** (in `store_synced_writes.go`; all inside the index lock, `store.go:449`):

```go
var ErrSyncPreconditionFailed = errors.New("secrets: ref changed locally since sync read it")

// ApplySynced writes a pulled value only if the ref's entry seq still equals
// expectEntrySeq (0 means "must be absent"); otherwise ErrSyncPreconditionFailed
// and nothing is written. Returns the new entry seq.
func (s *Store) ApplySynced(ctx context.Context, ref string, value []byte, meta SyncedMeta, expectEntrySeq int64) (int64, error)
// DeleteSynced deletes only if the entry seq equals expectEntrySeq; an absent ref is success.
func (s *Store) DeleteSynced(ctx context.Context, ref string, expectEntrySeq int64) (int64, error)
// ApplySyncedBatch applies many changes under one index lock and, for the file
// backend, one vault decrypt/encrypt; per-ref precondition results are returned.
func (s *Store) ApplySyncedBatch(ctx context.Context, ops []SyncedOp) ([]SyncedOpResult, error)
// ReadValues reads several refs with one backend open (one scrypt for the file backend).
func (s *Store) ReadValues(ctx context.Context, refs []string) (map[string][]byte, error)
// IndexSnapshot returns generation, doc seq, sidecar seq, entries and deletions in one read.
func (s *Store) IndexSnapshot(ctx context.Context) (IndexSnapshot, error)
type SyncedMeta struct{ CreatedAt, RotatedAt time.Time; RotateTTLDays int; Creator string }
```

A precondition failure leaves the ref to the next cycle's detection. That push uses `base_revision = synced_revision`, so the server preserves a branch if the head moved. Nothing is silently lost (review B6).

**Detection algorithm** (`secretsync/detect_local_changes.go`). Inputs: index `D`, sidecar `H`, snapshot `S`. `S` is the `local_map` rows plus `meta.index_generation` and `meta.index_seq`.

0. **Store target and generation.** If `D.Generation` is non-empty and differs from the pinned generation, refuse with exit 2 `store_target_changed`. The index was replaced or comes from another home.
1. **Legacy rewrite.** `D.Seq == 0 && S.index_seq > 0` means an older binary rewrote the index. This is **not** a rollback.
   - Run a legacy diff: an entry is a candidate edit when its timestamps or its `value_mac` (read in one batch) differ from the snapshot.
   - A missing ref is **never** treated as a delete; it gets repair (step 4).
   - Stderr warns once that deletes from that older AgentKit do not sync.
2. **Restore.** `D.Seq > 0 && D.Seq < S.index_seq` with the same generation means the index was restored from a backup. Enter **repair**:
   - for each snapshot row, compare the current `value_mac` with `row.value_mac`;
   - **equal:** apply the remote head (`ApplySynced` with `expect = current entry seq`);
   - **different:** do **not** overwrite. Treat it as a local edit and push it with `base_revision = row.synced_revision`, so it becomes a branch if the remote moved. Report `skipped_repair` and exit 12.
   - push no tombstones this cycle.
3. **Normal diff.** For each entry `e` in `D`:
   - no snapshot row: a create, or the join merge (6.3);
   - `e.Seq > row.entry_seq`: read the value in the batch, recompute `value_mac` and `meta_mac`. If changed, it is an update; if not, record the new seq only.
4. **Missing refs.** For each snapshot row absent from `D`:
   - `D.Deleted` holds the name with `seq > row.entry_seq`: tombstone;
   - otherwise the ref vanished: repair it from the head (`ApplySynced` with `expect = 0`) and report `repaired: vanished`.
5. **Mass-delete guard.** More than `max(5, 20% of live synced items)` tombstones in one cycle stops before pushing unless `--allow-mass-delete` is given (exit 12, `mass_delete_blocked`).

**Unsynced local change** (used by the pull; review S8). A ref has one when either:

- the current `value_mac` differs from the `value_mac` of the head this device last applied or pushed (`local_map.value_mac`); or
- an open conflict branch on the item was authored by this device.

While either holds, a new remote head is recorded but not applied locally.

Values are read only for candidate refs, in one batch. A cycle with no local change never opens the backend.

## 5. Local sync state

### 5.1 Layout, pinning, classification

```
AGENTKIT_HOME/secrets/sync/            0700
  config.json   0600
  sync.db       0600  SQLite (modernc.org/sqlite, already a dependency), WAL
  sync.lock           lockhome lock, one sync cycle at a time
  keys.age      0600  file keystore only
```

`config.json`:

```json
{"schema_version":1,"enabled":true,"install_id":"...","vault_origin":"https://vault.agentkit.best",
 "registry_url":"https://agentkit.best","vault_id":"...","device_id":"...","account":"...",
 "enabled_at":"...","setup_state":"complete",
 "store_target":{"backend":"keychain","index_path":"/abs/.../index.json","vault_path":"/abs/.../vault.age",
                 "keystore_backend":"keychain","index_generation":"..."}}
```

- **`setup_state`** is one of `sealed`, `genesis_uploaded`, `bundle_uploaded`, `items_uploaded` or `complete`. It drives `enable --resume` (6.2).
- **Store target pinning** (review B8). Every sync command except `status` resolves the Store config through the normal `storeConfig` (`secretscmd/backend.go:33-46`) and compares it with `store_target`. Any difference is exit 2 `store_target_changed`, with a message naming which field differs (paths and backend names only). `status` reports `store_target_ok:false` instead.
- **Moving the store** requires `sync disable --purge` and then re-enrolling, or a future explicit `sync retarget` (not in scope).
- **Contents.** `config.json` holds identifiers and local paths only; it is the cheap "enabled" check. `sync.db` is not `operationalstore`, is never in the operational outbox, and holds only ciphertext, HMACs and public membership data.

New surface in `docs/conformance/operational-data-surfaces.yaml`:

```yaml
- id: secrets-sync-state
  authority: secret-store
  data_class: secret
  privacy: E2EE sync state; ciphertext, HMACs and public membership data, never plaintext
  sync_eligibility: never
  rebuild_strategy: n/a
  retention_authority: device owner
  backup_treatment: secret-store-separate
  conflict_policy: n/a
```

### 5.2 Schema (`syncstate`, `PRAGMA user_version = 1`)

```sql
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
-- cursor, index_generation, index_seq, highest_bundle_seq, trust_anchor, recovery_sign_pub,
-- last_pull_at, last_push_at, last_error, alarm, audit_seq, audit_head, limits_json
CREATE TABLE membership_events (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, event_json TEXT NOT NULL);
CREATE TABLE membership_state (id INTEGER PRIMARY KEY CHECK (id = 1), state_json TEXT NOT NULL);
CREATE TABLE device_history (device_id TEXT PRIMARY KEY, sign_pub TEXT NOT NULL, added_seq INTEGER NOT NULL,
  added_by_recovery INTEGER NOT NULL, removed_seq INTEGER, fence_log_seq INTEGER);
CREATE TABLE witnessed_checkpoint (id INTEGER PRIMARY KEY CHECK (id = 1), checkpoint_json TEXT NOT NULL);
CREATE TABLE peer_checkpoints (author TEXT PRIMARY KEY, checkpoint_json TEXT NOT NULL, received_at_ms INTEGER NOT NULL);
CREATE TABLE state_digests (log_seq INTEGER PRIMARY KEY, state_digest TEXT NOT NULL); -- after each applied change
CREATE TABLE items (item_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, tombstone INTEGER NOT NULL,
  tombstone_revision INTEGER NOT NULL, head_digest TEXT NOT NULL, head_log_seq INTEGER NOT NULL,
  key_epoch INTEGER NOT NULL, head_record_json TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'secret',
  quarantined INTEGER NOT NULL DEFAULT 0);
CREATE TABLE record_digests (item_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY (item_id, digest));
CREATE TABLE conflicts (conflict_id TEXT PRIMARY KEY, item_id TEXT NOT NULL, log_seq INTEGER NOT NULL,
  record_json TEXT NOT NULL, resolved_at_log_seq INTEGER);
CREATE TABLE local_map (name_mac TEXT PRIMARY KEY, item_id TEXT NOT NULL UNIQUE, entry_seq INTEGER NOT NULL,
  value_mac TEXT NOT NULL, meta_mac TEXT NOT NULL, synced_revision INTEGER NOT NULL, local_only_reason TEXT);
CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, item_id TEXT, method TEXT NOT NULL,
  path TEXT NOT NULL, body BLOB NOT NULL, idempotency_key TEXT NOT NULL, record_digest TEXT,
  created_at_ms INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT);
CREATE TABLE apply_pending (item_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, op TEXT NOT NULL,
  expect_entry_seq INTEGER NOT NULL);
CREATE TABLE pending_enroll (role TEXT PRIMARY KEY, json TEXT NOT NULL, expires_at_ms INTEGER NOT NULL);
CREATE TABLE needs_rotate (item_id TEXT PRIMARY KEY, since_epoch INTEGER NOT NULL);
CREATE TABLE device_labels (device_id TEXT PRIMARY KEY, label TEXT NOT NULL);
```

- `state_digests` holds one row per applied change: `ComputeStateDigest(StateRows(items))` after that change. This lets any peer checkpoint at `log_seq <= cursor` be checked, including positions replayed in earlier cycles (review B4).
- Rows below the oldest checkpoint still held by a current peer and below `witnessed.log_seq` may be pruned.
- The digest is computed incrementally per item: rebuild the sorted row list only for touched items, using `akv1.StateRows` on the full map. Recomputing per change costs O(items). Items are capped at 2000 per vault (`akv:worker/src/limits.ts`), which is acceptable. P5 benchmarks it.

### 5.3 Anti-rollback state

- `witnessed_checkpoint` is the highest checkpoint this device signed after a verified pull.
- `highest_bundle_seq` is passed as `KnownBundleSeq` to `OpenRecoveryBundle`. A **fresh** recovering device has no such state (`KnownBundleSeq: 0`) and cannot detect a bundle rollback. This is documented as a limitation (review S5); acceptance criterion 6 covers only devices that know a higher seq.
- The age-file `.hwm` mark protects the local vault file. The sync checkpoint protects against the server. They are independent: `ak secrets recovery accept-rollback` never touches sync state.

### 5.4 Crash safety and locking

**Pull pages.** Each verified pull page commits in one transaction: membership, items, digests, conflicts, `state_digests`, `cursor`, and `apply_pending` rows carrying `expect_entry_seq`.

**Local apply.** After that commit, `ApplySyncedBatch` runs. A second transaction updates `local_map` and clears `apply_pending`. On the next cycle, leftover `apply_pending` rows are replayed. A row whose precondition fails is dropped; the ref then flows through the push path.

**Outbox.**

- Rows are inserted before any network call. They carry a fixed `Idempotency-Key` and body, so a retry is byte-identical.
- Before a resend the cycle pulls. An item row whose `record_digest` appears in the log is marked done.
- Rows older than 23 h are rebuilt with a new key only after that check.
- Membership rows that fail with 400 because the chain moved are rebuilt against the new head with a **new** key (6.3).

**Locking invariant** (review S2). No Store lock, backend lock, keystore lock or SQLite write transaction is held across an HTTP call.

- The engine is structured as: network phase (fetch and verify into memory), then local phase (one SQLite transaction plus one Store batch).
- A test wraps the transport so it fails if any lock-tracking hook reports a held lock during `Do`.
- `sync.lock` (one cycle at a time) is the only lock held across the network. `resolve` never takes it.

## 6. Flows (exact HTTP)

### 6.1 Transport (`secretsync/akvhttp`)

```go
type ClientConfig struct {
    BaseURL     string        // pinned vault origin
    ProofOrigin string        // equals BaseURL except local wrangler dev (test-only setter)
    Tokens      TokenSource
    SignSeed    []byte
    DeviceID    string
    HTTPClient  *http.Client  // 15 s per request
}
func New(cfg ClientConfig) (*Client, error) // only caller: secretsync.Open after config.json says enabled, and the enable/add/recover bootstrap
func (c *Client) Do(ctx context.Context, method, pathAndQuery string, body []byte, scope Scope, opts ...RequestOption) (Response, error)
func WithIdempotencyKey(k string) RequestOption
func WithDeviceKeyHeader(signPubB64 string) RequestOption // recovery identity only
type APIError struct{ Status int; Code, Message string; RetryAfter time.Duration }
```

**Every request:**

- `Authorization: Bearer <token>`.
- `AKV-Proof: akv1.BuildProof({HTM, HTU: ProofOrigin + pathAndQuery, TS: now ms, Token, Body, SecretKey: seed})` (`akv:go/akv1/proof.go:80`), with a fresh `jti` per attempt. `htu` includes the query string (`akv:worker/src/routes/api-handler.ts:47`).
- Mutations also carry `Idempotency-Key` and a cjson body.

**Error mapping is keyed on `error.code`, not on the status** (review nit):

| Code | Exit and reason |
|---|---|
| `quota_exceeded` | exit 1 `quota`. The status is 413 for the envelope cap and 403 elsewhere. |
| `unauthorized` | re-mint the token once, then exit 14 |
| `invalid_signature` on the proof (401) | exit 14; on records it is exit 13 |
| `forbidden` on a read (403) | exit 14 `device_removed` (`akv:worker/src/vault/request-guard.ts:61-66`) |
| `rate_limited` | honor `Retry-After` (`request-guard.ts:24-25`); exit 11 |
| `sync_disabled` | exit 11 `server_disabled` |

`GET /v1/meta` caches `limits` in `meta.limits_json`, which sets page sizes and caps.

### 6.2 Enable (genesis), crash-safe and resumable

1. **Preconditions** (2.3). Resolve the origin (6.10). `GET /v1/meta`.
   - **Second-vault guard:** there is no account-to-vault lookup on the Worker or ak-web today, and the owner decided against an ak-web pointer. `enable` therefore cannot detect an existing vault for the account, and relies on the stderr hint. This is tracked as **O1**. If ak-vault adds an owner-scoped lookup later, `enable` refuses with exit 4 when it finds one.
2. **Local setup.** Generate device keys and `LSK`, and pin the store target. Write `config.json` with `enabled:false` and the keystore entries.
3. Mint a token with scope `vault:read vault:write`. `account = sub`.
4. **Generate keys and genesis.**
   - `vault_id`, `VK[1]`, the recovery signing seed `rs`, and `rk = GenerateRecoveryKey()`.
   - `genesis = BuildGenesisEvent(vault_id, now, did, {vault_kind:"personal", owner_account, recovery_sign_pub, devices:[record]}, seed)`.
   - `wrap = WrapToDevice({VK[1], vault_id, 1, did, kx_pub})`.
5. **Seal before any upload** (review B9).
   - Genesis-time checkpoint: `cp0 = SignCheckpoint({vault_id, membership_seq: 0, membership_head: hash(genesis), log_seq: 0, state_digest: ComputeStateDigest(nil), key_epoch: 1, ts, author: did}, seed)`.
   - `bundle = SealRecoveryBundle({vault_id, BundleSeq: 1, VK:{1:VK[1]}, OwnerSignPub: sign_pub, RecoverySignSK: rs, Checkpoint: cp0, Password, RK: rk})`.
   - In one transaction, insert outbox rows: genesis `PUT /v1/vaults/{vid}` with `{event, wraps:[wrap]}`, then `PUT /recovery` with `{bundle}`. Store `VK[1]`. Set `setup_state = sealed`.
   - Zero `rs`. `rk` is used only for the kit.
6. **Write or print the recovery kit**, then start uploading. If the kit cannot be written, stop before any upload and delete local state.
7. `PUT /v1/vaults/{vid}`: expect 201. Persist the event and state, and pin `trust_anchor`. Set `setup_state = genesis_uploaded`.
8. `PUT /v1/vaults/{vid}/recovery`: expect 200 `{bundle_seq:1}`. Set `highest_bundle_seq = 1` and `setup_state = bundle_uploaded`.
9. Upload every local ref through the push path (6.4), with progress on stderr, honoring rate limits (120 requests/min/device). Set `setup_state = items_uploaded`.
10. Run a full cycle (6.5), which signs and posts the first real checkpoint. Set `enabled:true` and `setup_state = complete`.

**Crash or interruption:**

- Before step 7 returns 201: `enable` (or `enable --resume`) re-sends the stored genesis with the same key. A 201 or a replayed 201 continues the flow. The password is not needed again because the bundle is already sealed.
- At any later state: `enable --resume` (also suggested by `now` with exit 10) continues from `setup_state`. Nothing is regenerated, so the printed kit stays valid.
- `enable` without `--resume` on a partial setup prints the resume hint and exits 4.

### 6.3 Add a device with SAS

Codes are `akj1-` or `ako1-` followed by `b64(cjson(obj))`.

**Joiner, step 1 (`devices add`):**

1. The origin comes from **this device's environment** (6.10), never from the offer (review S3).
2. Mint a token for the new keys. `account = sub`. Generate `nonce_j`.
3. Print the join code `{v:1, ctx:"agentkit/akv1-join", account, device:{device_id, sign_pub, kx_pub, account, role:"owner", kind:"human"}, nonce_j, label}`. Store it in `pending_enroll(joiner)` (15 min).

**Owner (`devices approve <J>`):** TTY required, agent refusal applies.

1. **Validate the join code.**
   - `kid(sign_pub) == device_id`;
   - `account == state.owner_account`;
   - the device is not current and was never removed;
   - the label is ASCII.
2. Generate `nonce_i`. Set `in = SASInput{vault_id, initiator: own did, joiner, nonce_i, nonce_j}` and display `SASCode(in)`.
3. Print the offer code `{v:1, ctx:"agentkit/akv1-offer", vault_origin, vault_id, initiator, joiner, nonce_i, nonce_j, trust_anchor, checkpoint}`. The checkpoint is the owner's `witnessed_checkpoint`, authored by the owner.
4. On `y`: build wraps of every epoch the owner holds to the joiner, with `wraps_digest = WrapsDigest(those wraps)` **[#20]**.
   - `event = NextMembershipEvent(state, "device_add", now, own did, {device, sas: SASDigest(in), wraps_digest}, seed)`.
   - `POST /v1/vaults/{vid}/membership` with `{event, wraps}`: expect 201.
5. **Race** (review S1). A concurrent append makes the event fail chain linking with **400** `bad_request` (`akv:go/akv1/membership_log.go:160-168`). Re-pull membership, rebuild the event with a **new** idempotency key, and retry up to 3 times.

**Joiner, step 2 (`devices add --offer O`):** agent refusal applies.

1. **Validate the offer.**
   - `offer.vault_origin == configured origin` (else exit 2);
   - `joiner == own did`;
   - `nonce_j` equals the pending value.
2. Show `SASCode(in)` and get the user's confirmation (TTY) or `--confirm-sas`.
3. Poll `GET /v1/vaults/{vid}/membership?from=0&limit=1000`, paging until `has_more:false`, every 3 s. 403 means "not yet". Give up at `--wait`.
4. **Verify.** All of the following must hold; any failure is exit 13, and pending state is deleted.
   - (a) `VerifyMembershipChain(events, {VaultID, TrustedAnchor: offer.trust_anchor, Witnessed: {offer.checkpoint.membership_seq, membership_head}})`.
   - (b) `offer.initiator` is an **owner device** in the prefix state at `offer.checkpoint.membership_seq`, and `offer.checkpoint.author == offer.initiator`. `VerifyCheckpoint(offer.checkpoint, prefixState)` succeeds (review B2).
   - (c) There is exactly one `device_add` for this did. Its `author == offer.initiator` (review B2), its `sas == SASDigest(in)`, and its seq is greater than `offer.checkpoint.membership_seq`.
5. **Fetch and check the wraps.**
   - Fetch the wrap set delivered with that event: `GET /wraps?rcpt=<did>&membership_seq=<event.seq>` **[#20]**.
   - Require `WrapsDigest(set) == event.body.wraps_digest` **before unwrapping anything** **[#20]** (review B1).
   - `UnwrapFromDevice` each wrap into the keystore.
   - Wraps for epochs created by later rekeys are verified through 6.5 step 3.
6. Set `witnessed_checkpoint = offer.checkpoint` and `enabled:true`.
7. **First full replay** (6.5). It must also reproduce `offer.checkpoint.state_digest` at `offer.checkpoint.log_seq` (review B4), else exit 13.
8. **Join merge.** For each local ref that matches a remote name:
   - equal value and meta: link;
   - different: push a base-0 branch and keep the local value (exit 12).

   Local-only refs become new items.

### 6.4 Push

For each candidate from 4.4 (current epoch only; never while `rekey_required`):

1. **Build the record.**
   - `env = SealItem(VK[e], ItemContext{vault_id, item_id, base_revision, key_epoch: e, author: did, tombstone}, payload, nil)`.
   - `rec = SignRecord(SignedRecord{..., TS: now, Resolves, Env: env}, seed)`.
   - Insert an outbox row with body `cjson(rec)`, a key, and `record_digest`.

   VK authenticity: every `VK[e]` used here came from genesis, this device's own rekey, the recovery bundle, a `device_add` wrap set checked against its signed `wraps_digest`, or a rekey wrap set checked with `VerifyRekeyWraps`. A VK from any other path is never stored.
2. **Send** `PUT /v1/vaults/{vid}/items/{iid}` and handle the response:

   | Response | Action |
   |---|---|
   | 200 | Set `local_map.synced_revision` and `value_mac`. |
   | 409 `conflict` with `conflict_id` | The branch is preserved on the server. Keep the local value. Exit 12. |
   | 409 `tombstoned` | `DeleteSynced(ref, expect = current entry seq)`. Report `discarded: deleted_remotely`. Exit 12. A later `set` re-creates the item with `base_revision = tombstone revision`. |
   | 409 `conflict` without `conflict_id` | Idempotent replay; done. |
   | 409 `rekey_required`, or 400 epoch mismatch | Pull, and finish or await the rekey. Rebuild rows at the new epoch. |
   | 422 `idempotency_mismatch` | Rebuild once with a new key. |
   | `quota_exceeded` | Exit 1. |
   | `rate_limited`, 5xx, network | Keep the row; exit 11. |

### 6.5 Pull and verification

A cycle runs pull, push, pull, then checkpoint. The pull below is the network phase. All fetches happen before any local write.

1. **Peer checkpoints first** (review B4). `GET /v1/vaults/{vid}/checkpoints` gives the set `P`; record `received_at`. The Worker stores a checkpoint only if `log_seq <= currentLogSeq` (`akv:worker/src/vault/checkpoint-store.ts:17`), and the log and chain are append-only. So once `P` is fetched first, a later head below any `p` in `P` is a real contradiction, not a race.
2. **Membership.** `GET /membership?from=<local seq + 1>&limit=1000`, paged.
   - Append and verify the full stored chain with `VerifyMembershipChain(all, {VaultID, TrustedAnchor, Witnessed: witnessed})`.
   - Update `device_history`.
   - For each recovery-authored `device_add` not performed by this device, add `attention: recovery_enrollment` (exit 12).
   - Handle `recovery_rotate` **[#20]** by updating the pinned `recovery_sign_pub`.
   - A 403 `forbidden` means this device was removed: exit 14 `device_removed`.
3. **New key epochs.** For each new epoch `e` from a `rekey` event `R`:
   - fetch the full stored set `GET /wraps?key_epoch=<e>&set=rekey` **[#20]** (review B3);
   - run `VerifyRekeyWraps(R, set, &stateAfterR)`;
   - unwrap this device's wrap.

   A failure is exit 13 `wrap_substituted`.
4. **Changes.** `GET /changes?cursor=<cursor>&limit=<changes_page_max>` until `has_more:false`.
   - **Membership head check.** If `head.membership_seq` is **less than** the verified chain seq: rollback (exit 13). If it is **greater**: another device appended between reads. Re-run step 2, at most 3 times per cycle, then give up with exit 11 (no alarm). If equal: `head.membership_head` must equal the chain head, else fork.
   - **For each change in `log_seq` order**, check the author:
     - current device: `VerifyRecord(record, state)`;
     - removed device: verify with the #20 historical rule **[#20]** (`VerifyHistoricalRecord(record, history, fence)` or the merged equivalent). The record must verify under the author's `device_add` `sign_pub`, have `key_epoch <=` the highest epoch while a member, and have `log_seq <=` `device_history.fence_log_seq`. Before a fence is known, never apply it as a head. Past the fence it is exit 13 `post_fence_record`;
     - unknown author: exit 13.
   - **Replay** with `ApplyRecord(&itemState, rec, change.conflict_id)`. The outcome (kind, revision, conflict ID) must match the server's, else exit 13 `fork`.
     - Resolution of a branch is taken from replay (`resolves`), not from `resolved_revision` (review nit).
     - Per-item `key_epoch` never decreases on the head.
     - Append a row to `state_digests`.
   - **Decrypt the head** of a `secret` item with `OpenItem`.
     - `decrypt_failed` on a record that passed signature checks: set `items.quarantined = 1`, never apply the record locally, report `quarantined` and `item_quarantined` (exit 12). This is an integrity alarm for **that item only** (owner decision). Other items continue.
     - The quarantine clears when a later valid head on the item decrypts.
     - Otherwise, if the ref has no unsynced local change (4.4), queue `apply_pending` with `expect_entry_seq`.
5. **Rollback check after replay** (review B4). Compute `state_digest` at `head.log_seq` from `state_digests`. Then run:

   ```
   CheckRollback(witnessed.View(), {vault_id, membership_seq/head from the verified chain, log_seq: head.log_seq, state_digest, key_epoch: head.key_epoch})
   ```

   `CheckRollback` (`akv:go/akv1/checkpoints.go:123-143`) flags a strictly lower seq or epoch, or a different head or digest at an equal seq. An idle cycle with an unchanged head therefore passes, because the digest is equal.
6. **Peer checks against `P`.** For each `p` in `P`:
   - `VerifyCheckpoint(p, prefixState(p.membership_seq))`;
   - if `p.log_seq > head.log_seq` or `p.membership_seq > head.membership_seq`: exit 13 `withheld`;
   - otherwise `p.state_digest` must equal `state_digests[p.log_seq]` (or the digest of an empty vault at 0), else exit 13 `fork`;
   - a checkpoint by another device with `membership_seq >= removal_seq` of a removed device X sets `X.fence_log_seq` to the minimum such `log_seq` (the removal fence **[#20]**);
   - store `p` in `peer_checkpoints`.
7. **Local phase.** One SQLite transaction, then `ApplySyncedBatch` (5.4).
8. **Checkpoint.** After the push and the second pull, if anything changed:
   - sign and post a checkpoint `{vault_id, membership_seq, membership_head, log_seq: head.log_seq, state_digest, key_epoch, ts, author: did}` to `POST /checkpoints` (expect 201);
   - store it as `witnessed_checkpoint`;
   - a 400 (state moved past it) means re-pull once.

**Alarms.**

- Exit-13 alarms persist in `meta.alarm`, and later `sync now` runs refuse.
- To recover: `sync disable --purge`, then either re-enroll with `devices add` or run `sync recover`. `recover` requires a non-enabled home, so purge comes first (review nit).
- Local secrets keep working throughout.

### 6.6 Conflicts and settle

- **Branches** are rows in the `conflicts` table.
- **`status`** decrypts branch payloads on demand to compute `same_as_local` and `same_as_head`. No value or hash is printed.
- **`settle <ref> --keep X`** collects every open branch ID of the item into `resolves`.

**Head is live:** write one record with `base_revision = head revision`, `resolves = all`, and a payload of:

- `local`: the local value;
- `remote`: the head payload;
- `branch:<id>`: that branch's payload, or a tombstone if the branch is a tombstone.

**Head is a tombstone** (review S6). A tombstone on an already-deleted item is `bad_request` before `resolves` is checked (`akv:go/akv1/record_state.go:101-103`).

- `--keep local` or `branch:<id>` (live branch): write one non-tombstone record with `base_revision = tombstone revision` and `resolves = all`. This re-creates the item.
- `--keep remote` (stay deleted): write two records.
  1. A re-create with `base_revision = tombstone revision`, `resolves = all`, and the payload of the newest live branch. That value is already readable by every member in the branch, so nothing new is exposed.
  2. A tombstone with `base_revision = that revision`.

  Other devices apply only the final head of a cycle. A device that pulls between the two records applies and then deletes the value, which is a harmless churn.
- ak-vault follow-up **O3**: a spec rule allowing a resolves-only tombstone on a deleted item would make this one record. It is optional.

**Races and local apply:**

- If the head moved meanwhile, the 409 creates a new branch: exit 12, run `settle` again.
- If the chosen payload differs from local, `ApplySynced` runs after the push succeeds, with the expected-seq precondition.

### 6.7 Delete

- **Local delete** (4.4 step 4) becomes a tombstone record.
- **Remote tombstone** becomes `DeleteSynced(ref, expect)`. If the precondition fails because the ref was set again locally, the next push sends that value with `base_revision = synced_revision` and gets `tombstoned`, so the value is discarded and reported.
- A stale device can never resurrect a deleted credential.

### 6.8 Remove device: fence, rekey, reseal

1. **Collect inputs before any write.**
   - The password, and either the current recovery key or `--new-recovery-key`. `SealRecoveryBundle` needs both a password and a recovery key (`akv:go/akv1/recovery_bundle.go:48-66`), and neither is cached on the device.
   - `GET /recovery`, then `OpenRecoveryBundle` with each. This verifies them and yields `recovery_sign_sk` and every epoch's VK.
2. `device_remove{device_id, reason}`: `POST /membership` with `{event}`, expect 201. The vault is now `rekey_required`.
3. **Fence checkpoint immediately** **[#20]** (review B5). Pull to the current head (writes are refused, but reads work), then sign and `POST /checkpoints` with `membership_seq >= removal seq`.
   - The Worker accepts checkpoints while `rekey_required` (`akv:worker/src/vault/checkpoint-store.ts:14-30` has no rekey check).
   - Any record by the removed device after this checkpoint's `log_seq` is rejected by every client.
4. **Rekey.**
   - Generate `VK[e+1]`, with wraps to every remaining device (`ValidateWrapRecipients(..., {RequireAll: true})`).
   - `needs_rotate` lists every live, non-policy item, or `[]` for a `retired` self rotation (3.4).
   - The `rekey` event carries `wraps_digest`. `POST /membership` with `{event, wraps}` stores both atomically.
5. Pull, then sign and post a checkpoint. Seal a bundle with `bundle_seq = highest + 1`, all epochs' VKs, `OwnerSignPub = own sign_pub` and that checkpoint, then `PUT /recovery`.
   - The bundle is capped at 16 KiB (`akv:worker/src/limits.ts:32`), which allows roughly 200 retained epochs. Every removal or rotation adds one.
   - `status` warns above 150 epochs. Pruning epochs is out of scope (open item O4).
6. Print the needs-rotate list and the ak-web session reminder.

Steps 2 to 5 are outbox entries. `devices remove --resume` finishes them. The removal fence must be posted before the rekey is attempted.

### 6.9 Recovery on a fresh device (needs `go/v0.2.0`)

1. **Prepare.** Email login of the owner account; new device keys; a token with scope `vault:read vault:write`. The origin comes from the kit or the environment, and must match the environment's origin unless hidden `--vault-origin` is given.
2. **Fetch and open the bundle.** `GET /v1/vaults/{vid}/recovery` with `AKV-Device-Key: <b64 sign_pub>`, then `OpenRecoveryBundle({Bundle, VaultID, Password|RK, KnownBundleSeq: 0})`.
3. **Read and verify membership.** `GET /v1/vaults/{vid}/membership?from=0&limit=1000` with `AKV-Device-Key` (recovery identity read **[#20]**), paged.
   - Verify with `Witnessed = {bundle.checkpoint.membership_seq, membership_head}`.
   - `bundle.checkpoint.author == kid(owner_sign_pub)`, and the checkpoint verifies against the prefix state.
   - The chain's `recovery_sign_pub` (after any `recovery_rotate`) must equal the bundle's `RecoverySignPub`, else exit 13.
   - Pin `trust_anchor`.
4. **Enroll.** Sign `device_add{device: own record, sas: "", wraps_digest}` **[#20]** with the recovery signing key, authored `kid(recovery_sign_pub)`, with self wraps for every bundle epoch. `POST /membership` with `{event, wraps}`. On a 400 race, re-read and retry.
5. **Pull.** Full replay (6.5), refusing anything behind or forked from the bundle checkpoint. Apply everything to the local Store.
6. **Remove the other devices** unless the user deselects them in the TTY list (`--remove-others`).
   - For each: `device_remove`, then the fence checkpoint (6.8 step 3).
   - Then rekey (6.8 step 4).
7. **`recovery_rotate`** (6.12), then reseal with a new recovery key and the current or new password, at `bundle_seq + 1`. Write or print the new kit.
8. Remind the user to revoke all ak-web sessions (ak-vault key-lifecycle doc).

### 6.10 Vault token and origin

**Origin per environment**, from the configured registry (`registryurl`, `registry_url.go:17-18`):

| Registry | Vault origin |
|---|---|
| `https://agentkit.best` | `https://vault.agentkit.best` |
| `https://staging.agentkit.best` | `https://vault-staging.agentkit.best` |
| anything else | requires hidden `--vault-origin` |

The origin is pinned at enable or join, and the token `aud` is exactly that origin (ak-vault PR #19).

**Token request.** `POST {registry}/api/agentkit/vault/token`:

- **Header:** `Authorization: Bearer <CLI session token>`.
- **Body:** `{sign_pub, scope (sorted), ts, sig}`.
  - `ts` is **unix seconds** (owner decision).
  - `sig = akv1.SignDetached("akv1/vault-token-request", {aud, scope, sid, sign_pub, ts}, seed)`.
- The call is wrapped in `auth.WithReauth` (`reauth.go:41`).

**Response** (owner decision): `{access_token, token_type: "Bearer", expires_in, did}`.

- The CLI checks `did == own did`.
- It decodes the JWT payload without verifying it (the Worker verifies) to read `sub` (the account), `aud` (must equal the pinned origin) and `exp`.
- The token is cached in memory only, per process and scope. It is re-minted 30 s before `exp` or after one 401. It is never written to disk or logs.

**`sid` is the CLI session ID** (owner decision): `Session.SessionID` (`auth/store.go:24`, `store-slots.go:77`).

- Email-OTP sessions have it (`session_response.go:23`; kept on rotation, `reauth.go:153`).
- API-key re-mints (`reauth.go:110`) and license sessions do not. Those get exit 14 `session_without_sid` with "run `ak login` with your email" until ak-web follow-up **W2**.

**Staging.** Until ak-web#568 is live on staging, the staging Worker trusts only a test issuer, so the CLI cannot mint staging tokens. The soak waits for **W1**. Local e2e tests inject a test `TokenSource`.

### 6.11 Encrypted audit stream (needs `go/v0.2.0`)

**Key** **[#20]:**

```
AuditKey[e] = HKDF(VK[e], salt = vault_id, info = "akv1/audit-key" || epoch)
```

The exact derivation and API come from #20. Each entry has `kid = e<epoch>`, and verification selects the key per entry.

**Events** are appended after each cycle that wrote. Each is `{"v":1, "type": ..., "item_id"?, "revision"?, "device_id", "ts"}` with no names. `type` is one of:

- `item_put`, `item_delete`
- `conflict_settled`
- `device_add`, `device_remove`
- `rekey`
- `recover`, `recovery_rotate`

**Flow:**

1. `GET /audit?cursor=<audit_seq>` (inclusive cursor, `akv:worker/src/vault/audit-store.ts:61-79`) to get the head.
2. Call `AppendAuditEntry` per event under `AuditKey[current]`.
3. `POST /audit` with `{start_seq, prev, entries, checkpoint}`.
4. On 409, refetch and reseal, up to 3 times.

The local `secrets-audit` is never sent.

### 6.12 Recovery-key rotation (`sync rotate-recovery`, needs `go/v0.2.0`)

1. **Collect inputs.** The current password (to open the bundle). With `--change-password`, also a new password, entered twice. `GET /recovery` and open the bundle.
2. **Generate** a new recovery signing seed `rs2` and a new recovery key `rk2`.
3. **Post the event.** The owner device signs `recovery_rotate{recovery_sign_pub: pub(rs2)}` **[#20]** and posts `POST /membership` with `{event}`. On a 400 race, retry.
4. **Reseal.** Pull and checkpoint. Reseal with `bundle_seq + 1`, `RecoverySignSK: rs2`, `RK: rk2` and the current or new password. `PUT /recovery`.
5. **Write or print the new kit.** The old kit's key opens no current bundle. The old recovery signing key can no longer author membership, because the Worker and every client verify against the rotated `recovery_sign_pub`.

The kit is written before step 3, and step 3 and later are outbox entries, so a crash never leaves a rotated key without a kit.

## 7. Gates

### 7.1 Sync off means zero HTTP

**Structural rules:**

- `akvhttp.New` is reachable only from `secretsync.Open` and the bootstrap paths of `enable`, `devices add` and `sync recover`.
- `secretsync.Open` returns `ErrSyncDisabled` without I/O beyond reading `config.json`.
- There is no package-level `http.Client` and no `init()` I/O.
- `runtime/secrets` never imports `runtime/secretsync/...`. A `go list -deps` test enforces this.
- Non-sync `ak secrets` commands never call `secretsync`.

**Behavioral sweep** (reusing the `feat/vault-sync-off-gates` rig, which also excludes `secrets` from lazy auto-update):

- Every `ak secrets` leaf runs in a temp `AGENTKIT_HOME` with sync off.
- `HTTP_PROXY`/`HTTPS_PROXY` point at a counting listener, and the registry and vault origins at counting `httptest` servers.
- Expected results (review S9):

| Command (sync off) | Expected |
|---|---|
| Every v1 `ak secrets` command | zero connections |
| `sync status`, `sync disable` | zero connections, exit 0 or 10 |
| `sync now`, `settle`, `rotate-recovery`, `devices list/approve/remove/rotate` | zero connections, exit 10 |
| `enable`, `devices add`, `sync recover` | **use the network by design**. The test asserts zero connections until arguments and local preconditions validate (exercised with invalid flags, the memory backend, no session, and an already-enabled home), and asserts connections go **only** to the configured registry and vault origin when preconditions pass. |

### 7.2 Resolve never waits on the network

- `resolve` reads only the `Store` (`resolver.go:16`, `:88`). Sync never holds a Store or backend lock across HTTP (5.4).
- **Test setup:** sync enabled; the vault origin is a listener that accepts connections and never answers (plus a closed-port variant); a `--watch` process is blocked mid-pull.
- **Pass:** `ak secrets resolve` returns within its normal bound, and the resolve process makes no connection.
- Offline messages appear only in sync commands.

### 7.3 Warm resolve overhead below 50 ms p95

**Rig** (from the gates branch, extended here):

- release build;
- temp home with the file backend and a cached test passphrase, 50 refs, and one allow grant;
- 1 warm-up run, then 200 timed runs of `ak secrets resolve <ref> --json` per arm.

**Arms:**

- (a) sync off.
- (b) sync on, with `sync now --watch --interval 5s` against the local Worker, and an index of 2000 refs plus 1000 journal entries. Nothing changes remotely.
- (c) **as (b), with a second device pushing 5 changed items every interval**, so the watcher applies remote changes concurrently through `ApplySyncedBatch` while resolve runs (review S2).

**Pass:** `p95(b) - p95(a) < 50 ms` and `p95(c) - p95(a) < 50 ms`.

**Also:**

- An in-process `BenchmarkResolverResolveWarm` covers the index sizes above.
- A keychain-backend run on a developer macOS host is recorded, not gated.
- Results are recorded with machine, OS, Go version and commit.

### 7.4 Offline behavior

| Situation | Behavior |
|---|---|
| Network down, `sync now` | exit 11 `offline`; outbox kept |
| `--watch` offline | backoff from 15 s to 5 min; status shows `last_error` |
| `sync_disabled` | exit 11 `server_disabled` |
| ak-web down | exit 11 |
| ak-web 401/403 | exit 14 |
| Alarm | exit 13, sync halted, local secrets unaffected |

## 8. Dependency and vectors

### 8.1 Module

**Now:** `apps/cli/go.mod` gets

```
require github.com/bestagentkits/ak-vault/go v0.1.0
```

(tag `go/v0.1.0` at `544ebcf`), imported as `github.com/bestagentkits/ak-vault/go/akv1`.

- agentkit already has `golang.org/x/crypto v0.50.0` and `x/text v0.36.0`, above ak-vault's versions, so minimal version selection keeps agentkit's.
- Only P2 edits `go.mod`.

**ak-vault#20 changes protocol v1 wire behavior** (event bodies, a new event, a new route filter and the audit key). The client must move to **`go/v0.2.0`**, a new tag cut after #20 merges, in a dedicated bump PR that:

1. updates `require` to `v0.2.0`;
2. re-vendors the vectors from the tagged commit and updates `SOURCE.json`;
3. adapts any changed signatures.

These phases cannot merge before the bump: P5 (rekey set verification and historical authors), P7 (wraps digest, recovery read, `recovery_rotate`) and P8 (audit key). P1 to P4 and the transport do not depend on #20.

### 8.2 Vectors: vendor a pinned copy

**Decision:** vendor `protocol/v1/vectors/*.json` from the tagged commit into `apps/cli/internal/runtime/secretsync/testdata/akv1-vectors/`, with `SOURCE.json` holding `{repo, tag, commit, files:{name: sha256}}`.

**Reasons:**

- Tests stay hermetic.
- akv1's own vector tests load `../../protocol/v1/vectors` outside the module zip (`akv:go/akv1/vectors_harness_test.go:22-30`), so they cannot run from the module cache.
- agentkit links a newer x/crypto, and running the vectors in agentkit's build proves the combination agentkit ships.

**Tests:**

- `TestVendoredVectorsMatchSource` checks every file's sha256 against `SOURCE.json`.
- `TestAKV1Conformance` (`secretsync/akv1_conformance_test.go`) is a dispatcher over the functions agentkit calls, and adds the #20 vectors after the bump. It is replaced by an exported `akv1test.RunVectors` if ak-vault provides one (O2).

## 9. Phases

Each phase merges to `dev` alone, with tests, behind hidden commands. No two phases running in parallel own the same file.

| # | Phase | Depends on | Parallel with | Effort |
|---|---|---|---|---|
| P1 | Store groundwork: generation, seq, sidecar high-water mark, deletion journal, `ApplySynced`/`DeleteSynced` with expected seq, `ApplySyncedBatch`, `ReadValues`, `IndexSnapshot` | - | P2 | 2d |
| P2 | Module `v0.1.0`, keystore (pinned backend), vendored vectors and conformance | - | P1 | 1.5d |
| P3 | `akvhttp`: client, proof, code-keyed errors, `Retry-After`, vault token source (ts seconds, response shape) | P2 | P4 | 2d |
| P4 | `syncstate` schema, store, outbox; item mapping | P2 | P3 | 2d |
| P4b | Bump to `go/v0.2.0` and re-vendor vectors | ak-vault#20 merged and tagged; P2 | P3, P4 | 0.5d |
| P5 | Engine: detection and repair, pull ordering and verification (digest history, rekey set, removal fence, quarantine), push, conflicts and settle (incl. tombstone heads), checkpoints, resumable enable; minimal fake Worker and fault proxy | P1, P3, P4, **P4b** | - | 5d |
| P6 | CLI `sync enable/status/now/settle/disable` with exit codes, agent refusal, store-target check, help goldens | P5 | P7 engine part | 2d |
| P7 | Devices (SAS with author and wraps-digest checks, list, approve, remove with fence/rekey/reseal, rotate), `sync recover`, `sync rotate-recovery` | P5, P6, **P4b** | P8 | 4.5d |
| P8 | Encrypted audit append (per-epoch audit key) | P5, **P4b** | P7 | 1d |
| P9 | Gates: zero-HTTP sweep incl. new commands, offline resolve, lock-across-HTTP test, three-arm benchmark | P6, P7, `feat/vault-sync-off-gates` merged | P10 docs | 2d |
| P10 | Docs, e2e against local Worker at the v0.2.0 commit, soak tooling and evidence | P7, P8, P9; ak-web W1 for the soak | - | 2d |

The total is about 24.5 days, including P4b's 0.5d. The critical path is ak-vault#20 → P4b → P5.

### File ownership

- **P1:**
  - `runtime/secrets/index.go`
  - `runtime/secrets/store.go` (seq bump in Set/Delete only)
  - new `runtime/secrets/index_sequence_sidecar.go` and `runtime/secrets/store_synced_writes.go`
  - tests `index_seq_test.go`, `store_synced_writes_test.go` (includes the race test: a concurrent `Set` between snapshot and `ApplySynced` returns `ErrSyncPreconditionFailed`), and `index_legacy_rewrite_test.go`
  - the `agefile.go` batch helper if needed for one decrypt per batch
- **P2:**
  - `apps/cli/go.mod`, `go.sum`
  - `runtime/secretsync/keystore/*`
  - `runtime/secretsync/testdata/akv1-vectors/**`
  - `runtime/secretsync/akv1_conformance_test.go`, `runtime/secretsync/doc.go`
- **P3:** `runtime/secretsync/akvhttp/{client.go, proof_headers.go, api_error.go, vault_token_source.go, vault_origin.go}` and tests.
- **P4:** `runtime/secretsync/syncstate/{schema.go, store.go, outbox.go, items.go, membership.go, local_map.go, state_digests.go}` and tests; `runtime/secretsync/item_payload_mapping.go` and test.
- **P4b:** `go.mod`, `go.sum`, `testdata/akv1-vectors/**`, `akv1_conformance_test.go`. P2 is finished by then, so ownership passes.
- **P5:**
  - `runtime/secretsync/{engine.go, open.go, store_target.go, detect_local_changes.go, pull_changes.go, verify_membership.go, verify_rekey_wraps.go, historical_authors.go, peer_checkpoints.go, push_outbox.go, apply_local.go, checkpoints.go, conflicts_settle.go, enable_genesis.go, errors.go}` and tests
  - `runtime/secretsync/internal/akvfake/*`
  - `runtime/secretsync/internal/faultproxy/*`
- **P6:**
  - `commands/secretscmd/{sync_cmd.go, sync_enable.go, sync_status.go, sync_now.go, sync_settle.go, sync_disable.go, sync_render.go, sync_exit_codes.go, devices_cmd.go (empty parent)}`
  - `secretscmd.go` (registers both parents)
  - `render/json.go` (`SyncErrorInfo`)
  - `testdata/help/secrets_sync*.txt` and the `secrets.txt` golden
- **P7:**
  - `runtime/secretsync/{enroll_codes.go, enroll_joiner.go, enroll_approver.go, removal_fence.go, rekey.go, recovery_bundle_reseal.go, recover.go, recovery_rotate.go, rotate_device.go}` and tests
  - `commands/secretscmd/{devices_list.go, devices_add.go, devices_approve.go, devices_remove.go, devices_rotate.go, sync_recover.go, sync_rotate_recovery.go}`
  - `devices_cmd.go` (owned from P7 on)
  - `sync_cmd.go` registrations for `recover` and `rotate-recovery`. P6 is merged by then, so ownership passes.
  - `testdata/help/secrets_devices*.txt`, `secrets_sync_recover.txt`, `secrets_sync_rotate_recovery.txt`
- **P8:** `runtime/secretsync/audit_append.go` and test.
- **P9:** `commands/secretscmd/sync_gates_test.go`, `runtime/secretsync/lock_across_http_test.go`, `runtime/secrets/resolver_bench_test.go` (or the gates branch's file), and the bench script named by the gates branch.
- **P10:**
  - `docs/system-architecture.md` (ledger entry and "Secrets sync limits")
  - `docs/guides/secrets.md`
  - `docs/conformance/operational-data-surfaces.yaml`
  - `kits/core/skills/ak-ak/references/command-reference.md`
  - `runtime/secretsync/e2e/*` (build tag `akvault_e2e`)
  - `tools/vault-soak/*`

### Rollback per phase

- **P1:** revert. Older code ignores the new index fields, and `index.seq` is an inert file.
- **P2 to P5, P8:** new packages; revert freely.
- **P4b:** revert to `v0.1.0` only if no #20-dependent phase has merged.
- **P6/P7:** commands are hidden, so reverting removes them. Tester state is removed with `sync disable --purge`, or by deleting `secrets/sync/` and the keychain entries `akv1/<install_id>/*`.
- Staging data is synthetic.

## 10. Test strategy

### 10.1 Unit

**P1:**

- seq and generation; sidecar resume after a legacy rewrite; deletion-journal cap;
- `ApplySynced`/`DeleteSynced` preconditions, including absent-is-0;
- batch apply in one lock;
- legacy index load;
- GUI `secrets_api` tests unchanged.

**P2:**

- keystore round trip per backend; pinned backend ignores a `--backend` override;
- install-id isolation; Windows entry size;
- file keystore mode 0600;
- vectors.

**P3:**

- the proof verifies with `akv1.VerifyProof` (GET with query, PUT with body);
- idempotent retry; a single re-mint on 401;
- each code maps to the right exit, including 413/403 quota, 401 proof, and 403 forbidden as `device_removed`;
- `Retry-After` is honored;
- the token request signing input is exact (seconds `ts`), and the response's `did`/`aud` are checked;
- a missing `sid` gives `session_without_sid`;
- the token never appears in errors.

**P4:**

- schema; outbox order; rollback leaves the cursor unchanged;
- mapping round trip (UTF-8, binary, unknown meta, sensitivity, oversize, invalid name).

**P5 detection table:**

- create, edit, touched-but-unchanged;
- delete with journal, vanished;
- restore with an unchanged ref (repaired) and with a changed ref (skipped and pushed as a branch);
- legacy rewrite (no delete, no revert);
- generation mismatch (exit 2);
- mass-delete guard;
- concurrent-create canonicalization.

### 10.2 Integration (fake Worker plus fault proxy)

Per review S10, most behavior runs against the **real Worker** (`wrangler dev`, 10.3) through `internal/faultproxy`. This is an `httptest` reverse proxy that can delay, drop, reorder or rewrite responses: roll back `/changes`, hide a `/checkpoints` entry, swap a wrap, replace a record signature, return 403, or return 429 with `Retry-After`.

`internal/akvfake` is kept minimal. It is an in-process server used only for:

- unit-speed engine tests on Go-only CI;
- states the real Worker refuses to produce, such as a forked chain or a post-fence record.

It is built only from akv1 functions plus an idempotency map. No quotas or revocation.

**Tests (both harnesses where applicable):**

- **Two engines A and B:**
  - propagation;
  - simultaneous edit, branch, and settle on a live head;
  - settle on a tombstone head with all three `--keep` modes;
  - delete versus offline edit (no resurrection);
  - concurrent create;
  - replay of a lost response.
- **No-false-alarm suite** (review B4):
  - idle cycles x 10;
  - B appends membership between A's `/membership` and `/changes`;
  - B pushes and posts a checkpoint between A's reads;
  - all pass without an alarm.
- **Each fault**, giving exit 13 with the expected reason: rollback of `/changes`, membership rollback and fork, a hidden newer log against a peer checkpoint, a forged signature, a post-fence record by a removed author, a swapped `device_add` wrap, a bad rekey set, a wrong-epoch envelope. Local Store unchanged, and later cycles refuse.
- **Quarantine:** a member-signed record whose envelope decrypts with the wrong key quarantines that item only, and other items still sync.
- **Enrollment:**
  - an offer whose `device_add` is authored by another device (anchor swap) is refused;
  - an offer with a foreign `vault_origin` is refused;
  - the joiner verifies `offer.checkpoint.state_digest` during replay.
- **Removal:**
  - remove B on A: B gets exit 14; A posts the fence before the rekey;
  - new writes are unreadable with B's keys;
  - a forged B record after the fence is rejected.
- **Recovery:** after a later `device_add`, recovery succeeds via the recovery membership read; `rotate-recovery` makes the old kit fail.
- **Local races:**
  - a local `set` between pull commit and apply is never overwritten;
  - a legacy-binary index rewrite does not revert.
- **Store target:** a run with `--backend file` against a keychain-pinned vault gives exit 2.
- **Agent refusal:** every command in 2.2 under a stubbed adapter ancestry gives exit 6 plus an audit row.
- **`grants.json`** is byte-identical after a full sync with policy items.
- **Redaction:**
  - captured stdout, stderr and JSON contain none of the synthetic values, tokens or recovery keys, and names only in allowlisted `ref` fields;
  - a scan of `sync.db` and `config.json` finds no synthetic name or value.

### 10.3 End to end against a local Worker

`runtime/secretsync/e2e`, build tag `akvault_e2e`. `AKVAULT_DIR` points to an ak-vault checkout at the `go/v0.2.0` commit.

- **Setup:**
  - generate an ephemeral P-256 key;
  - start `pnpm --dir $AKVAULT_DIR/worker exec wrangler dev --env staging --port <free> --var VAULT_ISSUER:https://e2e-issuer.invalid --var VAULT_JWKS_JSON:<public jwk>`;
  - use a test `TokenSource` that mints ES256 tokens with aud `https://vault-staging.agentkit.best`;
  - `ProofOrigin` is `http://vault-staging.agentkit.best` (`akv:worker/scripts/staging-smoke.ts:7-9`);
  - the fault proxy sits in front.
- **Flows:** enable (including a kill after the genesis upload, then `--resume`), SAS add (codes and confirmation passed through the engine API, not the CLI), push and pull, conflicts and settle, tombstone, remove with fence, rekey and reseal, recover after a later `device_add`, rotate-recovery, rotate.
- **Cleanup:** stop wrangler and delete its `.wrangler/` state.
- **Schedule:** a scheduled `ak-vault-e2e` job, not part of the default gate.

### 10.4 Staging soak: 7 days, 2 devices (owner decision)

Starts when ak-web#568 mints staging tokens (W1) and staging runs the #20 Worker. Synthetic data only.

1. Two machines on the staging registry with fresh homes, logged in to the same staging test account.
2. A runs `enable --recovery-kit-out`. B runs `devices add`, and A runs `devices approve`; the operator compares the SAS.
3. Both run `sync now --watch --json` under a service manager.
4. `tools/vault-soak/workload.sh` drives:
   - every 5 min, set or rotate one of 20 synthetic refs;
   - hourly, delete and re-create one ref, plus a same-ref write on both machines within 2 s, settled from A;
   - every 6 h, B offline for 30 min;
   - once per day, `rotate-recovery` on A.
   - A propagation probe: A sets a probe ref, and B records when `sync status --json` shows the probe item's new revision. No values are read.
5. **Collect:**
   - propagation p50, p95 and p99;
   - errors by `reason`, and alarms (must be 0);
   - quarantines (must be 0);
   - maximum outbox depth and rate-limit hits;
   - `peer_checkpoint_age_s`;
   - resolve benchmark on both machines;
   - a redaction scan of the logs.
6. **Post evidence** on ak-vault#8 and agentkit#2298 with commits and versions. **Clean up:** `sync disable --purge` on both machines and delete the soak homes.

## 11. Decisions (owner-decided unless marked)

| # | Decision | Status |
|---|---|---|
| D1 | `ak secrets sync recover` (not `ak secrets recover`); `settle` for conflicts; `sync now` replaces push/pull; `devices remove` replaces revoke; new `sync rotate-recovery` | owner-accepted |
| D2 | Commands hidden until the external review on ak-vault#8 | owner-decided |
| D3 | No background push on `set`/`delete`; propagation needs `sync now` or `--watch` | owner-decided |
| D4 | No vault pointer in ak-web for now; second device joins via `devices add`; `enable` refuses an existing vault only once a lookup exists (O1) | owner-decided |
| D5 | Password minimum 12 characters; no breached-password check | owner-decided |
| D6 | `decrypt_failed` on a validly signed record quarantines that item and raises an item-level integrity alarm (exit 12 `item_quarantined`); the vault keeps syncing | owner-decided |
| D7 | Soak 7 days, 2 devices | owner-decided |
| D8 | ak-web token contract: `ts` unix seconds; response `{access_token, token_type, expires_in, did}`; `sid` = CLI session ID; API-key sessions are W2 | owner-decided |
| D9 | Recovery key never stored on a device; remove, rotate and rotate-recovery ask for it or generate a new one | design |
| D10 | Join by copy-paste codes plus SAS, both sides confirm; approve only in a TTY, never by an agent | design |
| D11 | Local device keeps its own value while it has an unsynced change or an own open branch | design |
| D12 | `recover` always rotates the recovery key and the recovery signing key | design |

## 12. Changes needed outside agentkit

**ak-vault#20** (being implemented; tag `go/v0.2.0` after merge) covers every blocking protocol item:

1. `device_add.body.wraps_digest`, with posted wraps required to match. Clients verify it before unwrapping, and the Worker serves the wraps delivered with a given `device_add` (`?membership_seq=`).
2. The full rekey wrap set as uploaded (`GET /wraps?key_epoch=e&set=rekey`), not filtered by current devices.
3. `membership.get` for the recovery identity (spec 3.5 and 9.4, threat-model I4).
4. A per-epoch HKDF audit key, with a multi-epoch `VerifyAuditChain`.
5. The removal fence for records by removed authors, plus a client verification function and vectors.
6. A `recovery_rotate` event.

The client needs confirmation of three things when #20 merges:

- exact field, route and query names;
- the Go function name for historical-author verification;
- that the Worker serves the `device_add` wrap set by `membership_seq` (item 1). If #20 serves it differently, 6.3 step 5 follows the merged route.

**ak-vault follow-ups** (non-blocking, file as `ai-handle`):

- **O1:** an owner-scoped "vaults for this account on this origin" lookup, so `enable` can refuse a second vault. No such lookup exists today.
- **O2:** export the vector harness (`akv1test.RunVectors`).
- **O3:** allow a resolves-only tombstone on a deleted item (6.6).
- **O4:** recovery-bundle epoch growth versus the 16 KiB cap.
- **Docs drift** (review S11): `docs/security/key-lifecycle-and-recovery.md:32-33` still says the SAS transcript is undefined (spec 3.5 defines it), and `:61-63` conflicts with spec section 4 on older-epoch delivery. Both should be fixed in #20 or a docs PR.

**ak-web:**

- **W1:** vault token endpoint live on staging, trusted by the staging Worker, before the soak. Production only after #8.
- **W2** (open follow-up): give API-key sessions a `sessionId`, or bind `sid` server-side, so non-OTP sessions can sync.
- **Token contract** (decided, D8): ak-web must implement exactly `{access_token, token_type, expires_in, did}`, unix-seconds `ts`, and `sid` = CLI session ID.

## 13. Risks

| Risk | L | I | Mitigation |
|---|---|---|---|
| #20 slips, blocking P5/P7/P8 | M | H | P1 to P4 and P6 scaffolding proceed on v0.1.0; P4b is a small bump PR |
| #20 final names differ from this design | M | L | **[#20]** markers; re-check at P4b |
| Restored, legacy or replaced index reverts or deletes data | M | H | Generation, sidecar, preconditions, repair never overwrites a changed ref, legacy never deletes, mass-delete guard, store-target pin |
| False alarms halt users | M | H | Checkpoints fetched first, strict-lower rule, re-read on append, digest after replay, no-false-alarm suite, soak target 0 |
| User loses recovery kit and password | M | H | Kit written before upload; `rotate-recovery`; documented unrecoverable |
| Second vault created by `enable` on another device | M | M | Hint; O1 |
| Agent enrolls a device | L | H | TTY-only approve plus agent refusal (speed bump, as documented for `approve`) |
| File-backend lock contention under remote churn | M | M | Batch APIs, no lock across HTTP, benchmark arm (c) |
| Freeze attack (server hides peer checkpoints) | L | M | `peer_checkpoint_age_s` warning; documented limitation |
| Fresh recovering device cannot detect bundle rollback | L | M | Documented; bundle checkpoint plus recovery membership read still bound the state |
| Recovery bundle epoch growth | L | M | Warning above 150 epochs; O4 |
| Name or value exposure via `sync.db` | L | H | HMAC under LSK, ciphertext only; DB scan test |

## 14. Docs impact

- **`docs/system-architecture.md`:** ledger entry (section 1) plus "Secrets sync limits":
  - vault-wide key;
  - server-visible metadata;
  - freeze-attack limitation and the peer-checkpoint age warning;
  - fresh-device bundle-rollback limit;
  - the removal-fence window;
  - no re-seed;
  - the deletion journal keeps deleted names in `index.json`.
- **`docs/guides/secrets.md`:** enable and resume, add a device, conflicts and settle, remove and rekey, recover, rotate-recovery, offline behavior, store-target pinning, limits.
- **`docs/conformance/operational-data-surfaces.yaml`:** `secrets-sync-state`.
- **`kits/core/skills/ak-ak/references/command-reference.md`:** new commands, after unhide.
- **agentkit-docs:** an issue for the user docs; no website impact until GA.

## Unresolved questions

- Q1. Does the Desktop app ship its own bundled `ak` binary? If yes, legacy index rewrites (4.4 step 1) will be common until Desktop updates. That is safe by design, but deletes from Desktop will not sync until then.
- Q2. Does ak-web restrict the vault-token `aud` to the known vault origins? This bounds a hidden `--vault-origin` misuse; the joiner already ignores the offer's origin.
- Q3. The exact #20 names (fields, `?membership_seq=` / `?set=rekey`, and the historical-verification and multi-epoch audit Go APIs) are to be confirmed at P4b.
- Q4. O1: should ak-vault add an owner-scoped vault lookup so `enable` can refuse a second vault, or is the hint enough for v1?

Status: DONE_WITH_CONCERNS
Summary: Revision 2 fixes all 10 review blockers and applies every should-fix item. Protocol gaps are rewritten against ak-vault#20, and #20-dependent phases (P5, P7, P8) are gated on a `go/v0.2.0` bump (P4b). Owner decisions are recorded as decided, and exit codes are renumbered to avoid secretscmd's existing 6 to 9.
Concerns: #20 field and route names are provisional ([#20] markers); second-vault detection has no lookup today (O1); API-key sessions cannot sync until W2.
