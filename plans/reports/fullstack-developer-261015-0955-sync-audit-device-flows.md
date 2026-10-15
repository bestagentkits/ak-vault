# Sync audit for device, rekey and recovery flows

The agentkit secrets sync client now writes audit entries for membership changes. It writes them from enroll approval, device removal (with rekey), recovery, recovery-key rotation and device key rotation, which closes the spec section 7 conformance gap.

- **PR:** bestagentkits/agentkit#2423 (base `dev`, label `os-specific`, Refs #2298)
- **Branch:** `fix/secrets-sync-audit-device-flows`
- **Worktree:** `/Volumes/GOON/www/claudekit/agentkit-wt-sync-audit-flows`
- **CI and merge:** see "CI and merge" below.

## What changed (apps/cli/internal/...)

- **`runtime/secretsync/audit_membership_events.go` (new):** builds audit events from the verified membership chain.
  - Only events this device authored count: `device_add` (one per added device, with a subject), `device_remove` (with a subject), `rekey` and `recovery_rotate`.
  - A recovery-authored add of this device becomes `recover`.
  - It contains `queueMembershipAudit`, which queues and moves the watermark in one transaction and reports whether it caught up. It also contains `recordMembershipAudit`, `sendQueuedAudit`, `auditBeforeKeySwitch` and `fatalAfterLanding`.
- **`runtime/secretsync/audit_events.go`:** new `subject_device_id` field.
- **`runtime/secretsync/audit_append.go`:** membership events bypass the item brake (quota / 64 rows) up to 128 rows, all or nothing.
- **`runtime/secretsync/audit_outbox_batch.go`:** `fits` also requires the checkpoint author to be the current device, so rows signed by a previous key are re-signed.
- **Flow wiring:**
  - `enroll_approver.go`, `recovery_rotate.go`: record after the change lands.
  - `removal_fence.go`, `recover.go`: queue before the bundle reseal or recovery-key rotation, send after it. Recovery clears the pending joiner enrollment before the send.
  - `rotate_device.go`: the switch to the new key is gated on the previous key's add being queued. Otherwise it returns a resumable error.
  - `engine.go` `runCycle`: queues anything above the watermark, as a backstop for stopped flows.
- **`runtime/secretsync/syncstate/state_digests.go`:** new rising meta key `audit_membership_seq`.
- **`runtime/secretsync/sync_status.go`, `commands/secretscmd/sync_render.go`:** `PendingPushes` / `pending_outbox` exclude audit rows. New `PendingAudit` / `pending_audit`, and the text line "audit batches waiting to send: N".
- **Tests:**
  - `audit_device_flows_test.go` (new);
  - `audit_events_test.go`: strict parser cases;
  - P8 tests adjusted for the membership entries their setup now produces.

## Decisions

- **Subject field:**
  - `subject_device_id` is required on `device_add` and `device_remove`, and refused on every other type. Unknown fields are still refused.
  - `device_id` stays the actor. `recover`, `rekey` and `recovery_rotate` carry no subject.
  - A device id is an opaque, non-secret identifier. No secret names or values appear in any entry, and tests assert this.
- **Spec section 7 rekey entry:** it is queued at the new epoch right after the rekey and post-rekey pull, and sent under a checkpoint the rekeying device signs. Tests verify the checkpoint covers the rekey entry's seq.
- **Crash safety:**
  - The rows and the watermark move together in one transaction.
  - A stop before queueing is finished by `--resume` or by the next sync (`runCycle`).
  - A stop after queueing leaves outbox rows that the next cycle sends.
- **After landing:**
  - Once a membership change has landed, audit errors do not fail the flow, except alarms, `ErrDeviceRemoved` and corrupt state.
  - Rows stay queued and visible in `pending_audit`.
  - The one exception is device key rotation: it refuses the switch rather than lose the previous key's `device_add`.
- **Backfill:** a home with no watermark backfills from membership seq 0. Only events this device authored are queued, so the backfill is bounded.
- **Older beta parsers:** beta.26/27 strict parsers refuse `subject_device_id`. On those clients only audit appends stop; item sync continues. This is accepted because sync is not GA and production sync is off.

## Evidence (head b864d7086, merged with origin/dev 83145b2b6)

- `go test -race -count=1 -timeout 50m` passed for:
  - `./internal/runtime/secretsync/...`: secretsync took 564s, plus akvhttp, akvfake, faultproxy, keystore and syncstate;
  - `./internal/commands/secretscmd/...` (391s);
  - `./internal/render/...`.
  - This run was before the last test-only commit. The focused race run (`TestAudit|TestMembershipAudit|TestParse`) after that commit also passed.
- `go vet`, `gofmt` and `golangci-lint` (0 issues) are clean on secretsync and secretscmd.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed, including commitlint. It asked for the `os-specific` label, which was applied.
- Mutation checks, each confirmed failing and then restored:
  - re-enabling the quota brake for membership events fails both braked-outbox tests;
  - bypassing the key-switch gate fails `TestAuditDeviceRotationWaitsForTheAddToBeQueued`;
  - sending the audit before the reseal fails `TestAuditAlarmAfterARemovalDoesNotStrandTheBundle`;
  - sending before the enrollment cleanup fails `TestAuditAlarmAfterARecoveryLeavesNoPendingEnrollment`;
  - dropping the checkpoint-author check in `fits` fails the device rotation test.
- Review rounds, each by a fresh isolated reviewer:
  - **Round 1:** two Majors, both fixed: the watermark moved past dropped events, and failures after landing failed the flows.
  - **Round 3:** Minors, fixed by the brake bypass.
  - **Round 4:** Minors 1-3 and Nits 1 and 3 fixed: the rotation gate, queue-before and send-after the reseal, the status wording, a test for a stop after the rotate add, and a PR docs-impact note.
  - **Delta round 5:** one Major, a stray `package.json` workspaces change from a `bun install`, now removed. A recovery-path alarm test was added.
  - **Delta round 6:** no Blocker or Major; the Minor (a test) and the Nit (a comment) were fixed.

## CI and merge

- **CI:** the one PR CI run was green on every required check: Go checks, Go vet on all platforms, kitcmd shards, risk-selected contracts, source policy, os-required and required.
- **Update-branch:** dev then moved with an unrelated sandbox change (#2422), so the branch was updated with `gh pr update-branch`. The required checks ran again and passed.
- **Merge:** squash-merged through auto-merge as `b5fed52ca6b48dac65ec7a73f90e8d1d3f8fb2ff`.
- **Dev full-suite run:** the run the merge triggered (38712578699) was cancelled.
- **Issue:** I commented on agentkit#2298.
- **Cleanup:** the worktree and the local and remote branches are removed, the scratch logs are deleted, and none of my test processes are still running.

## Concerns

- If the audit stream refuses on quota until the membership outbox reaches 128 rows, device key rotation refuses until it drains. This is fail closed by design. Rotation is also the response to a compromised key, so `devices remove` is the fallback. A runbook line may be worth adding.
- A local queueing error that keeps recurring before the key switch (for example a missing vault key) blocks every rotation resume until it is fixed. The error is returned as is, not wrapped as `ErrRotationPending`.
- `pending_audit` counts outbox batches. Events still above the watermark, after a stop before queueing, are not counted until the next cycle queues them.
- Design section 6.11 (a plan record) was not edited. The plaintext audit event schema, including `subject_device_id`, is defined only in code and tests, not in the ak-vault spec. The server never sees the plaintext.

## Unresolved questions

- Are any beta.26/27 devices syncing against staging? They would stop appending audit entries once a newer device writes a `subject_device_id` entry.
- Should the plaintext audit event schema be documented in the protocol spec, or stay client-defined?
- Should flow results (remove, recover, rotate) report the pending audit count, rather than leaving it to `sync status`?

Status: DONE_WITH_CONCERNS
Summary: Device, rekey and recovery flows now write crash-safe audit entries. The rekey entry lands at the new epoch under a signed checkpoint, and the status counts are separated. Evidence and reviews are green.
Concerns: Rotation fails closed when the membership audit outbox is full; the plaintext event schema is not in the spec; older beta parsers refuse the new field.
