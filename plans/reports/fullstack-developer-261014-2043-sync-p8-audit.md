# Sync client: encrypted audit append (status: completed)

- Plan: `plans/261013-1320-8-client-web-gates` (design §6.11, spec §7)
- PR: bestagentkits/agentkit#2380, squash-merged to `dev` as `92a3eb3cb`
- Issue: one-line comment posted on agentkit#2298

## Files

All files are in `apps/cli/internal/runtime/secretsync/`.

| File | Lines | Role |
|---|---|---|
| `engine.go` | +56/-7 | Additive changes: two required audit limits; events queued right after the push; the audit step at the end of the cycle; audit error codes; `last_error` ranking (device_removed, then push_refused / quota_exceeded, ahead of audit codes) |
| `audit_events.go` | 193 | Event vocabulary from design §6.11, strict parsing, record-to-event mapping, applied-write diff |
| `audit_chain_verify.go` | 191 | Stored tip, joined epoch, entry-by-entry verifier using the key of each entry's epoch |
| `audit_chain_read.go` | 197 | Paged read from the stored tip, head and peer checkpoint checks, completion of logged rows |
| `audit_outbox_batch.go` | 207 | Batch rows, fit check, re-seal, own-row decrypt |
| `audit_append.go` | 203 | Queue (hard cap 64, quota brake), seal plus signed checkpoint, three read/re-seal/send attempts |
| `audit_send_rows.go` | 62 | POST each row; answer must equal the batch end; rollback answer raises the fork alarm |

Six test files: `audit_append_test.go`, `audit_append_faults_test.go`, `audit_append_negative_test.go`, `audit_append_cycle_test.go`, `audit_events_test.go`, `audit_harness_test.go`.

## Required tests

All use akvfake, plus faultproxy where noted.

- **Per-epoch key:**
  - `TestAuditKeyIsDerivedPerEpoch`
  - `TestAuditVerifierSelectsTheKeyOfEachEntryEpoch`
  - `TestAuditQueuedBeforeRekeyIsResealedAtTheNewEpoch`
  - `TestAuditDeviceJoinedAfterRekeyAppends`
- **Idempotent and retry-safe:**
  - `TestAuditLostAnswerIsNotAppendedTwice` (faultproxy)
  - `TestAuditLostAnswerOvertakenByAPeerIsNotDuplicated`
  - `TestAuditMovedHeadIsResealedAndRetried`
  - `TestAuditRepeatedConflictStopsAfterThreeAttempts`
  - `TestAuditCrashBetweenQueueAndSendKeepsTheEvent`
  - `TestAuditRekeyRaceIsRetriedWithoutAlarm`
  - `TestAuditPushFailingPartwayKeepsAppliedEvents`
  - `TestAuditFailureAfterThePushKeepsAppliedEvents`
- **Malformed or unknown entries fail closed:**
  - `TestParseAuditEventIsStrict`
  - `TestAuditUnknownEventIsRejectedWithoutHaltingSync`
  - `TestAuditUndecryptableEntryRefusesTheStreamOnly`
  - `TestAuditReadRefusesBrokenChainAnswers`
  - `TestAuditReadRefusesAReusedNonce`
  - `TestAuditAppendAnswerAtAnotherHeadAlarms`
  - `TestAuditAppendRollbackAnswerIsAFork`
  - `TestAuditRowOnlyPartlyInTheChainIsAFork`
  - `TestAuditChainGoingBackwardsAlarms`
  - `TestAuditPeerCheckpointsAreCheckedAgainstTheChain`
- **No secret names or values in plaintext:** `TestAuditRecordsOneIDOnlyEventPerAppliedWrite` decrypts every entry and checks that no synthetic ref or value appears. Events carry only `item_id`, `revision`, `device_id`, `ts` and `type`, which matches design §6.11 ("no names") and data classification.

## Fault policy (decided during review)

- **Persisted global alarms:** faults only the server can cause, because the worker refuses them on append:
  - a bad envelope, kid or decreasing epoch;
  - a reused nonce;
  - a replaced stored entry (fork) or a shortened chain (rollback);
  - a gap, an oversized page or bad paging;
  - a head or checkpoint past the read (withheld);
  - a POST answer at another head;
  - a POST rollback answer.
- **`ErrAuditRejected`, no alarm:** faults any writer could cause, because entries carry no author signature and the server cannot open them:
  - an entry that does not open;
  - an unknown or malformed event.
  - Audit appends stop and item sync continues; `last_error` is `audit_rejected`.

This avoids one bad writer halting secret sync for the whole vault. The threat model already lists unsigned audit entries as a limitation.

## Evidence

Final head `990750ad7` (origin/dev `9e06105b2` merged in).

- `go test -race -count=1 ./internal/runtime/secretsync/... ./internal/commands/secretscmd/... ./internal/render/...`: all ok.
- `go vet`: clean. `golangci-lint` on secretsync: 0 issues.
- `PREFLIGHT_BASE=origin/dev bash tools/preflight.sh`: all gates passed. It flagged the os-specific matrix, so the PR carried the `os-specific` label.
- Full-module `go test ./...` on darwin: 221 packages ok. `kitcmd` (10-minute timeout under host load) and `runtimeprobe` (it found a real `omp` install on this host) failed. Neither depends on secretsync.
- CI: the first run had 2 jobs that no self-hosted runner picked up (infrastructure). One rerun went green. After merging dev, the run was green. The `full-suite` run on dev that the merge triggered was force-cancelled.
- Mutation checks are caught by tests for:
  - completing rows from the chain;
  - the page-size bound;
  - error-code precedence;
  - queueing on a partial push;
  - queueing after a failed post-push pull.
- Review: five fresh isolated reviews. The last one found no blockers or majors; its minor findings were fixed.

## Accepted trade-offs and known limits

- An event is lost if the process dies between the push and queueing, or when a PUT answer is lost and a later pull completes that row.
- Nonce uniqueness is checked within one read only. Peer checkpoints below the stored tip are not compared, and the client does not require its own checkpoint in the returned list.
- A rekey landing between the audit read and the POST reports `audit_bad_request` once; it heals next cycle. Epoch-ahead is retried without escalation.
- Re-sealing a row whose old-epoch key was dropped fails each cycle. This is bounded by the cap.
- The joined epoch comes from the last `device_add`; the recovery bundle's oldest epoch is not considered.
- `audit_outbox_batch.go` is 207 lines.

## Concerns for the orchestrator

1. **P7 membership events.** Nothing emits `device_add`, `device_remove`, `rekey`, `recover` or `recovery_rotate` yet. P7 should call `e.appendAudit(ctx, ps, lim, []AuditEvent{...})`. Spec §7 says the rekeyer MUST append at the new epoch right after a rekey.
   - Strict parsing per the design means a later change to the vocabulary or fields locks out older binaries. If membership events need a subject ID, decide that before the first release.
2. **`sync_status.go` `PendingPushes` counts audit rows.** That file was outside my ownership. It is worth an ai-handle issue.
3. **A full audit stream** (100k-entry cap, no retention) reports `audit_quota_exceeded` every cycle. Retention policy is an ak-vault question.

## Unresolved questions

- Should membership audit events carry a subject field (the added or removed device)? This has to be decided before P7 emits them and before any release.
- What retention or rollover applies to a full audit stream (ak-vault server)?
