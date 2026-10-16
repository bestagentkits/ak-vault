# Red-team evidence

Evidence for the [red-team scenarios](./release-gates.md#red-team-scenarios) gate of
[#8](https://github.com/bestagentkits/ak-vault/issues/8). Each row names the scenario,
the tests that exercise it, what the run showed and the GitHub issues it produced.
The tests own the details; this page points to them. It records a run and does not
replace the release gate: the gate is still checked on #8 at the release commit.

## Run

| Codebase | Commit | Suites |
|---|---|---|
| ak-vault | `main` plus the `red-team-*` tests added with this page; the tested head and its CI run are recorded in the comment on #8 that links this page | `pnpm test` (protocol + Worker in workerd), `go test ./...` |
| agentkit (sync client) | `dev` at [`5a9a55a`](https://github.com/bestagentkits/agentkit/tree/5a9a55a3b9afdf8221a38dab4118bc631404ae5e) | `go test` on `internal/runtime/secretsync/...` and `internal/commands/secretscmd/...`; `make vault-e2e` against this ak-vault head |

Worker tests run the real Worker, Durable Objects and SQLite storage inside workerd
([`worker/vitest.config.ts`](../../worker/vitest.config.ts)). Protocol rejection cases
are vectors under [`protocol/v1/vectors/`](../../protocol/v1/vectors/), checked by
both the TypeScript suite and Go `TestVectors`. Client paths below are relative to
agentkit's `apps/cli/internal/runtime/secretsync/` unless they say otherwise.

Result key: **Pass**, the attack is refused or detected. **Pass, finding**, refused,
with a separate gap filed. **Limitation**, behaves as the threat model's stated
limitation and is not claimed as detected. **N/A**, the feature under attack does
not exist yet.

## Scenarios

| # | Scenario | Evidence | Result | Findings |
|---|---|---|---|---|
| 1 | Wrong `iss`/`aud`/`alg`, unknown `kid`, expired or not-yet-valid token | [`auth-token.test.ts`](../../worker/test/auth-token.test.ts): "rejects %s" (wrong audience/issuer, expired, not yet valid, issued in the future), "rejects alg none, HS256 and unknown kid", "keeps production and staging audiences apart", "fails closed with 503 when the JWKS endpoint is unreachable"; [`jwks-cache.test.ts`](../../worker/test/jwks-cache.test.ts): "never serves expired keys while the issuer is down"; new [`red-team-token-and-proof.test.ts`](../../worker/test/red-team-token-and-proof.test.ts): attacker key presenting the trusted `kid`, embedded `jwk`/`jku`/`x5u`, ES256 signature relabelled as another `alg`. Client: `akvhttp` `TestWebTokenSourceRejectsMalformedOrForeignTokens`, `TestFetchMetaPinsTheIssuer` | Pass | Related open: [#29](https://github.com/bestagentkits/ak-vault/issues/29) |
| 2 | Stolen token without the device key; replayed proof; proof for another URL or body | `auth-token.test.ts` "proof of possession" block (missing, replayed `jti`, other URL/method/body, stale timestamp, stolen token); `proof.json` rejections (`wrong_htu`, `wrong_bh_other_body`, `wrong_ath_other_token`, `replayed_jti`, `signed_by_other_device`); new `red-team-token-and-proof.test.ts`: proof moved to another query string, to another token of the same device, between two vaults of one device, and a stolen token on every read and write route with the vault state unchanged | Pass, finding | [#41](https://github.com/bestagentkits/ak-vault/issues/41): refused proofs still spend the device's rate budget |
| 3 | Revoked session; revoked device; registry unavailable | [`revocation.test.ts`](../../worker/test/revocation.test.ts): revoked session on its next request with an unexpired token, revoked device in every session, `min_iat`, webhook authentication and replay, "returns 503 when the revocation registry cannot be reached". Client: `akvhttp` `TestDoStopsAfterSecondUnauthorized` | Pass | |
| 4 | Server injects a recipient or device into membership | Vectors: `membership.json` `injected_recipient`, `non_owner_author`, `non_member_non_recovery_author`; `device-add-wraps.json` `injected_key_for_joiner`, `injected_recipient`, `dropped_wrap_from_signed_set`; `rekey-wraps.json` `injected_recipient_*`. [`membership.test.ts`](../../worker/test/membership.test.ts): "refuses an injected wrap recipient", "refuses a device-adding event whose wraps do not match its signed wraps_digest"; [`authorization.test.ts`](../../worker/test/authorization.test.ts): "wraps are accepted only inside a signed event"; [`signed-wrap-sets.test.ts`](../../worker/test/signed-wrap-sets.test.ts). Client: `TestJoinRefusesSubstitutedWraps`, `TestTamperedMembershipAlarms` | Pass | |
| 5 | Stale membership or rollback after a witnessed checkpoint | Vectors: `checkpoints.json` `rollback.reject` (all five), `membership.json` `chain_behind_witnessed_checkpoint`, `chain_forks_from_witnessed_checkpoint`, `recovery-bundle.json` `rollback_lower_than_known`. [`checkpoints-audit.test.ts`](../../worker/test/checkpoints-audit.test.ts): "refuses rollback, forks and future state". Client: `TestMembershipRollbackAlarms`, `TestRollbackAlarmWhenLogGoesBackwards`, `TestRollbackAlarmOnPositionBelowCursor`, `TestRollbackAlarmOnDifferentRecordAtHeldPosition`, `TestAuditChainGoingBackwardsAlarms` | Pass | |
| 6 | Server withholds updates from a new device | New [`red-team-withheld-updates.test.ts`](../../packages/protocol/test/red-team-withheld-updates.test.ts): a frozen prefix (before a removal and rekey) verifies for a device with no witnessed checkpoint, and becomes `rollback` only against a second-channel checkpoint. Client: `TestHiddenLogAgainstPeerCheckpointAlarms` (detected only through a peer checkpoint the server chose to serve), `TestWithheldAlarmWhenHeldPositionIsNeverReached` (only positions the device itself holds). agentkit `docs/system-architecture.md` "Freeze attack" states it as a limitation | Limitation | Documented in the [threat model](./threat-model.md#explicit-limitations) ("Withholding never-seen updates"); client status of peer-checkpoint age: [agentkit#2400](https://github.com/bestagentkits/agentkit/issues/2400) |
| 7 | Concurrent writes, conflict resolution, retry with same and different idempotency body | [`items.test.ts`](../../worker/test/items.test.ts): "concurrent writers: one wins, the other gets 409 with a preserved branch", "same key + same body returns the stored response; a different body is 422", "a retried conflicting write returns the same conflict_id"; `records.json` `conflict_branch_and_resolve`; new [`red-team-concurrency-and-retry.test.ts`](../../worker/test/red-team-concurrency-and-retry.test.ts): six parallel writers, one key sent four times at once, one key with two bodies at once. Client: `TestConcurrentEditConflictIsSettled` (e2e), `TestConcurrentCreateDifferentValuesConflict`, `TestLostPushAnswerIsNotDuplicated`, `TestFaultLostItemAnswerThenRestart` | Pass | |
| 8 | Stale offline device replays writes below a tombstone | `items.test.ts`: "a stale offline device cannot resurrect a deleted secret", "a replayed record is refused and not preserved"; `records.json` `cas_tombstone_lifecycle`. Client: `TestDeleteIsNotResurrected` (e2e), `TestRestoreNeverUndoesADeletion`, `TestChainedEditAfterRemoteDeleteDoesNotResurrect` | Pass | |
| 9 | Rekey interrupted; recovery interrupted | `membership.test.ts`: "a rekey must carry a complete wrap set matching wraps_digest"; [`removal-fence-and-recovery-rotation.test.ts`](../../worker/test/removal-fence-and-recovery-rotation.test.ts): `recovery_rotate` "lands only with a resealed bundle"; new `red-team-concurrency-and-retry.test.ts`: a rekey whose answer was lost is replayed, a rekey rebuilt from stale state is refused, two owners racing rekeys land exactly one. Client: `TestRemoveDeviceResumesAfterEachCrash`, `TestRemoveDeviceSurvivesLostAnswers`, `TestRecoverResumesAfterEachCrash`, `TestUnfinishedRecoveryDoesNotExpire`, `TestRotateRecoveryResumesQueuedRotation`, `TestJoinResumesInterruptedFirstCycle`, `TestEnableResumesAfterTheGenesisAnswerIsLost` (e2e) | Pass | |
| 10 | Removed member reads new material; `needs-rotate` for the rest | `authorization.test.ts`: "a removed device loses access immediately"; `membership.test.ts`: "a removed device is denied and writes wait for rekey"; `removal-fence-and-recovery-rotation.test.ts`: writes by a removed device refused; vectors `removed_member_recipient`, `removed_member_older_epoch`, `removal-fence.json`; new [`red-team-removed-member.test.ts`](../../worker/test/red-team-removed-member.test.ts): after `member_remove` the old and a fresh device of the account read nothing, the rekey set has no wrap for them, and `needs_rotate` lists the exposed item. Client: `TestRemoveDeviceFencesRekeysAndReseals`, `TestRemovedDeviceIsFencedAndItsWritesRefused` (e2e), `TestRotateAfterAStoppedRemovalFlagsTheExposedItems` | Pass | Limitations stay as stated: no clawback; the fence binds the log as its remover verified it ([#21](https://github.com/bestagentkits/ak-vault/issues/21); `removal-fence-binds-log.test.ts`) |
| 11 | Reader and machine write; machine reads outside its vault | `authorization.test.ts` "read-only devices" block; `checkpoints-audit.test.ts` read-only cases; new [`red-team-tenant-and-role-isolation.test.ts`](../../worker/test/red-team-tenant-and-role-isolation.test.ts): reader and machine refused on every write route with no state change; a machine of the owner account refused on every item, change, wrap, checkpoint and audit route of another vault | Pass, finding | [#42](https://github.com/bestagentkits/ak-vault/issues/42) (open; the owner decided to fix it, via [ak-web#578](https://github.com/bestagentkits/ak-web/issues/578), before machine identities ship in #6): through the recovery-identity path that machine still fetches the other vault's encrypted bundle and membership. Related open: [#22](https://github.com/bestagentkits/ak-vault/issues/22), [#14](https://github.com/bestagentkits/ak-vault/issues/14) |
| 12 | Cross-tenant read with a valid token | `authorization.test.ts`: "another tenant's device cannot touch a vault it does not belong to", "a device presenting another account's sub is refused"; `auth-token.test.ts`: "a token whose did names a non-member device is forbidden"; [`recovery-fetch.test.ts`](../../worker/test/recovery-fetch.test.ts): "refuses another account"; new `red-team-tenant-and-role-isolation.test.ts`: another tenant's token and proof refused on every read and write route and on a genesis for the victim's vault ID, state unchanged | Pass | |
| 13 | Hostile shared profile or policy text widens a grant or runs a command | The attacked feature is not built: portable policy ([#7](https://github.com/bestagentkits/ak-vault/issues/7)) and agent discovery ([agentkit#2299](https://github.com/bestagentkits/agentkit/issues/2299)) are open. Existing guards: `policy.json` `malicious_policy_cannot_elevate`, `instruction_text_is_inert`, `unknown_field_grant_all` (TS and Go); client `TestLocalFromPayloadFailsClosed` (synced `policy` and `profile` kinds are never applied), `TestSpoofingNamesStayLocalAndAreNotApplied` | N/A | Re-run when #7 / agentkit#2299 land |
| 14 | Forked PR reads secrets or triggers a deploy | Configuration review of [`.github/workflows/`](../../.github/workflows/) and repository settings, below | Pass, findings | Hardening: [#43](https://github.com/bestagentkits/ak-vault/issues/43), [#44](https://github.com/bestagentkits/ak-vault/issues/44), [#45](https://github.com/bestagentkits/ak-vault/issues/45) |
| 15 | Planted plaintext and names in dumps, logs, metrics and errors | [`disclosure-scan.test.ts`](../../worker/test/disclosure-scan.test.ts): canaries in item names and values, audit, recovery password and keys, scanned across every Durable Object table, console line and response; new [`red-team-disclosure-scan.test.ts`](../../worker/test/red-team-disclosure-scan.test.ts): canaries in query strings, path segments, proof, idempotency and bearer headers, a device-key header on the recovery-identity path, webhook bodies and refused or oversize bodies, scanned across response bodies and headers, logs and both Durable Object dumps. agentkit e2e `checkLogRedaction` scans the `wrangler dev` log of the full e2e run (all nine scenarios passed against this head) for synthetic names, values, passwords, recovery keys and JWTs; a manual grep of that log also found no bearer, proof, idempotency-key, bundle or ciphertext fields. Client: `TestNoSecretInSyncState`, `akvhttp` `TestDoErrorsCarryNoSecretsOrPaths` | Pass (local) | Staging Workers Logs are not scanned with seeded traffic: the owner replaced the [staging soak](./release-gates.md#staging-soak) with the Docker e2e, whose scan found no hits; residual risk stated there |

## Scenario 14: workflow and settings review

Checked on 2026-10-15 against the workflows at the tested commit and the live
repository settings:

- **CI** runs on `pull_request`, never `pull_request_target`, with
  `permissions: contents: read` and no `secrets.*` reference, so fork code runs
  without credentials. The repository's default workflow token is read-only.
- **Deploy** runs on `workflow_run` and acts only when the CI run was a `push` to
  `main` that succeeded. A fork branch named `main` arrives as `pull_request` and is
  skipped. A manual dispatch needs write access and a green CI push run for the same
  commit.
- **Environments**: `staging` and `production` accept deployments only from `main`;
  `production` requires a reviewer. Cloudflare credentials are environment secrets
  exposed only to the deploy step; checkout uses `persist-credentials: false`;
  every action is pinned by commit SHA.
- The production reviewer may approve their own run during bootstrap. This is the
  recorded [bootstrap exception](./release-gates.md#production-deploy-control), not a
  new finding.

Gaps that a fork cannot exploit today, filed as hardening: an unused organization
secret is visible to this repository (#43), the `main` ruleset does not require a
pull request although AGENTS.md says it does (#44), and SHA pinning is a convention
rather than an enforced setting (#45).

## What this run does not cover

- **Platform logs, traces and metrics.** The Worker emits no metrics and its only log
  line comes from [`operational-logger.ts`](../../worker/src/http/operational-logger.ts);
  Cloudflare invocation logs are disabled
  ([data classification](./data-classification.md#handling-rules)). Locally,
  `wrangler dev` prints its own request lines with full paths (vault and item IDs,
  no bodies or headers), the counterpart of those disabled invocation logs. Workers
  Logs and traces on the real platform are not reproducible locally, and the owner
  replaced the staging soak with the Docker two-device e2e, so they stay unscanned;
  see the residual risk under [staging soak](./release-gates.md#staging-soak).
- **Client policy and discovery** (scenario 13), until the feature exists.
- **External review.** This run is the owner's agents testing their own code; it does
  not satisfy the [external review](./release-gates.md#external-review) gate.
