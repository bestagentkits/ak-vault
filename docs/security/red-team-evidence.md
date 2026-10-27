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
| 2 | Stolen token without the device key; replayed proof; proof for another URL or body | `auth-token.test.ts` "proof of possession" block (missing, replayed `jti`, other URL/method/body, stale timestamp, stolen token); `proof.json` rejections (`wrong_htu`, `wrong_bh_other_body`, `wrong_ath_other_token`, `replayed_jti`, `signed_by_other_device`); new `red-team-token-and-proof.test.ts`: proof moved to another query string, to another token of the same device, between two vaults of one device, and a stolen token on every read and write route with the vault state unchanged | Pass, finding (fixed) | [#41](https://github.com/bestagentkits/ak-vault/issues/41): refused proofs spent the device's rate budget. Fixed: requests refused at authorization now count against a separate per-device budget ([`rate-limit.test.ts`](../../worker/test/rate-limit.test.ts)) |
| 3 | Revoked session; revoked device; registry unavailable | [`revocation.test.ts`](../../worker/test/revocation.test.ts): revoked session on its next request with an unexpired token, revoked device in every session, `min_iat`, webhook authentication and replay, "returns 503 when the revocation registry cannot be reached". Client: `akvhttp` `TestDoStopsAfterSecondUnauthorized` | Pass | |
| 4 | Server injects a recipient or device into membership | Vectors: `membership.json` `injected_recipient`, `non_owner_author`, `non_member_non_recovery_author`; `device-add-wraps.json` `injected_key_for_joiner`, `injected_recipient`, `dropped_wrap_from_signed_set`; `rekey-wraps.json` `injected_recipient_*`. [`membership.test.ts`](../../worker/test/membership.test.ts): "refuses an injected wrap recipient", "refuses a device-adding event whose wraps do not match its signed wraps_digest"; [`authorization.test.ts`](../../worker/test/authorization.test.ts): "wraps are accepted only inside a signed event"; [`signed-wrap-sets.test.ts`](../../worker/test/signed-wrap-sets.test.ts). Client: `TestJoinRefusesSubstitutedWraps`, `TestTamperedMembershipAlarms` | Pass | |
| 5 | Stale membership or rollback after a witnessed checkpoint | Vectors: `checkpoints.json` `rollback.reject` (all five) and `regrown_past_witnessed_passes_checkpoint_comparison_alone`, `removal-fence.json` `restored_regrown_*` and `restored_log_behind_kept_head` (a log restored below the witnessed position and regrown past it is refused against the kept head), `records.json` `replayed_older_revision`; [`red-team-replayed-policy.test.ts`](../../packages/protocol/test/red-team-replayed-policy.test.ts) and Go [`red_team_replayed_policy_test.go`](../../go/akv1/red_team_replayed_policy_test.go) (an older policy revision re-served by replay or by restore), `membership.json` `chain_behind_witnessed_checkpoint`, `chain_forks_from_witnessed_checkpoint`, `recovery-bundle.json` `rollback_lower_than_known`. [`checkpoints-audit.test.ts`](../../worker/test/checkpoints-audit.test.ts): "refuses rollback, forks and future state". Client: `TestMembershipRollbackAlarms`, `TestRollbackAlarmWhenLogGoesBackwards`, `TestRollbackAlarmOnPositionBelowCursor`, `TestRollbackAlarmOnDifferentRecordAtHeldPosition`, `TestAuditChainGoingBackwardsAlarms` | Pass; limitation for a device that resumes from its cursor | Limitation in the [threat model](./threat-model.md#explicit-limitations) ("A device resuming from its cursor does not see a restore below it"); agentkit client test for the regrown case: [#76](https://github.com/bestagentkits/ak-vault/issues/76) |
| 6 | Server withholds updates from a new device | New [`red-team-withheld-updates.test.ts`](../../packages/protocol/test/red-team-withheld-updates.test.ts): a frozen prefix (before a removal and rekey) verifies for a device with no witnessed checkpoint, and becomes `rollback` only against a second-channel checkpoint. Client: `TestHiddenLogAgainstPeerCheckpointAlarms` (detected only through a peer checkpoint the server chose to serve), `TestWithheldAlarmWhenHeldPositionIsNeverReached` (only positions the device itself holds). agentkit `docs/system-architecture.md` "Freeze attack" states it as a limitation | Limitation | Documented in the [threat model](./threat-model.md#explicit-limitations) ("Withholding never-seen updates"); client status of peer-checkpoint age: [agentkit#2400](https://github.com/bestagentkits/agentkit/issues/2400) |
| 7 | Concurrent writes, conflict resolution, retry with same and different idempotency body | [`items.test.ts`](../../worker/test/items.test.ts): "concurrent writers: one wins, the other gets 409 with a preserved branch", "same key + same body returns the stored response; a different body is 422", "a retried conflicting write returns the same conflict_id"; `records.json` `conflict_branch_and_resolve`; new [`red-team-concurrency-and-retry.test.ts`](../../worker/test/red-team-concurrency-and-retry.test.ts): six parallel writers, one key sent four times at once, one key with two bodies at once. Client: `TestConcurrentEditConflictIsSettled` (e2e), `TestConcurrentCreateDifferentValuesConflict`, `TestLostPushAnswerIsNotDuplicated`, `TestFaultLostItemAnswerThenRestart` | Pass | |
| 8 | Stale offline device replays writes below a tombstone | `items.test.ts`: "a stale offline device cannot resurrect a deleted secret", "a replayed record is refused and not preserved"; `records.json` `cas_tombstone_lifecycle`. Client: `TestDeleteIsNotResurrected` (e2e), `TestRestoreNeverUndoesADeletion`, `TestChainedEditAfterRemoteDeleteDoesNotResurrect` | Pass | |
| 9 | Rekey interrupted; recovery interrupted | `membership.test.ts`: "a rekey must carry a complete wrap set matching wraps_digest"; [`removal-fence-and-recovery-rotation.test.ts`](../../worker/test/removal-fence-and-recovery-rotation.test.ts): `recovery_rotate` "lands only with a resealed bundle"; new `red-team-concurrency-and-retry.test.ts`: a rekey whose answer was lost is replayed, a rekey rebuilt from stale state is refused, two owners racing rekeys land exactly one. Client: `TestRemoveDeviceResumesAfterEachCrash`, `TestRemoveDeviceSurvivesLostAnswers`, `TestRecoverResumesAfterEachCrash`, `TestUnfinishedRecoveryDoesNotExpire`, `TestRotateRecoveryResumesQueuedRotation`, `TestJoinResumesInterruptedFirstCycle`, `TestEnableResumesAfterTheGenesisAnswerIsLost` (e2e) | Pass | |
| 10 | Removed member reads new material; `needs-rotate` for the rest | `authorization.test.ts`: "a removed device loses access immediately"; `membership.test.ts`: "a removed device is denied and writes wait for rekey"; `removal-fence-and-recovery-rotation.test.ts`: writes by a removed device refused; vectors `removed_member_recipient`, `removed_member_older_epoch`, `removal-fence.json`; new [`red-team-removed-member.test.ts`](../../worker/test/red-team-removed-member.test.ts): after `member_remove` the old and a fresh device of the account read nothing, the rekey set has no wrap for them, and `needs_rotate` lists the exposed item. Client: `TestRemoveDeviceFencesRekeysAndReseals`, `TestRemovedDeviceIsFencedAndItsWritesRefused` (e2e), `TestRotateAfterAStoppedRemovalFlagsTheExposedItems` | Pass | Limitations stay as stated: no clawback; the fence binds the log as its remover verified it ([#21](https://github.com/bestagentkits/ak-vault/issues/21); `removal-fence-binds-log.test.ts`) |
| 11 | Reader and machine write; machine reads outside its vault | `authorization.test.ts` "read-only devices" block; `checkpoints-audit.test.ts` read-only cases; new [`red-team-tenant-and-role-isolation.test.ts`](../../worker/test/red-team-tenant-and-role-isolation.test.ts): reader and machine refused on every write route with no state change; a machine of the owner account refused on every item, change, wrap, checkpoint and audit route of another vault | Pass, finding | [#42](https://github.com/bestagentkits/ak-vault/issues/42) (open; the owner decided to fix it, via [ak-web#578](https://github.com/bestagentkits/ak-web/issues/578), before machine identities ship in #6): a machine session marked `session_kind: machine` is now refused on the recovery-identity path (Worker side fixed); the finding stays open until machine identities have their own sign-in that ak-web marks `session_kind: machine` ([ak-web#578](https://github.com/bestagentkits/ak-web/issues/578)), because a token without the claim is still treated as a human session and ak-web mints vault tokens only for email-OTP sign-ins, so a CI device signed in that way is a human session. Making the claim mandatory: [#88](https://github.com/bestagentkits/ak-vault/issues/88). Related open: [#22](https://github.com/bestagentkits/ak-vault/issues/22), [#14](https://github.com/bestagentkits/ak-vault/issues/14) |
| 12 | Cross-tenant read with a valid token | `authorization.test.ts`: "another tenant's device cannot touch a vault it does not belong to", "a device presenting another account's sub is refused"; `auth-token.test.ts`: "a token whose did names a non-member device is forbidden"; [`recovery-fetch.test.ts`](../../worker/test/recovery-fetch.test.ts): "refuses another account"; new `red-team-tenant-and-role-isolation.test.ts`: another tenant's token and proof refused on every read and write route and on a genesis for the victim's vault ID, state unchanged | Pass | |
| 13 | Hostile shared profile or policy text widens a grant or runs a command | Re-run on 2026-10-27 against agentkit `dev` with synced profiles, enforced synced policy, `run`, aliases and the relay ([below](#scenario-13-hostile-policy-and-profile-text)); first run 2026-10-16. Protocol: [`red-team-hostile-policy.test.ts`](../../packages/protocol/test/red-team-hostile-policy.test.ts), [`red-team-profile-provenance.test.ts`](../../packages/protocol/test/red-team-profile-provenance.test.ts) and Go [`red_team_hostile_policy_test.go`](../../go/akv1/red_team_hostile_policy_test.go), [`red_team_profile_provenance_test.go`](../../go/akv1/red_team_profile_provenance_test.go); vectors `policy.json`, `policy-binding.json`, `profile.json`. Client: `TestHostileMemberPolicyAndProfileItemsStayInert`, `TestHostileProfileFieldStaysAttributedToItsAuthor`, the `TestPolicyGate*` tests, `secrets/synced_policy_gate_test.go`, `TestDescribeShowsProfileProvenanceAndNoValue`, `TestRunChecksTheExecGrantAgainstTheAliasTarget`, `TestPolicyRefusalExitsFifteenWithItsReason`; local-Worker e2e `TestProfileAnnotatedOnOneHomeAppearsOnTheOther`, `TestSealedSetAndDeleteAppliedOnceThroughMCP`; and an uncommitted engine-level probe of seven cases | Pass, findings (no grant widened, no command ran); stated limitations unchanged | First run: [#80](https://github.com/bestagentkits/ak-vault/issues/80). Re-run hardening: [#150](https://github.com/bestagentkits/ak-vault/issues/150) (dashboard carries the raw previous profile), [agentkit#2745](https://github.com/bestagentkits/agentkit/issues/2745) (a pulled secret silently shadows a local alias) |
| 14 | Forked PR reads secrets or triggers a deploy | Configuration review of [`.github/workflows/`](../../.github/workflows/) and repository settings, below | Pass, findings | Hardening: [#43](https://github.com/bestagentkits/ak-vault/issues/43), [#44](https://github.com/bestagentkits/ak-vault/issues/44), [#45](https://github.com/bestagentkits/ak-vault/issues/45) |
| 15 | Planted plaintext and names in dumps, logs, metrics and errors | [`disclosure-scan.test.ts`](../../worker/test/disclosure-scan.test.ts): canaries in item names and values, audit, recovery password and keys, scanned across every Durable Object table, console line and response; new [`red-team-disclosure-scan.test.ts`](../../worker/test/red-team-disclosure-scan.test.ts): canaries in query strings, path segments, proof, idempotency and bearer headers, a device-key header on the recovery-identity path, webhook bodies and refused or oversize bodies, scanned across response bodies and headers, logs and both Durable Object dumps. agentkit e2e `checkLogRedaction` scans the `wrangler dev` log of the full e2e run (all nine scenarios passed against this head) for synthetic names, values, passwords, recovery keys and JWTs; a manual grep of that log also found no bearer, proof, idempotency-key, bundle or ciphertext fields. Client: `TestNoSecretInSyncState`, `akvhttp` `TestDoErrorsCarryNoSecretsOrPaths`. Deployed platform: the [platform log scan](#platform-log-scan) on a lab Worker | Pass (local); platform: finding | [#61](https://github.com/bestagentkits/ak-vault/issues/61): `wrangler tail` shows `AKV-Proof` and `AKV-Webhook-Signature` header values; Workers Observability logs and traces, analytics and the deployed dump had no hits. Waived by the owner on 2026-10-16 ([decision on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6209133248)); #61 stays open as hardening |

## Scenario 13: hostile policy and profile text

### Re-run of 2026-10-27

Run against agentkit `dev` at
[`95b4cdc29`](https://github.com/bestagentkits/agentkit/tree/95b4cdc29b6d04fd4976ddf6ce6f85beabe33096), which
syncs profiles (agentkit#2684), enforces synced policy on every grant release
(agentkit#2615), and has `request` with the exec scope, `ak secrets run`, aliases and
remote MCP calls over the relay (agentkit#2511, #2512, #2617, #2688). ak-vault was at
`main` `2bcb540`. Everything ran in a local lab: the in-process two-device harness
with the fake Worker, and agentkit's e2e against a local `wrangler dev` Worker built
from this checkout. Homes were fresh temp directories with in-memory stores and
keystores, and all data was synthetic. No staging or production, and no OS keychain.

The hostile member is device B, an enrolled editor whose records carry valid
signatures. B writes sealed records straight to the Worker, skipping the client's own
mapping. The victim is device A. An uncommitted probe in the client's `secretsync`
package covered the cases below. Its source is kept with the run report, not in
either repository.

| Case | Expected | Actual |
|---|---|---|
| Valid but hostile profile text from B under its own ID: prompt injection and `$(touch …)` in `when_to_use`, `curl … \| sh` in `description`, an attacker host in `usage_hosts`, extra `projects`, `permissions`, `aliases` naming another ref, `sensitivity`, and a zero-width joiner | Shown as untrusted text; no grant, run or alias | Every field reached A with origin `sync` and `by` B. All were listed in `describe --json` `untrustedFields`, which carries the fixed notice, and relay `describe` reported each with origin `sync`. With no local grant the release waited for approval, both for the item and for the name in `aliases`. No canary file, no `aliases.json` and no grant were written |
| Profile text the §5.1 rules refuse: a bidi override, a zero-width space, a byte order mark, a newline, 1,025 code points, a string where a list belongs, a comma in a list item, an `http:` `rotate_url`, an unknown key such as `exec`, an unknown `src` | Profile dropped with a reason; the rest of the record applies | For each case, in a fresh vault, A audited `profile_invalid` once, kept its own earlier profile and applied the record |
| Provenance forgery: a changed field claiming A's ID, a field claiming a device that does not exist, A's unchanged field relabelled to B, and a create whose field names A | Dropped and audited; never shown as A's own | Each field was dropped and audited `profile_provenance_invalid` with the item ID and field key only; the rest applied |
| A policy item from B trying to widen: `max_ttl_s` 2^53−1, `require_approval:false`, `*` and extra projects and purposes, empty `deny_agents`, payload sensitivity `normal` | Effective grant ≤ local grant ∩ every governing policy | With no local grant, nothing was released. Combined with A's policy (`max_ttl_s` 60, `require_approval`, one project, one purpose), the verdict was exactly A's limits: a standing allow was refused, a grant in a project only B allowed was refused `policy_denied`, and only a fresh allow-once in the narrow scope released. A `normal` policy item did not lower an item A raised to `high` |
| Malformed or unopenable policy items: an extra `meta` key (`exec`), an unknown body field (`grant`), a string where a list belongs, a record sealed under a key A does not hold | Refuse release, never fall back to the local grant, with a clear reason | Extra `meta` key: every synced ref refused `policy_invalid`. Bad body: the governed item refused `policy_invalid` while an ungoverned item still answered. Unopenable record: the sync reported `item_quarantined: decrypt_failed` and the gate refused `policy_decrypt_failed` |
| `run` or exec of a command named in profile or policy text | Nothing executes | No path reads profile or policy text to pick a program: `ak secrets run` and the relay `run` take argv from the caller and release only under an exec grant pinned to the program's hash. No canary ran in any case |
| Aliases through synced data | Aliases stay device-local | No sync path writes `aliases.json`, and the profile `aliases` field resolves nothing. A secret B pushed under the name of A's alias shadowed the alias after the pull, as a stored ref always does. The grant on the alias target did not release it: the release waited for approval of the new name. Nothing reported the shadowing ([agentkit#2745](https://github.com/bestagentkits/agentkit/issues/2745)) |
| B edits A's honest policy item down to `{}` | Stated limitation (spec §8.1, threat model E2) | The device followed B's signed head, and still released nothing without a local grant |

**MCP-originated text.** Sealed operations from `/mcp` carry only a name and a
value. They are applied with the creator `remote-mcp` and no profile, so a remote
MCP client cannot write profile text. Relay `describe`, `search` and `list` return
profile text with its origin. **Dashboard** (`packages/vault-app`, now on `main`):
profile text is rendered as Text nodes with its origin, through a DOM builder with no
HTML sinks. On a write the dashboard carries the raw previous `meta.profile` rather
than the profile it verified. A reconstruction with the protocol functions showed that
a field receivers had dropped as forged is carried again under the dashboard's
signature, and receivers drop it again, this time against the dashboard's revision.
Nothing widens, but this does not follow the §5.1 writer rule
([#150](https://github.com/bestagentkits/ak-vault/issues/150)).

Findings: none that widens a grant, runs a command or passes the provenance check.
Two hardening issues were filed, #150 and agentkit#2745. The limitations already
stated in the [threat model](./threat-model.md) (E2) still hold: any member can edit
or delete a policy, and an unopenable record or a malformed binding refuses every
item of the vault. The [Docker two-device e2e](../../e2e/docker/README.md) has no
profile or policy scenario, so it was not part of this run.

### Run of 2026-10-16


Run on 2026-10-16. The features this scenario attacks are not built: portable policy
is not enforced by any client ([#7](https://github.com/bestagentkits/ak-vault/issues/7))
and there are no shared profiles, discovery or `run`
([agentkit#2299](https://github.com/bestagentkits/agentkit/issues/2299)). The run covers
the two surfaces a hostile vault member can reach today.

**Protocol policy evaluator** (TypeScript `effectiveGrant` and Go `EffectiveGrant`).
Each hostile policy is parsed from raw JSON text, as a device would receive it. Refused
as `bad_request`, so the caller denies: duplicate keys hiding a long TTL,
`__proto__` and `constructor` keys, case, fullwidth and trailing-space lookalike
fields, `grant`, `exec` and nested-policy fields, exponent, fractional, negative and
above-2^53 TTLs, wrong types, lone surrogates, a byte-order mark, trailing data,
and policy text instead of an object; an unknown item sensitivity is refused the same
way. Accepted policies only narrowed: `*`, `proj_*`, `c*` and `$(id)` in allow and
deny lists are literals, an allow
list cannot add an entry, and `require_approval:false` cannot lift local approval or
the approval of a high-sensitivity item. Instruction text in `description`,
`when_to_use` and `urls` is returned verbatim and leaves the grant exactly as without
it. A randomized check (2,000 local grant and policy pairs per language, valid and
hostile, fixed seed) found no widening.

**Sync client** at agentkit `dev`
[`4aff1984b`](https://github.com/bestagentkits/agentkit/tree/4aff1984bf805e5d3a4e09e8376039692be65e83). An
uncommitted engine-level probe had an enrolled member seal and push, through the real
engine and the fake Worker, a `policy` item with grant-everything text and `grants`,
`approvals`, `trust`, `exec` and `when_to_use` meta, items of kind `profile`, `Policy`
and `grant`, and a secret named `SYNTH_SHELL_$(id)` with shell and instruction text in
its value and meta. On the victim's sync the policy item was cached as ciphertext only,
the other three were reported `unapplied: unsupported_kind` and stayed out of the
Store, the secret was stored as inert data with only the mapped metadata, no command
ran, and the sync wrote no grant, pending-request or trust file. The probe source is
attached to [agentkit#2478](https://github.com/bestagentkits/agentkit/issues/2478). The full
`secretsync/...` and `secretscmd/...` suites passed at the same commit with the probe
in place.

Findings: none that widens a grant or runs a command. That engine-level path has no
committed test, filed as hardening
([agentkit#2478](https://github.com/bestagentkits/agentkit/issues/2478)), which also
records a design note for #7 and agentkit#2299: the client carries unknown meta keys
forward on its next push under its own signature, so record authorship alone cannot
attribute profile text once profiles read from meta.

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
- At the time of the run the production reviewer could approve their own run during
  bootstrap, the recorded
  [bootstrap exception](./release-gates.md#production-deploy-control), not a new
  finding. That exception ended on 2026-10-16: only the owner approves production
  now. The staging environment still holds the formerly shared Cloudflare token;
  the owner closed that part under code-owner review of `.github/` and
  `worker/wrangler.jsonc` (in effect since 2026-10-16), with a stated residual risk (see the
  [release gates](./release-gates.md#production-deploy-control)).

Gaps that a fork cannot exploit today, filed as hardening: an unused organization
secret is visible to this repository (#43), the `main` ruleset does not require a
pull request although AGENTS.md says it does (#44), and SHA pinning is a convention
rather than an enforced setting (#45).

## Platform log scan

Run on 2026-10-16 with [`worker/scripts/platform-log-scan/`](../../worker/scripts/platform-log-scan/README.md)
as merged, on Worker source, protocol library and `wrangler.jsonc` identical to
`main` at `d097c41`; two earlier runs with pre-review revisions of the script gave
the same result.
A throwaway lab Worker on `workers.dev` ran the real Worker and Durable Object classes
with a synthetic issuer and sync on, and was deleted afterwards together with its
Durable Object namespaces (checked through the API). Counts and
settings are recorded [on #8](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6208699925).

**Settings scanned:** production's `observability` block as in
[`wrangler.jsonc`](../../worker/wrangler.jsonc) (enabled, head sampling 1, invocation
logs off) plus traces at head sampling 1, which production does not enable. Invocation
logs stayed off.

**Traffic:** 51 checked steps, 70 requests, all with the expected status. Two devices
enroll, push, pull and verify, checkpoint, conflict and tombstone; audit; recovery
bundle; a third device recovers with the recovery key, removes the lost device and
rekeys; recovery-key rotation; webhook revocation of a session. Error paths: garbage,
foreign-audience, expired and missing tokens; garbage, foreign-key and replayed proofs;
a revoked session; a malformed device-key header; malformed, mis-shaped and oversize
bodies; a reused idempotency key; bad-signature and malformed webhooks; canaries in a
query string and path.

**Planted values**, each searched as text, hex and base64/base64url at every
alignment: secret names and values, audit plaintext, recovery passwords and keys,
recovery signing keys, every bearer token and proof sent, device signing and
key-exchange secrets, vault and audit keys, the issuer key, idempotency keys, the
webhook secret and signatures, and canaries in refused bodies and headers. Opaque IDs
and URL canaries were counted for context only, since request URLs are platform
metadata.

| Source | Rows | Gating hits |
|---|---|---|
| Workers Observability events (operational log lines and trace spans) | 1,414 | 0 |
| Workers Observability traces | 73 | 0 |
| Workers Observability invocations | 73 | 0 |
| GraphQL Workers and Durable Object analytics | n/a | 0 |
| Durable Object dump (vault and revocation registry, every table) | 120 | 0 |
| Responses (status, headers, body) | 70 | 0 |
| `wrangler tail` | 59 events | 77 needle-form matches: 75 of `AKV-Proof` values (a proof is searched whole and per segment, in several encodings) and 2 of `AKV-Webhook-Signature` values |

In tail, Cloudflare replaced `Authorization`, `Idempotency-Key` and `AKV-Device-Key`
with `REDACTED`, because it redacts by header name
([#61](https://github.com/bestagentkits/ak-vault/issues/61)). Tail also carries the
request URL, with long ID-like segments redacted heuristically, and the client IP.
Workers Observability recorded only the `accept*` request headers, and replaced
ID-like path segments with `REDACTED`, though not always (the earlier runs kept some
item IDs), which the
[data classification](./data-classification.md#visible-operational-metadata-unavoidable)
already lists as visible. Trace spans record SQL statement text with placeholders,
never bound values. Tail is best effort: it delivered 31 of the 74 requests that
analytics counted, and one attempt was repeated because tail never connected.

## What this run does not cover

- **Platform sinks beyond the scan.** The [platform log scan](#platform-log-scan)
  covers Workers Observability, `wrangler tail` and analytics with production's
  observability settings plus traces. It does not cover invocation logs turned on,
  Logpush or other account-level sinks, and tail is best effort.
- **Client policy and discovery** (scenario 13): the 2026-10-27 re-run attacked the
  client in-process, with the fake Worker carrying the hostile records. The real Worker
  carried synced profiles only in the e2e that syncs an honest profile, because
  item ciphertext is opaque to it. A desktop app reveal and the operator's own `get`
  and `export` are not grant-based, and no policy caps them.
- **Review.** This run is the owner's agents testing their own code; it does
  not satisfy the [review](./release-gates.md#review-by-the-owner) gate.
