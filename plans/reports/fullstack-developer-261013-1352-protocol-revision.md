# Protocol v1 revision (issue #20): implementation report

**Status: done.** Pull request [#23](https://github.com/bestagentkits/ak-vault/pull/23) is open into `main` and has not been merged. It was built on branch `fix/protocol-v1-revision-20` in the worktree `/Volumes/GOON/claude/ak-vault/protocol-revision-20`, as commit `a29a535`.

## What changed

1. **Signed wrap sets.** `genesis`, `device_add` and `member_add` now carry `wraps_digest`, and TS and Go both have `verifyDeviceWraps`. The Worker verifies each wrap set when it is uploaded and stores the whole set. `GET /wraps?membership_seq=n` returns that set to members, and `POST /wraps` has been removed.
2. **Recovery identity.** It may now read `GET /membership`, but only when the `AKV-Device-Key` header is present. Every other route refuses it.
3. **Audit key per key epoch.** Each epoch has its own audit key derived with HKDF, and the key epoch is part of the AAD. Audit entries at an epoch the reader holds no key for come back opaque.
4. **Removal fence.** Removal events now sign `log_fence`, which must equal the current change-log head: a stale fence gets 409 and a fence ahead of the head gets 400. `log_seq` positions are contiguous, and TS and Go both have `verifyLoggedRecord`.
5. **`recovery_rotate`.** A new event that is stored atomically together with the resealed recovery bundle. The recovery key may now author only `device_add`.

All of this lands in one PR: the spec (including a new Revisions section), regenerated vectors, the threat model, the security docs and a runbook note.

## Deviations from the user's design

Each one, with its reason, is recorded in the PR.

- **The fence is the signed `log_fence`, not a server-stored checkpoint.** The server's checkpoint store keeps only one checkpoint per author and can replace or withhold it. A signed field on the removal event cannot be changed afterwards.
- **The recovery key may author `device_add` only.** It cannot read the change log, so it cannot sign an honest fence.
- **`wraps_digest` is also required on `genesis` and `member_add`,** not just `device_add`.
- **The completeness check for wrap sets is relaxed.**
- **`POST /wraps` is removed.**

## Evidence

All results are at commit `a29a535`.

| Check | Result |
|---|---|
| `pnpm typecheck` | exit 0 |
| `pnpm test` | protocol 342/342, Worker 122/122 |
| `pnpm vectors` | exit 0; running it again leaves 0 diff lines |
| `go test ./...` | ok |
| `pnpm build` | exit 0 |
| gitleaks via Docker, `dir` scan of the changed files | no leaks |

An isolated review found one blocker: the fence only binds log positions, not log contents. I fixed it by narrowing the claim in the docs and opening #21 to track content binding. I also opened #22 to check logged records against role history. The re-review is DONE with no blockers.

## Concerns

- **Rate-limit test timeout.** `worker/test/rate-limit.test.ts` timed out once while the machine's load average was about 200. It passes when run on its own.
- **Old staging vaults.** Staging vaults created before this revision will no longer verify. The runbook note says to abandon them.
- **External review still needed.** Issue #8's external review is still required before release.

## Unresolved questions

- Should content binding for the fence (#21) block GA, or is it acceptable as a documented limitation?

## Security review fixes

The new head is `940c707e64a2bbd83ed934a6d1c0086b02293888`. It is pushed to `fix/protocol-v1-revision-20`, and PR #23 is still not merged. The fixes respond to `code-reviewer-261013-1600-protocol-revision-security-review.md`.

- **Audit verifier fails closed (S1).**
  - The verifier now requires the key for the current key epoch, and for every entry epoch at or above `minKeyEpoch`. In TS `minKeyEpoch` is optional and defaults to the current epoch; in Go it is an explicit argument.
  - The bare `null` is replaced by a typed opaque marker in both TS and Go.
  - The vector `every_entry_opaque_without_keys` is now a refusal case. New refusal vectors cover a missing key at or above the minimum, a minimum above the current epoch, an opaque tail, and a chain that is entirely opaque.
- **Recovery bundle freshness (S2).** `PUT /recovery` now carries `{bundle, membership_seq}`. The Worker answers 409 `conflict` if the bundle was sealed before the latest `recovery_rotate`, and 400 if `membership_seq` is ahead of the log or missing. There is a Worker test; no vector was needed because the bundle wire format did not change.
- **Fence victims (S3).** The spec and threat model now say the exposure covers every device that had not pulled up to the fence, and that detection needs a digest per log position.
- **`POST /wraps` test (S4).** The test already existed in `authorization.test.ts` and asserts 404. The threat model now cites it.
- **Post-rekey audit append (S5).** It is now a MUST.
- **N1.** A vault created before this revision is refused with `unsupported_version`, covered by a Worker test and the runbook.
- **N2.** `wraps_digest` now uses the `akv1/wraps\n` domain tag, and the vectors are regenerated.
- **N5.** Stored wraps are capped by a new `wraps_per_vault` limit (20,000), covered by a Worker test.
- **N3 and N4.** N3 went to a comment on #22; N4 became the new issue #24.
- **#21.** It is added to `docs/security/release-gates.md` as a required item and is not implemented in this PR.

**Evidence at `940c707`:**

| Check | Result |
|---|---|
| `pnpm typecheck` | exit 0 |
| `pnpm test` | protocol 347/347, Worker 125/125 (the Worker suite did not time out in this run) |
| `pnpm vectors` | exit 0; vectors committed; a re-run gives 0 diff lines |
| `go test -count=1 ./...` | ok, and `go vet` and `gofmt` are clean |
| `pnpm build` | exit 0 |
| gitleaks (Docker, `dir` scan of changed files) | no leaks |

**Unresolved:** whether the agentkit client keeps a digest per log position. Fence detection depends on it, and it cannot be checked from this repo.

## Re-review fixes (R1, R2, R3)

Head is `f946747d881a2a108b79b653ea02ea4699c1438b`, pushed and not merged. The evidence is also posted as a comment on PR #23.

- **R1.** I reworded spec §7, `audit.ts` and `audit.go`, and the matching limitation in the threat model. Verification requires the current epoch's key, not an entry at that epoch. A chain truncated before its first entry at the minimum epoch can pass as entirely opaque, and only a witnessed checkpoint bounds this. Clients MUST NOT present an all-opaque result as verified.
- **R2.** This is a variant of the headroom option, and it is a deviation:
  - A rekey that clears `rekey_required`, and a recovery `device_add`, are exempt from `wraps_per_vault`. They are still bounded by events x `wraps_per_request`.
  - Owner enrollment is capped at `devices_per_vault` = 255, plus one slot for recovery, so a full rekey always fits in one request.
  - The last membership event slot is reserved for the required rekey.
  - Why this is deadlock-free: a required rekey can only be refused for exceeding `wraps_per_request` or for running out of event slots, and both are ruled out by construction.
  - I rejected a fixed headroom because a second removal uses it up and it locks out recovery.
  - Boundary tests are in `worker/test/vault-storage-limits.test.ts`. A mutation check confirmed that they fail without the exemptions.
- **R3.** The latest `recovery_rotate` seq is now kept in a meta key, `recovery_rotated_seq`, written by the rotate append. `putRecovery` reads it and fails closed with `internal` if the value is corrupt.
- **Docs.** Spec §10 and its Revisions section, and threat-model D2.

**Evidence:**
- `pnpm typecheck`: ok.
- `pnpm test`: protocol 347/347, worker 128/128.
- `pnpm vectors`: idempotent.
- `go test -count=1 ./...`: ok.
- `pnpm build`: ok.
- gitleaks: no leaks.

**Unresolved questions:**
- Exempt uploads are bounded only by 10,000 events x 256 wraps, about 2.56M rows in the worst case. If that is too loose, a tighter bound could be added in a separate issue.
- Recovery enrollment cannot use the last event slot, because it is reserved for the required rekey. A vault with exhausted events is full, and recovery is refused there too.

Status: DONE
