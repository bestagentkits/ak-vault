# Code review round 2: review fixes (`ef142f6..4e7301b`)

Scope: 4 commits (100a2d3, a01be26, a5e2fb4, 4e7301b), 33 files, +911/-160. Read-only. REVIEW.md applied.

## Evidence (HEAD 4e7301b)

- `pnpm -r typecheck`: pass (protocol, worker src/test/node).
- `pnpm -r test`: protocol 276/276, worker 105/105 (13 files).
- Probe (temp test file, run once, then deleted; `worker/.wrangler` removed; `git status` clean): unrelated-account `PUT /v1/vaults/<random>` with garbage body leaves tables in the DO (see SF1).
- GitHub API: `staging` and `production` environments both have custom branch policy `main`; production has required reviewer; both hold their own `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID`. Pinned SHAs verified: checkout/setup-node = v4.4.0, setup-go = v5.6.0, pnpm/action-setup = `v4` (annotated tag, compare = identical).
- wrangler 4.149.0: `observability` is `inheritable`, so `invocation_logs: false` also applies to `env.staging`.

## Round-1 findings status

| ID | Status | Evidence |
|---|---|---|
| S1 recovery fetch | Fixed, tested | `vault-authorization.ts:99-119`; `recovery-fetch.test.ts` (owner check, did/key binding, malformed header, wrong-key proof, jti replay, scope, removed did, current non-owner); e2e in `membership.test.ts:129` (fetch, open, recovery-signed enroll) |
| S2 docs vs spec | Fixed | ADR open items, key-lifecycle steps 1-5, spec §3.5 |
| S3 reader/machine appends | Fixed, tested | POLICY `checkpoints.post`/`audit.post` = WRITE + writer; `checkpoints-audit.test.ts` negatives for machine, reader, read scope |
| S4 storage for unknown vaults | **Partially fixed** | Non-genesis ops fixed and tested; genesis path still writes (SF1) |
| S5 change-log bound | Fixed, tested | counters in `meta` updated inside the mutation txn; seed path, conflict counting, both caps tested |
| S6 deploy gating/secrets | Fixed, one gap | workflow_run gate correct; dispatch bypasses CI (SF2) |
| S7 invocation logs | Fixed | `wrangler.jsonc:14`, data-classification updated |
| N1 JWKS negative cache | Fixed, tested | fail-closed, expired keys never served (`jwks-cache.test.ts`) |
| N2 capped body reader | Fixed, tested | chunked API + webhook bodies → 413, early stop asserted |
| N5 silent deploy skip | Fixed | missing creds → `exit 1` |
| N6 webhook retry 409 | Fixed (spec §9.3 documents "treat as delivered") |

## Verified, no issue

- Recovery fetch can't reach other ops: branch only when `op === 'recovery.get'` and `did` not current (`vault-authorization.ts:119`). Current devices keep `human_owner`. Stolen token alone is insufficient: `did == kid(AKV-Device-Key)` plus proof by that key. Jti burned under `did` before return. Live revocation and rate limit still run first. No new enumeration surface: 403/404 distinction pre-existed.
- Counter consistency: idempotent replay returns before `mutate` (no count); `quota_exceeded`, replay `conflict` and other throws roll back the `meta` update with the txn; committed 409 conflict branch counts; seed uses `length(CAST(record_json AS BLOB))` = UTF-8 bytes = runtime `utf8Encode(cjson).length`. `insertRecord` is the only `INSERT INTO records`.
- `isReplay` is additive in `applyRecord`; `seen: []` only drops the in-memory list; `UNIQUE(item_id,digest)` still backstops. Vectors unchanged.
- Lazy schema: pre-change DOs have `meta` → constructor re-runs idempotent schema; genesis on a never-touched DO calls `ensureSchema` first; `vaultExists` short-circuits on `schemaReady` so no op reads missing tables.
- Deploy: for `workflow_run`, `github.ref` is the default branch; gate requires `conclusion == success`, `event == push`, `head_branch == main`; checkout is `head_sha` with `persist-credentials: false`; CI `cancel-in-progress` on main means superseded runs conclude `cancelled` and never deploy; tokens only in the Deploy step env.

## BLOCKING

None.

## SHOULD-FIX

**SF1. S4 still reachable through genesis; spec §10 claim is false.**
- `worker/src/vault/vault-durable-object.ts:56-58`: `ensureSchema()` (13 tables + indexes) and `enforceRateLimit` (one row) run before `authorize`. DDL is outside any transaction.
- Failure: any valid, unrevoked token from any ak-web account sends `PUT /v1/vaults/<random id>` with an `Idempotency-Key` and a junk body. It gets 400/403, but the DO keeps a schema and a `rate_counters` row. Repeat with fresh IDs → unbounded DO count/storage, the exact round-1 S4 scenario with a different verb. Confirmed by probe (tables non-empty after the failed genesis).
- `docs/protocol/v1/spec.md:270-271` ("A request for a vault that has no genesis returns `not_found` and writes nothing") is wrong for the genesis request. `vault-storage-limits.test.ts:22-27` does not cover the genesis verb, so the gap is untested.
- Fix: in genesis, run the storage-free checks first: parse body, `verifyGenesis`, author/owner match, `verifyProof` signature/htu/ath/bh with `isReplay` returning false. Only then `ensureSchema`, burn the jti and rate-limit. Add a junk-genesis case to the "non-existent vaults" test, and narrow the spec sentence to match.

**SF2. `workflow_dispatch` skips the CI gate; release-gates claim is wrong.**
- `.github/workflows/deploy.yml:13,27`: on dispatch the gate checks only `github.ref == main` and deploys `github.sha`, whatever CI says for that commit (red, running or cancelled).
- `docs/security/release-gates.md:55` says the workflow deploys "only after CI passed on the same commit".
- Failure: a maintainer dispatches while main's head has failing tests. Staging deploys red code with no approval, and production waits only on the reviewer, who is an agent under the documented bootstrap exception.
- Fix: in the gate, for dispatch, require a successful CI push run on the SHA, e.g. `gh run list -w CI --commit "$SHA" --event push --status success --json databaseId -q 'length'` > 0, with `actions: read` on that job. Or narrow the doc to state that dispatch is an unchecked manual redeploy.

**SF3. Threat model not updated for the new pre-membership path; spec overstates removed-device exclusion.**
- New wire surface: `AKV-Device-Key`, and the first request accepted from a non-member device without a signed event. REVIEW.md "Spec or wire format → threat model updated if guarantees moved". `docs/security/threat-model.md` has no row or explicit limitation for "owner-account token holder downloads the bundle and guesses offline". The S3 row ("theft without device key") is now incomplete: with this path, a fresh key is enough when the attacker can obtain an owner-account token for a new `did`.
- `docs/protocol/v1/spec.md:130-131` ("A removed (lost or stolen) device can never use this path") widens the guarantee. Code excludes only the removed device ID (`vault-authorization.ts:101`). The thief of a removed laptop with a live ak-web session for the owner account generates a new key, gets a token for the new `did` (as every legitimate fresh device must), and fetches the bundle. Only ak-web session revocation (`min_iat`/`sid`) stops that, and the doc doesn't say so.
- Fix: add a threat-model row and limitation (offline guessing; mitigation = Argon2id minimums, 256-bit rk, ak-web session revocation after loss). Reword spec:130 to "a removed device ID is refused; after a loss, revoke the owner's ak-web sessions, because a new key with a fresh owner-account token can still fetch the ciphertext". Mirror it in key-lifecycle:112.

## NIT

- **N-a.** `docs/protocol/v1/spec.md:256-257`: "The only request from a device outside membership is the recovery bundle fetch". Recovery enrollment (`membership.post` with recovery-signed `device_add`, `vault-authorization.ts:87-95`) is also from outside membership. Say "the only *read*", or list both.
- **N-b.** `request-guard.ts:17-27`: `rate_counters` rows are never pruned and are written before authorization. Any account can add one row per `did` it holds to any existing vault. Not a regression and small per row, but it's the remaining unauthenticated write on existing vaults. Prune stale windows alongside the `proof_jti` cleanup.
- **N-c.** No test exercises the constructor branch for an existing DO (`schemaReady` true at construction, the path every pre-change production DO takes after deploy). Logic is trivial, but REVIEW wants proof. Add one restart-style test (e.g. a new stub on an evicted DO) if the pool supports it.

## Unresolved questions

1. Does ak-web mint vault tokens for any client-chosen `did` under an authenticated session? If yes, SF3's exposure is "any live owner session", and session revocation after device loss is the key mitigation and must be documented.
2. S3 fix makes machine identities unable to append audit entries. Is losing machine-side audit of `run`/CI access intended (product decision), or should machines get a narrow, quota'd audit-append right?
3. Bootstrap exception (shared CF token across environments, agent may approve production) is documented with a revocation trigger. Confirm it is tracked as an issue so it isn't forgotten before sync GA.

Status: DONE_WITH_CONCERNS
Summary: S1-S3, S5-S7, N1, N2, N5, N6 are fixed and tested (typecheck green, 276 + 105 tests). S4 is only partially fixed (a junk genesis PUT still creates DO storage, confirmed by probe). workflow_dispatch bypasses the CI gate. The threat model/spec overstate the new recovery-fetch path.
Concerns/Blockers: No BLOCKING. SF1-SF3 should land before the release gate.
