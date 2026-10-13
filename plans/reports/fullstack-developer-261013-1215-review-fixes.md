# Review fixes: S1, S3, S4, S5, N1, N2 (ak-vault Worker)

Source: `plans/reports/code-reviewer-261013-1156-ak-vault-bootstrap-review.md`. No commit, push or deploy. Docs, .github, wrangler.jsonc and *.md were not touched (another agent owns them; their diffs in `git status` are not mine).

## Files changed

Source
- `worker/src/vault/vault-authorization.ts`: recovery-fetch path, POLICY change, header comment.
- `worker/src/vault/vault-request.ts`: `deviceKey: string | null`.
- `worker/src/routes/api-handler.ts`: plumbs `AKV-Device-Key`, uses the capped reader.
- `worker/src/routes/revocation-webhook.ts`: uses the capped reader.
- `worker/src/http/read-body-capped.ts` (new): streaming body reader with a byte cap.
- `worker/src/vault/vault-durable-object.ts`: lazy schema creation and the vault-exists check before any write.
- `worker/src/vault/request-guard.ts`: comment only.
- `worker/src/vault/item-store.ts`: indexed replay lookup and record caps.
- `worker/src/limits.ts`: `records_per_vault: 200_000`, `record_bytes_per_vault: 512 MiB`.
- `worker/src/auth/jwks.ts`: 30 s negative cache.
- `packages/protocol/src/record-state.ts`: optional `ApplyRecordOptions.isReplay`.
- `packages/protocol/src/index.ts`: doc line for `isReplay`.

Tests
- New: `worker/test/recovery-fetch.test.ts`, `vault-storage-limits.test.ts`, `jwks-cache.test.ts`, `request-body-limits.test.ts`, `helpers/recovery-bundle.ts`.
- Updated: `membership.test.ts`, `checkpoints-audit.test.ts`, `authorization.test.ts` (now uses the shared bundle helper), `packages/protocol/test/protocol-behaviour.test.ts`.

## Decisions and behaviour

**S1: recovery fetch by a fresh device.**
- The new path runs only when the op is `recovery.get` and the token `did` is not a current device.
- It requires all of the following:
  - `sub === owner_account`, else 403.
  - `did` is not in `removed_device_ids`, else 403.
  - `AKV-Device-Key` is strict b64url of 32 bytes and `deviceIdFromSignPub(key) === did`. A missing, malformed or mismatched header gets 401 `unauthorized`.
  - The proof verifies against the presented key (`verifyRequestProof`, with the jti burned under `did`).
  - The token has `vault:read` scope.
- Current devices are unchanged: they still need a human owner device.
- `Authorized.device` is now `DeviceRecord | null`; nothing read it before.
- The header comment states the offline-guessing exposure.

**S3.** `audit.post` and `checkpoints.post` now need `vault:write` scope and the `writer` role. The `EITHER` scope set was removed.

**S4: no storage for vaults that don't exist.**
- The constructor only reads `sqlite_master`. It runs the idempotent schema only when the `meta` table already exists.
- `genesis` calls `ensureSchema()` and keeps rate limiting.
- Every other op returns 404 if the schema or membership state is missing, before the rate counter, proof jti or idempotency writes.
- Remaining gap: a genesis attempt that fails auth still creates the tables plus one rate-counter row. This is by design, because genesis keeps rate limiting.

**S5: record caps.**
- Running totals `{records, bytes}` are kept in `meta` under the key `record_usage`. Bytes are the UTF-8 length of `cjson(record)`.
- If the key is missing, the totals are seeded once from the `records` table.
- Both applied records and preserved conflict branches count. Going over either cap returns 403 `quota_exceeded`, the same as `items_per_vault`.
- Replay detection is now `SELECT 1 FROM records WHERE item_id=? AND digest=?`, passed to `applyRecord` as `isReplay`, and `seen` is `[]`.
- The protocol change is additive: the callback is checked alongside `state.seen`, so the default behaviour and the vectors are unchanged. No Go change was needed.
- Tests lower the caps by writing `meta.record_usage` through `runInDurableObject`. There is no production test hook.

**N1: JWKS negative cache.**
- After a failed load, the same source is refused (503) for 30 s without fetching.
- An expired cache entry is never used. A still-fresh entry survives a failed unknown-kid refetch.
- `clearJwksCache` also clears the failure record.

**N2: body size cap.**
- `readBodyCapped` rejects a declared `Content-Length` over the cap.
- Otherwise it reads the stream chunk by chunk and cancels it once the total passes the cap. It returns `quota_exceeded`, which is 413.
- It is used by both the API handler and the webhook.

## Evidence

- `pnpm -r typecheck`: protocol and worker pass, including the test and node tsconfigs.
- `pnpm -r test`: protocol 276/276 (was 275, plus the `isReplay` test); worker 105/105 in 13 files (was 83).
  - The "Network connection lost" line is the existing, expected JWKS-unreachable test.
- `pnpm vectors -- --check`: "0 stale vector file(s)".
- `cd go && go test ./...`: ok.
- Mutation check: with the constructor forced back to eager schema creation, the empty-storage test fails as expected. I then restored the file.
- Cleanup: removed `worker/.wrangler/`, which vitest-pool-workers creates. No background processes were left running.

## Notes for docs owner

- The spec and docs should describe:
  - the `AKV-Device-Key` header and recovery-fetch conditions;
  - that audit and checkpoint posts are writer-only;
  - the new `records_per_vault` / `record_bytes_per_vault` limits;
  - the 30 s JWKS failure backoff.
- `/v1/meta` publishes the new limits automatically, and the meta test passes unchanged.

## Unresolved questions

1. Should a failed genesis attempt also avoid leaving a rate-counter row? That would mean moving the genesis rate limit after event verification. I left it as instructed.

Status: DONE
Summary: S1, S3, S4, S5, N1 and N2 are implemented with tests; typecheck, all TS tests (276 + 105), Go tests and the vectors check are green. The only protocol change is an optional `isReplay` callback; vectors are unchanged.
Concerns/Blockers: Docs and the spec still need to describe the new header, the writer-only audit and checkpoint posts, and the new limits. That is owned by the docs agent.
