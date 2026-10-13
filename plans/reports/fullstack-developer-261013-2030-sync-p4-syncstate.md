# Sync client: syncstate store, outbox and item mapping

PR: https://github.com/bestagentkits/agentkit/pull/2330 is part of agentkit#2298. It is stacked on #2322 (base `feat/secrets-sync-module-keystore`), labelled `os-specific`, and not merged.
Branch: `feat/secrets-sync-state-store`, head `8223dcfa9`.

## Delivered

- `apps/cli/internal/runtime/secretsync/syncstate/`: `schema.go`, `store.go`, `outbox.go`, `items.go`, `membership.go`, `local_map.go`, `state_digests.go`, plus tests.
- `apps/cli/internal/runtime/secretsync/item_payload_mapping.go` and its test.
- Ownership deviation: `apps/cli/go-test-shards.json` gains one line, which adds syncstate to windows-shard-2.

## Coordinator decisions applied

- S1 to S5 and N1 to N8 are applied. The private-key guard on `pending_enroll` is applied and its contract documented. The comment on `ExpectSeqLessEntry = -1` is in place.
- Schema deviation from design §5.2: `device_history` has `PRIMARY KEY (device_id, added_seq)`. It is recorded in the PR and in the comment on the schema test literal.

## Review

- **First full-diff review:** no blockers. Its should-fix items S1 to S5 and the nits are applied.
- **Delta re-review:** no blockers. It raised 3 should-fix items, all fixed and tested in `8223dcfa9`:
  - a replayed removal without its fence is now a no-op;
  - an older incarnation's removal can still be replayed or fenced after a re-add;
  - the `kind_changed` quarantine now persists until it is cleared explicitly.
- **Nits from the delta re-review, also fixed:**
  - a re-add at exactly the removal seq is refused;
  - the private-key tokenizer now splits capital runs and knows `priv`;
  - the `sqlite_master` LIKE pattern is escaped.
- **Also fixed:** the crash-test child now blocks on a timer instead of `select{}`, so the Go runtime no longer reports a deadlock in it and the parent's kill is what ends it.

## Evidence (head `8223dcfa9`)

- `go test -race -count=1 ./internal/runtime/secretsync/...`: ok for all 3 packages.
- `go vet` (host and `GOOS=windows`): clean.
- `golangci-lint`: 0 issues.
- `make lint-ascii`: pass.
- Shard verify: `[OK] 219 Windows Go packages`.
- `PREFLIGHT_BASE=origin/feat/secrets-sync-module-keystore bash tools/preflight.sh`: all gates passed.

## Cleanup

- Removed the worktree's node_modules and `.husky/_` left by `pnpm install`.
- Reverted a stray `go.work.sum` change from preflight.
- My preflight runs left no temp dirs. The existing `agentkit-kitcmd-preflight.*` dirs predate them or belong to other sessions, so they were left in place.

## Unresolved

- P1 (#2323) is unmerged. The mapping uses `secrets.Metadata`, and `apply_pending` stores the -1 seq-less token as a plain integer. The engine phase must bridge to P1's `SyncedMeta`.
- Names may contain bidi and line-separator format characters (U+202A-202E, U+2066-2069, U+2028/2029). Only C0, DEL and C1 are refused, as decided. A possible follow-up issue.
