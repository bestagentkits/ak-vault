# Sync client: `akvhttp` transport, agentkit#2298

**Status:** DONE. PR https://github.com/bestagentkits/agentkit/pull/2329 is open and not merged. It is stacked on #2322 (base `feat/secrets-sync-module-keystore`); retarget it to `dev` after #2322 merges.

Worktree: `/Volumes/GOON/www/claudekit/agentkit-wt-sync-p3`, branch `feat/secrets-sync-akvhttp`. The branch has five commits; head is `582926c10`.

## Files
All new files are in `apps/cli/internal/runtime/secretsync/akvhttp/`:
- `client.go`
- `proof_headers.go`
- `api_error.go`
- `vault_token_source.go`
- `vault_origin.go`
- a test file for each of the five

**Ownership deviation:** `apps/cli/go-test-shards.json` gained one line, for the new package in windows-shard-0. The parallel `syncstate` phase also edits this file, so a trivial merge conflict is possible.

## Acceptance criteria
- **akv1 for proof, kid and signing:** `BuildProof`, `Kid`, `SignPublicKey`, `SignDetached`, `CJSON` and `CJSONParse` all come from akv1. There is no custom cryptography.
- **Errors keyed on code and fail closed:** codes are checked against akv1's closed set plus `internal`. Unknown codes and malformed bodies become `unrecognized`. `ReasonOf` maps an error to the design's reason values (section 2.2).
- **Retry-After:** the value is bounded to between 1 s and 5 min. `Do` retries inline at most twice, and only when the wait is 10 s or less; a longer wait is returned to the caller.
- **Token cache:** in memory only, per scope. A token is re-minted 30 s before it expires or after one 401. Concurrent callers share a single mint. Tokens are never logged or put in error text.
- **Injectable transport:** no package-level client and no `init` I/O. A test proves that the default path goes through `http.DefaultTransport` as it stands at request time.
- **Origin check:** `/v1/meta` must name the pinned vault origin as its audience and the ak-web registry origin as its issuer, matched byte for byte. The token source pins every token's `iss` to that same registry origin. A proof origin that differs from the base URL is allowed only when the base URL is a loopback address, and the token source's audience must equal the proof origin.
- **No live network:** tests use `httptest` fakes only.

## Evidence (at `582926c10`)
- `go test -race -count=3` passes; coverage is 94.6%.
- `go vet` and golangci-lint report 0 issues.
- `make lint-ascii` passes.
- The shard manifest `--verify` passes, and so does the shard contract test.
- `tools/preflight.sh`: all gates pass.

## Review
A fresh, isolated code reviewer found no blockers and seven should-fix items, all of which were fixed:
- the proof origin could point at another host;
- the renewer's origin was not checked;
- a session with no registry was accepted;
- a failed session renewal had no reason attached;
- `forbidden` on `/recovery` was treated as a removed device;
- some query bytes would be re-encoded by the server;
- several tests were missing.

A re-review of those fixes found no blockers and no should-fix items. Its three nits were also fixed.

## Issuer pin (coordinator decision)
The coordinator decided that the `/v1/meta` issuer is pinned to the configured ak-web origin. This landed in commits `d4910cfcb` and `582926c10`.
- **`FetchMeta`** takes the expected issuer as a new argument. It canonicalizes the configured value with `ParseOrigin`, then requires the served issuer to match that canonical form byte for byte; anything else fails with `ErrOriginMismatch`.
- **Token source:** `WebTokenSourceConfig.Issuer` is removed. The token source pins `iss` to its registry origin and exposes it through `TokenSource.Issuer()`.
- **Client:** `New` refuses an issuer that is not a canonical origin, and `Client.Meta` checks the server against the token source's issuer.
- **Tests** cover:
  - a matching issuer;
  - a configured value with a trailing slash or in another case, which is accepted;
  - a served value with a different host, a lookalike host, a trailing slash, a path, an explicit port, another case or http, which is refused;
  - a configured value that is invalid, which is refused;
  - `Client.Meta` with a real `WebTokenSource`.
- **Both ends agree on the form:**
  - ak-web's `oauthIssuer()` requires `new URL(v).origin === v`, so it always produces a bare origin.
  - The Worker compares `iss` exactly.
- **Review:** a fresh, isolated reviewer looked at just this delta. It found no blockers and one should-fix item (a test that `Issuer()` returns the canonical form), which is fixed. Its nits were also taken: `New` now validates the issuer, and `FetchMeta` errors say which configured origin was invalid.
- **Gates:** `go test -race`, vet, golangci-lint, `make lint-ascii` and preflight were all re-run and pass.
- The PR body is updated.

## Cleanup
- `node_modules` was installed in the worktree so preflight could run. It is gitignored and left in place, as is the worktree.
- No servers were started. Go test caches are in the shared GOCACHE.

## Unresolved questions
- The `Meta.Limits` presence check is settled: the engine phase will do it, as recorded by the coordinator.
- The local end-to-end recipe in the design doc (`VAULT_ISSUER:https://e2e-issuer.invalid`) must now make the fake vault's `VAULT_ISSUER` equal to the fake registry origin. The design doc is outside this phase's file ownership, so I have not edited it; it needs a one-line update.
- ak-web may add fields to its token response. Unknown fields are tolerated; only the fields this client relies on are strict.
