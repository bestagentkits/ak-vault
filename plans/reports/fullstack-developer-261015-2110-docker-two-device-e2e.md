# Docker two-device e2e: report

Delivered `e2e/docker/` in ak-vault PR #55 (merged, squash; closes #40, refs #8). The real `ak` CLI runs on two devices against the Worker under `wrangler dev`, with a fake ak-web. Every scenario passes against the Worker that includes the removal fence. No agentkit change was needed.

## What was built

- `run.sh` + `lib/`: the runner, which runs on the macOS system bash 3.2. `--agentkit-ref`, `--agentkit-dir`, `--scenarios`, `--soak D` and `--keep`. It prints a pass/fail table with timings, tears down with `down -v` and checks nothing is left, and exits non-zero on failure.
- `fake-akweb/` (Go): OTP sign-in, refresh, sign-out, the §9 ES256 `at+jwt` token mint bound to the device key, JWKS, and the signed revocation webhook with retry. Test hooks cover the OTP inbox, revoke (including `webhook_only`) and stats. Tests cover the contract and refusals.
- `vault/`: this checkout's Worker under `wrangler dev --env staging`, with the image labelled by its commit. It refuses CF variables and `.dev.vars`/`.env`. Its webhook secret is passed through a tmpfs env-file.
- `device/`: `ak` built from the pinned agentkit commit, cross-compiled so it also builds for amd64. It uses the file backend with a synthetic passphrase. A pty driver plays the person at the keyboard (passphrase, OTP, reveal, approve). A supervisor runs `sync now --watch`.
- `scanner/`: the disclosure scan of the Durable Object's SQLite (raw bytes and a table dump), the Worker log and wrangler's log, covering every encoding the Worker's test helper covers.
- `README.md` explains why and how, and is linked from `docs/README.md`.

## Evidence (ak-vault `a4f5656`, Docker 29.4 arm64)

| agentkit | Run | Result |
|---|---|---|
| dev `3bfecc6` (includes agentkit#2458) | full, 09:19 +07 | 10/10 PASS |
| dev `3bfecc6` | full, 09:26 +07 | 10/10 PASS |
| branch `67ff8e6` (agentkit#2458) | full, 09:34 +07 | 10/10 PASS |
| dev `3bfecc6`, pre-commit tree | full + `--soak 10m` | 11/11 PASS |
| pre-fence `661c303` | propagation, removal, recovery | removal and recovery FAIL: blocked by agentkit#2450 (the Worker returns 400 `bad_request` on a removal without `log_head`), as expected |

**Propagation latency**
- Across the 4 full runs, A→B p50 was about 7.5 to 8.5 s and the maximum was 8.8 s.
- The 10-minute soak ran 41 iterations with 0 errors and 0 samples over the 60 s gate:

  | Direction | p50 | p95 | max |
  |---|---|---|---|
  | A→B | 7447 ms | 7864 ms | 7882 ms |
  | B→A | 7549 ms | 7844 ms | 8016 ms |

**Other timings**

| Measure | Time |
|---|---|
| Offline catch-up after reconnect | about 32 to 33 s |
| Kill switch, from switching back on to delivery | about 24 to 28 s |
| Delete propagation | about 2.1 to 2.7 s |

**Disclosure:** 61 needles, searched in 5 encodings each, over 35 files and 30 tables gave 0 hits in every run.

**Other checks**
- `go vet` and `go test -race` pass for fake-akweb.
- All 3 images build with `buildx --platform linux/amd64`.
- gitleaks finds no leaks in the committed files.
- PR CI passed (TypeScript, Go, secret scan).

**Review:** an isolated reviewer found 1 blocker and 7 should-fix items, all fixed. The re-review found no blockers, and its last should-fix and nits were applied before the final runs.

## Cleanup

- I stopped all runs, and every teardown was verified: no akvault containers, volumes or networks are left.
- I removed the images I built (devices, vault, fake-akweb, the probe image, gitleaks).
- I removed the worktree and the local branch.
- Run summaries are kept at `/private/tmp/claude-502/-Volumes-GOON-claude-ak-vault-bootstrap-ak-vault-f5d084/79905a31-a501-4708-836d-bcd859e62a56/scratchpad/evidence/`.
- Issue #40 is closed and labelled `shipped`. Results are posted on #8.

Status: DONE_WITH_CONCERNS
Summary: The two-device Docker e2e is merged (#55) and green on the fence-aware agentkit (dev 3bfecc6 and the branch 67ff8e6). The pre-fence 661c303 is recorded as blocked by agentkit#2450. The propagation gate holds with a wide margin, and disclosure is 0 hits.
Concerns/Blockers:
- fake-akweb's Go tests are not in CI, because I deliberately left CI unchanged.
- The stack runs workerd locally, so it is not production evidence and does not replace the external review on #8.
- One soak only (10 min), and it was on the tree before the final review nits. The final full runs are on the merged commit.

Unresolved questions:
- Should the CI `go` job also run `go test` in `e2e/docker/fake-akweb`?
- Is a longer soak (for example `--soak 2h`) wanted as release-gate evidence?
- After a device removal, `ak secrets list --json` does not set `needsRotation` on the secrets the removal flagged; the count appears only in the remove output. Is that intended, or a gap worth an agentkit issue?
