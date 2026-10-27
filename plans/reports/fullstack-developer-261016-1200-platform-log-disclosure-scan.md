# Platform log disclosure scan (#8 gate)

Outcome: scan built, run on deployed lab Worker, merged as PR #62 (squash `b25c2bb`). Gate stays UNTICKED: `wrangler tail` shows `AKV-Proof` and `AKV-Webhook-Signature` header values (#61). Everything else had 0 gating hits.

## Final run (2026-10-16 12:48-12:53 Asia/Saigon, script at branch `a021711`, Worker source = main `d097c41`)

- 51 steps, 70 requests, 0 unexpected statuses; report `dirty: false`.
- Gating hits: Observability events 1,414 rows 0; traces 73 rows 0; invocations 73 rows 0; GraphQL analytics 0; DO dump 120 rows 0; responses 70 rows 0.
- wrangler tail: 59 events, 31 fetch invocations of 74 analytics requests (best effort); 77 needle-form matches (75 proof, 2 webhook signature).
- Two earlier runs (pre-review revisions) same result. One attempt timed out waiting for tail to connect, repeated. SIGINT mid-deploy test: exit 130, lab deleted.
- Settings: production observability (head sampling 1, invocation_logs false) plus traces on lab only.

## Review

- Two isolated code-reviewer passes vs REVIEW.md: no blockers.
- Should-fix items fixed: cleanup on SIGINT/SIGTERM/uncaught (wrangler children stopped, deletion rechecked after 20 s), tail flush before read, fail closed on full telemetry page, subdomain redaction, report/capture paths refused inside any worktree (symlink/case-safe), analytics count in report, refused dump falls through to real Worker, genesis fail-fast, docs count wording, option and report modules split out.
- Not done: unit tests for scan helpers (worker vitest runs in workerd; helpers rely on a runtime self-test and the offline guard checks run by hand); `lab-vault-model.ts` (237), `run-platform-log-scan.ts` (237), `lab-traffic.ts` (215) stay over 200 lines as cohesive sequential modules.

## Delivery

- PR: https://github.com/bestagentkits/ak-vault/pull/62 (Refs #8, no closing ref; CI green; auto-merged).
- #8 evidence comment (counts only, edited to final run + PR link): https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6208699925
- Finding: #61 (ai-handle).
- Deploy run for merge commit: 38858323759 (in progress; production approval left to coordinator).
- Docs: `docs/security/release-gates.md`, `red-team-evidence.md`, `data-classification.md`, `docs/README.md`, `worker/scripts/platform-log-scan/README.md`.

## Cleanup

- All lab Workers (5 runs + SIGINT test) deleted: 0 `ak-vault-lab-*` scripts, 0 lab DO namespaces (API-checked).
- Worktree and local branch removed; no wrangler/tail processes; no temp dirs; scratch captures deleted. No `.wrangler/` created.
- No credentials, account id, subdomain or canary values in PR, docs, issue or this report.

## Unresolved questions

- #61: rename headers (wire change: spec, vectors, TS and Go) or owner waiver on #8?
- Production approval of Deploy run 38858323759: coordinator.
