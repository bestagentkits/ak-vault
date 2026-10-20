# Remote access e2e (staging)

Playwright suites for the remote-access surface: MCP discovery and audience
separation, the dashboard's CSP, Trusted Types and CSRF refusals, the dashboard
leak check, cross-tenant refusals and the MCP tools. They run against a deployed
Worker, by default `https://vault-staging.agentkit.best`. Nothing here writes to
production; the base URL must be `https`, or plain `http` on `127.0.0.1` or
`localhost` for local checks.

## Run

```sh
pnpm install --frozen-lockfile
pnpm --filter ./e2e/remote-access typecheck
pnpm --filter ./e2e/remote-access e2e:list
pnpm --filter ./e2e/remote-access e2e
```

Every suite asks `gate()` first (`support/env.ts`) and skips with a stated reason
when a prerequisite is absent. A skip is an environment blocker, never a pass.
The reasons are: the target does not report `remote_access=true`; ak-web's
authorization server does not answer; no signed-in test account; no phase-10 `ak`
binary.

## Environment

| Variable | Purpose |
|---|---|
| `VAULT_E2E_BASE_URL` | Worker origin. Default `https://vault-staging.agentkit.best`. |
| `VAULT_E2E_AK_WEB_ORIGIN` | ak-web origin for OAuth. Default `https://staging.agentkit.best`. |
| `VAULT_E2E_STORAGE_STATE` | Playwright storage-state file of a signed-in staging test account. Kept outside the repo. |
| `VAULT_E2E_SECOND_STORAGE_STATE` | Second staging account, for cross-tenant checks. |
| `VAULT_E2E_VAULT_ID` | The first account's vault id, for cross-tenant checks. |
| `AK_BIN` | Path to a phase-10 relay-capable `ak`. Never the installed binary on the machine. |
| `AK_E2E_OWNER_HOME` | Temp HOME prepared for the owner device. Never the real home. |

No credential is stored in the repo, printed, or written to a report. Storage-state
files and HOME directories belong in a temp location outside the checkout.

## Leak checks

Each run makes two random sentinels in process memory only (`global-setup.ts`): a
value sentinel and a name sentinel. The dashboard round-trip suite checks that the
value never appears in the DOM, storage, IndexedDB, responses or the console. The
name is checked in responses and the console only, because the dashboard shows
names by design.

`leak-scan.ts` runs `wrangler tail --env staging` for the whole run and searches
each chunk in memory. It reports counts only. If the tail cannot start or stops
during the run, the result is `unavailable` and the teardown prints a `BLOCKED`
line. That is not a clean scan.

## Known state

- The staging Worker must report `remote_access=true` for the remote suites to run.
  The Phase 11 run on 2026-10-20 found it did not; see
  [red-team evidence](../../docs/security/red-team-evidence.md#remote-access-staging-run-2026-10-20).
- The `ak` phase-10 command contract (device approve/remove, annotate, set
  argument shapes) is not verified here. The suites that drive `ak` are gated on
  `AK_BIN` and will need to be checked against that binary when it exists.
- Playwright runs serially (`workers: 1`) with no traces, screenshots or video,
  because those capture DOM and network bodies that hold sentinels.
