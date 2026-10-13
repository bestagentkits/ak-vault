---
status: in-progress
issues: [ak-vault#8, ak-vault#13, ak-web#568, agentkit#2298]
---

# ak-vault #8: web and client gates (ak-web, agentkit)

## Outcome
The parts of the #8 release gates owned by ak-web and the `ak` CLI exist, are tested,
and run against staging: ak-web mints device-bound vault tokens and delivers
revocations; the CLI proves sync-off makes zero HTTP requests, `resolve` never needs
the network, measures warm resolve overhead, and syncs a vault end to end on staging
so the soak can start.

## Constraints
- Production sync stays off (`VAULT_SYNC_ENABLED=false`). External review on #8
  cannot be self-attested; #8 stays `blocked` until it exists.
- No custom crypto: the CLI uses `github.com/bestagentkits/ak-vault/go/akv1`.
- ak-web: vault tokens are a dedicated mint path (the "vault OAuth resource" of #568), not an
  entry in the generic OAuth resource list; MCP/API
  token verification is not loosened. New secrets go through `lib/env.ts`.
- agentkit: secret surfaces stay out of the operational sync outbox; work lands on
  `dev` via PRs; ASCII-only literals; universal flags on new commands.
- Each repo follows its own AGENTS.md/CLAUDE.md, CI and branch rules.

## Non-goals
Desktop UX (agentkit#2300), account dashboard (ak-web#569), discovery/exec
(agentkit#2299), production enablement.

## Phases
| # | Phase | Repo | Status |
|---|---|---|---|
| 1 | Tag `go/v0.1.0`; staging audience (#13). Trusting ak-web's staging issuer waits for #568 on staging | ak-vault | done: #13 shipped (#19), `go/v0.1.0`; protocol revision #20 shipped (#23), `go/v0.2.0`. Staging issuer switch moves to phase 6 |
| 2 | Vault token mint (device key possession, `sid`/`did`, aud per env) + revocation outbox/webhook + revoke-all | ak-web (#568) | merged to dev (ak-web#571), flag off |
| 3 | Gates: `secrets` excluded from auto-update, zero-HTTP sync-off test, offline resolve test, resolve benchmark rig | agentkit | PR agentkit#2318 in review |
| 4 | Sync client design (UX, schemas, local state, mapping v1 store to akv1 items) reviewed before code | agentkit (#2298) | done: design revision 2 (`agentkit-sync-client-design.md`), reviewed |
| 5 | Sync client implementation: device key, token client, genesis/enroll (SAS), push/pull with CAS and conflicts, recovery | agentkit (#2298) | in progress: P1 agentkit#2323 and P2 (with P4b) agentkit#2322 reviewed, waiting on agentkit CI; revision 3 notes in the design |
| 6 | Staging soak wiring and evidence on #8 | all | in progress: ak-web staging OAuth signing key set; staging Worker trusts `https://staging.agentkit.best` (#27, #28); webhook secrets matched; live smoke needs a staging CLI session |

## Acceptance
- ak-web: mint refuses without CLI session, wrong key possession, revoked session, flag off;
  token verifies against the Worker contract (spec §9); revoking a CLI session or all
  sessions delivers a signed webhook the Worker accepts (409 treated as delivered); tests + CI green.
- agentkit: tests prove 0 HTTP with sync off and resolve with server unreachable;
  benchmark documents rig and p95; sync round trip between two devices on staging.
- ak-vault: staging and production reject each other's tokens (test).

## Key contract facts
- `kid(pub) = b64url(SHA-256("akv1/kid\n" || pub)[0:16])`; `did = kid(sign_pub)`.
- Token: ES256, `typ at+jwt`, iss = ak-web origin, aud = vault origin of that env,
  claims sub, exp, nbf, iat, jti, sid, did, scope ⊆ {vault:read, vault:write}.
- Webhook: spec §9.3.
