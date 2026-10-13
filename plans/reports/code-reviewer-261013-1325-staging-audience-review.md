# Review: staging token audience (#13), diff 544ebcf..HEAD

Scope: worker/wrangler.jsonc, worker/vitest.config.ts, worker/test/auth-token.test.ts,
worker/scripts/staging-smoke.ts, docs/protocol/v1/spec.md §9, docs/security/release-gates.md,
plans/261013-1320-8-client-web-gates/plan.md. Checks reported by the lead (typecheck, TS+Go tests,
vectors no diff) were not re-run. The `unstable_readConfig` behavior was checked with a scratch script.

## Verdict
No blockers. The change meets the #13 acceptance criteria: each environment refuses the
other's token with `unauthorized`, and a test covers it.

## Verification
- `unstable_readConfig` with `env: undefined` returns `https://vault.agentkit.best`, and with
  `env: 'staging'` it returns `https://vault-staging.agentkit.best`. `vars` are not inherited
  across envs, so the staging value comes from `env.staging` alone.
- The test is not trivial. Tokens differ only in `aud` (same iss/key/sub/did/scope, fresh jti
  and proof per call), the matching token returns 200 under the same env override, and the
  other returns 401 with the exact error body. So the refusal comes from the audience check
  (`jwt-verify.ts:106`). A broken config read fails loudly: `undefined` is dropped by
  JSON.stringify, which fails the `toBe` pins. The pins also catch the two envs being set to
  the same value.
- `call()` merges `opts.env` over `env` per request, and `verifyToken` reads `VAULT_AUDIENCE`
  per call. The JWKS cache is not keyed by audience, so the override has no stale-state risk.
- No other hard-coded production audience in worker/src, scripts or .github/workflows.
  `/v1/meta` echoes `env.VAULT_AUDIENCE` (public, fine). Remaining `vault.agentkit.best` hits
  are the landing page, proof `htu` vectors and the test `BASE`, none of them audience.
- Staging smoke AUDIENCE matches wrangler staging. `generate-staging-issuer-key.ts` has no
  audience, so nothing to change there.
- Spec §9 wording is consistent with ADR 0001:73, threat-model S4 and release-gates. No vectors
  carry `aud`, so the "vectors no diff" result is expected.
- Plan file: no secrets, tokens, account IDs or customer names. The kid formula, the webhook
  409-as-delivered rule, the claim set and `typ at+jwt` (accepted by the verifier) match spec
  §2/§9. The issue references resolve (ak-web#568, agentkit#2298).

## Findings

### Blocker
None.

### Should-fix
1. **`CLOUDFLARE_ENV` leaks into the "production" read** (`worker/vitest.config.ts:21`). Wrangler 4
   uses `CLOUDFLARE_ENV` when `env` is undefined. I confirmed it: with `CLOUDFLARE_ENV=staging`,
   "production" resolves to the staging audience and the test fails with a misleading message.
   It fails closed, not silently, but a developer shell or a future CI step with that variable
   set breaks `pnpm test`. Fix: pass `env: name === 'production' ? '' : name`. Verified that `''`
   returns the top-level vars even when `CLOUDFLARE_ENV=staging`, and it matches
   `deploy:production`'s `--env=""`.
2. **Threat model not updated for the new guarantee.** release-gates.md now states "neither
   accepts the other's tokens", and AGENTS.md (spec/vector rule 4) asks for a threat-model
   update when a guarantee changes. Fix: add "staging/production audience separation" to the
   S4 evidence column in `docs/security/threat-model.md:75`, citing
   `worker/test/auth-token.test.ts`.

### Nit
1. `./wrangler.jsonc` in `unstable_readConfig` resolves against the process cwd, not the config
   file. This works under `pnpm -r test` / `vitest run` in `worker/` but breaks if vitest is
   started from the repo root with `--config worker/vitest.config.ts`. Use
   `fileURLToPath(new URL('./wrangler.jsonc', import.meta.url))`.
2. `docs/security/release-gates.md:60` is now one long unwrapped line. The rest of the file wraps
   at about 85 columns.
3. Plan wording: the constraint says "not a generic OAuth resource", but the ak-web#568 title is
   "Add dedicated vault OAuth resource". These probably agree ("dedicated" vs "generic"), but
   state it explicitly so the ak-web implementer does not misread it.
4. Plan phase 1 bundles "ak-web staging issuer" under #13, but this PR changes only the ak-vault
   side. Mark phase 1 partial or split it, so closing #13 does not imply the staging issuer is
   wired.

## Unresolved questions
- Should staging keep trusting the test-only JWKS after ak-web's staging issuer exists, or switch
  `VAULT_ISSUER`/JWKS together with ak-web#568? This is outside this diff, but it decides when the
  smoke script's ISSUER changes.

Status: DONE
Summary: The staging audience split is correct and the cross-environment refusal test is valid
(not trivial). There are 2 should-fix items (CLOUDFLARE_ENV leaks into the config read; threat
model S4 not updated) and 4 nits. No blockers.
