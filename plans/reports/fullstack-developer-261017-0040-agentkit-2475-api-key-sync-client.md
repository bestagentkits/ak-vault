# agentkit#2475: API-key sign-ins for vault sync (client)

Status: DONE_WITH_CONCERNS. PR https://github.com/bestagentkits/agentkit/pull/2499 is open into `dev` and ready for review, at head `0b5e86a27`. It has not landed yet; the train lands it, so there is no landed SHA. Issue #2475 is labelled `done`.

## What changed

- **Exchange:** an API-key sign-in now exchanges the saved key, once, for an ak-web device session:
  - the challenge returns a nonce;
  - the exchange body is `{nonce, sign_pub, sig}`;
  - `sig` is Ed25519 over `"akv1/api-key-device-session" || 0x0A || cjson({api_key_id, nonce, sign_pub})`, signed with the device's existing sync signing key.
- **Storage and renewal:** the session lives in the session.json vault slot beside the API-key login and renews through `/api/agentkit/auth/refresh`.
- **Re-enrollment and loop bound:** the client re-enrolls at most once per run. A session ended right after it was created stops the run with exit 14, so there is no loop.
- **Errors:** every ak-web error code has its own message and reason. Unknown codes fail closed. Errors never print the API key, a token, the nonce, the proof or the signing key.
- **Key changes and revocation:** signing in with another API key drops the device session. A device session replaced for a new sync key, or by the email step-up, is revoked best-effort. Logout revokes device sessions.
- **Recovery path:** `sync recover`, `sync rotate-recovery`, `devices remove` and `devices rotate` refuse API-key device sessions.
  - Scripted runs exit 14 with `recovery_needs_email_sign_in`.
  - In a terminal, they offer the email step-up.
  - License sign-ins keep `session_without_sid`.
- **Joining a vault** uses the existing `devices add` / `devices approve` flow. The sync commands stay hidden.
- **Docs:** `docs/guides/secrets.md` (sync sign-in section), `docs/system-architecture.md` (one ledger bullet) and the help goldens.

## About #2476

#2476 was not rejected: it landed in train-20261016T0908Z (48a2ac6aa is on `dev`). What ak-vault#74 rejected was letting an API key mint vault tokens directly. This PR does not do that, and keeps the #2476 OTP step-up for keys without vault scope.

## Evidence

- Fixed signature vector, computed with ak-web's `vaultSigningInput` and Node Ed25519 from a synthetic seed; Go matches it byte for byte.
- Fake ak-web test covering challenge, exchange, refresh, token and revoke.
- One test for each refusal code, malformed answers, the loop bound, key changes and the recovery refusals.
- `golangci-lint run ./...` reports 0 issues.
- Preflight receipt: `head 0b5e86a27be85a28fb4330b948c140f8df2cf94b (tree dab51e90b6ed) vs origin/dev merge-base 571488e66886ec3e521b6167846e9ed71ed071c0, depth=fast, mode=scoped, gates contract,biome,tstest,golint,gotest,cruft,commitlint, passed 2026-10-16T18:25:45Z`.
- An isolated reviewer found no blockers. Its two should-fixes (session not tied to the current key, replaced sessions not revoked) were fixed, and a re-review returned DONE.
- Tested on the macOS host. The live staging test was not run.

## Concerns

- A device session dropped locally after a key change is not revoked on the server. It counts against the old key until that key is revoked or 30 days pass.
- ak-vault#90 (open) will refuse recovery-bundle writes for API-key sessions. The client already gates `devices remove`/`rotate`, but a recovery row queued earlier by an email session and flushed later by a device session could still be refused.
- In a script, a key without vault scope now sends one request and exits 14 with `token_refused` (`vault_scope_missing`). Before this change it stopped locally with `session_without_sid`. The PR calls this out.
- I filed #2497 (ai-handle) because the sync docs still say the production vault refuses sync.

## Staging steps (orchestrator)

```sh
export AGENTKIT_HOME="$(mktemp -d)"
export AGENTKIT_REGISTRY_URL=https://staging.agentkit.best
# turn on Vault sync for the key on the staging API keys page first
ak login --api-key "$AK_STAGING_API_KEY"
ak secrets sync enable --recovery-kit-out ./kit.txt      # new vault
#   or join: ak secrets devices add  (new device) + ak secrets devices approve <join-code> (member device)
ak secrets sync now
ak secrets sync status --json        # sign_in.api_key_device = "enrolled"
ak secrets sync recover --recovery-kit ./kit.txt --json --yes   # expect exit 14, recovery_needs_email_sign_in
```

## Cleanup

- Removed the worktree `agentkit-wt-2475` and the local branch; the remote branch stays for the train.
- Removed the exited preflight scratch dir `/tmp/ak-pf.8Xnipu` and my lint cache. I left `/tmp/ak-pf.ewwLLk` alone because another session's preflight is using it.
- No processes left running.
