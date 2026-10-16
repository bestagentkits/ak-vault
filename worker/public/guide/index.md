---
title: "ak-vault guide: from .env to an encrypted vault"
url: https://vault.agentkit.best/guide/
status: "Local vault available. Sync commands in preview; agent-discovery commands planned, not available yet."
---

# From `.env` to a vault, step by step

Part 1 works today with the AgentKit CLI. Part 2 describes the preview sync commands and Part 3 the planned agent commands; each step is marked and its syntax may change before release.

**Legend:** *available* works in the current `ak` CLI. *preview* ships hidden in the released CLI but is not a supported workflow; syntax may change. *planned* is designed but not released; do not script against it yet. Sync is not generally available: the production sync API is live as a pre-release preview, not yet externally reviewed.

## Part 1: Keep secrets in the local vault (available)

Everything stays on this machine: values live in the OS keychain by default, or in an age-encrypted file vault, and agents read them through references you control.

1. **Install the AgentKit CLI** (available). The local vault ships inside `ak`, the AgentKit CLI. AgentKit is in closed beta; follow the install instructions at [agentkit.best](https://agentkit.best).
2. **Import an existing `.env` file** (available). Existing keys are skipped unless you pass `--force`. Check the result, then delete the plaintext file.
   ```sh
   ak secrets import-env .env
   ak secrets list
   ```
3. **Add or replace a single secret** (available). `set` and `rotate` prompt for the value without echoing it, so it never lands in your shell history. They also accept `--value=-` from stdin or `--value-file`.
   ```sh
   ak secrets set OPENAI_API_KEY
   ak secrets rotate OPENAI_API_KEY
   ```
4. **Inspect without revealing** (available). `get` shows metadata and prints the value as `[redacted]`. Add `--reveal` only when you need to see it; it asks you to confirm first.
   ```sh
   ak secrets get OPENAI_API_KEY
   ```
5. **Reference secrets in agent configs** (available). Put a reference where the value used to be. `ak` resolves it locally, and only for an agent binary you have granted.
   ```
   OPENAI_API_KEY=${secret:OPENAI_API_KEY}
   ```
6. **Decide which agents may read it** (available). When an agent asks for a secret, the request waits for you. Answer it once, for a time window, or grant an agent fingerprint ahead of time. The audit ledger shows every access and the grant that allowed it.
   ```sh
   ak secrets approve
   ak secrets grants
   ak secrets audit
   ```

## Part 2: Sync a second device (preview)

The end-to-end encrypted sync described on this site. A pre-release preview is live in production, before the external security review; the steps below are not a supported workflow until that review closes, and production credentials do not belong in it yet.

1. **Sign in to your AgentKit account** (available). `ak login` exists today for your AgentKit account; the preview sync commands use that sign-in.
2. **Opt in to sync on your first device** (preview). Sync stays off until you turn it on. Enabling it creates the vault key on this device, wraps it to your device key, a password-derived key and a recovery key, and uploads only ciphertext.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets sync enable
   ```
3. **Save your recovery key offline** (preview). You will be shown a 32-byte recovery key, written in Crockford base32. Store it on paper or in a password manager you trust. If you lose every device, your password and this key, nobody can decrypt the vault.
4. **Enroll a second device with a six-digit code** (preview). Start enrollment on the new device and approve it on one you already trust. Both screens show the same six digits; approve only if they match. A mismatch aborts. See [how the code is derived](https://vault.agentkit.best/how-it-works/index.md).
5. **Check that it worked** (preview). The new device verifies the signed member list before it unwraps anything. Change a secret on one device and expect it on the other within about a minute on a healthy connection (a design target, not a measured result).

## Part 3: Let agents discover and use secrets (planned)

Planned commands that let an agent find and request secrets without ever seeing values it was not granted.

1. **Let agents find secrets by description** (planned). `search` and `describe` let an agent find the right secret from its encrypted description without seeing any value.
   ```sh
   # PLANNED: not available yet, syntax may change
   ak secrets search "openai"
   ak secrets describe OPENAI_API_KEY
   ```
2. **Let agents ask for what they need** (planned). `request` lets an agent ask for a secret it has not been granted, and the request waits for your approval.
3. **Run a process with secrets injected** (planned). `run` starts a child process with the approved values in its environment. That process receives plaintext by design, so grant it only to software you trust.
   ```sh
   # PLANNED: not available yet, syntax may change
   ak secrets run -- npm start
   ```

## Part 4: If a device is lost or stolen

Some of this works today on the local vault; the device-removal and recovery steps are in preview.

1. **Revoke the lost device** (preview). A removed device is checked on every request, so it is refused even with an unexpired token. Removal also moves the vault to a new key epoch before new writes. The released beta (`v3.0.0-beta.30`) cannot remove a device or recover yet: the service refuses them until a release with the removal-fence client. Until then, revoke the lost device in your AgentKit account, which the service enforces on its next request.
2. **Rotate what it could read** (available). Revocation cannot take back values the device already decrypted. Rotate sensitive credentials at the provider, then store the new value.
   ```sh
   ak secrets rotate OPENAI_API_KEY
   ```
3. **Cut off agents on that machine** (available). Remove an agent fingerprint's grants on one secret, or all of them at once.
   ```sh
   ak secrets revoke OPENAI_API_KEY --agent sha256:<fingerprint>
   ak secrets revoke --agent sha256:<fingerprint> --all
   ```
4. **Lost every device? Recover with your password or recovery key** (preview; not yet on the released beta, see step 1). A fresh device can enroll itself through the encrypted recovery bundle, which also carries the owner's public trust anchor and the newest witnessed checkpoint so it does not have to trust the server.

## Keep reading

- [How it works](https://vault.agentkit.best/how-it-works/index.md)
- [Security model](https://vault.agentkit.best/security/index.md)
- [FAQ](https://vault.agentkit.best/faq/index.md)
