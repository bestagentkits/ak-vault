---
title: "ak-vault guide: from .env to an encrypted vault"
url: https://vault.agentkit.best/guide/
status: "Local vault available. Sync commands in preview; agent-discovery commands in agentkit dev builds, coming in the next release. Browser dashboard and remote MCP on staging only, pre-release, not for production credentials."
---

# From `.env` to a vault, step by step

Part 1 works today with the AgentKit CLI. Part 2 describes the preview sync commands and Part 3 the agent commands (discovery in agentkit dev builds, the rest planned); each step is marked and its syntax may change before release. Parts 5 to 7 cover the browser dashboard and remote MCP, which run on staging only: pre-release, not for production credentials.

**Legend:** *available* works in the current `ak` CLI. *preview* ships hidden in the released CLI but is not a supported workflow; syntax may change. *dev builds* is in agentkit dev builds and coming in the next release, not in a released version. *planned* is designed but not released; do not script against it yet. Sync is not generally available: the production sync API is live as a pre-release preview, enabled before the owner's review. The owner accepted the review gate on 2026-10-16 with no written findings; it is not an independent third-party review.

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

The end-to-end encrypted sync described on this site. A pre-release preview is live in production, enabled before the owner's review, which is not an independent third-party review. Sync is not generally available: the steps below are not a supported workflow until every release gate is met, and production credentials do not belong in it yet.

1. **Sign in to your AgentKit account** (available). `ak login` exists today for your AgentKit account; the preview sync commands use that sign-in.
2. **Opt in to sync on your first device** (preview). Sync stays off until you turn it on. Enabling it creates the vault key on this device, wraps it to your device key, a password-derived key and a recovery key, and uploads only ciphertext.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets sync enable
   ```
3. **Save your recovery key offline** (preview). You will be shown a 32-byte recovery key, written in Crockford base32. Store it on paper or in a password manager you trust. If you lose every device, your password and this key, nobody can decrypt the vault.
4. **Enroll a second device with a six-digit code** (preview). Start enrollment on the new device and approve it on one you already trust. Both screens show the same six digits; approve only if they match. A mismatch aborts. See [how the code is derived](https://vault.agentkit.best/how-it-works/index.md).
5. **Check that it worked** (preview). The new device verifies the signed member list before it unwraps anything. Change a secret on one device and expect it on the other within about a minute on a healthy connection (a design target, not a measured result).

## Part 3: Let agents discover and use secrets (dev builds and planned)

Commands that let an agent find and request secrets without ever seeing values it was not granted. Discovery is in agentkit dev builds; `request` and `run` are planned.

1. **Let agents find secrets by description** (dev builds). `search` finds secrets by their metadata and `describe` shows one secret's profile and where each field came from, never a value. Both are available in agentkit dev builds and coming in the next release; no released version has them yet.
   ```sh
   # DEV BUILDS: available in agentkit dev builds, coming in the next release; syntax may change
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

1. **Revoke the lost device** (preview). A removed device is checked on every request, so it is refused even with an unexpired token. Removal also moves the vault to a new key epoch before new writes. Removal and recovery need `v3.0.0-beta.31` or later, which includes the removal-fence client; the service refuses them from older releases. On an older release, upgrade or revoke the lost device in your AgentKit account, which the service enforces on its next request.
2. **Rotate what it could read** (available). Revocation cannot take back values the device already decrypted. Rotate sensitive credentials at the provider, then store the new value.
   ```sh
   ak secrets rotate OPENAI_API_KEY
   ```
3. **Cut off agents on that machine** (available). Remove an agent fingerprint's grants on one secret, or all of them at once.
   ```sh
   ak secrets revoke OPENAI_API_KEY --agent sha256:<fingerprint>
   ak secrets revoke --agent sha256:<fingerprint> --all
   ```
4. **Lost every device? Recover with your password or recovery key** (preview; needs `v3.0.0-beta.31` or later, see step 1). A fresh device can enroll itself through the encrypted recovery bundle, which also carries the owner's public trust anchor and the newest witnessed checkpoint so it does not have to trust the server.

## Part 5: Use your vault from the browser (staging)

**Staging only: pre-release, not for production credentials.** The dashboard runs at `https://vault-staging.agentkit.best/app` with an AgentKit staging account. Production has it switched off.

The dashboard is a device of your vault, like a second laptop. It creates its own device keys in the browser, keeps them in IndexedDB as non-extractable keys, and decrypts in the page, so the server still receives only ciphertext from it. Version 1 enrollment adds devices only to an account that owns the vault, so the dashboard is for vault owners; an editor of a shared vault cannot add a browser.

1. **Sign in** (staging). Open the dashboard and sign in with your AgentKit account. There is no passphrase: every visit unlocks with a fresh sign-in. **Lock**, or leaving the page, drops the session and the decrypted view from memory and ends the sign-in; the device keys stay in this browser.
2. **Approve the browser from an owner device** (staging; uses the preview sync commands from Part 2). The first sign-in shows a join code starting `akj1-`. On a device that already owns the vault, run the command below. It prints an offer code: paste it into the browser, which then shows a six-digit code. Answer `y` in the terminal only if both codes match, then choose **I approved it, continue**. Approval needs you at a terminal; it is refused for an agent and with `--json`.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets devices approve <join code>
   ```
3. **What the dashboard can do** (staging). List secrets with their metadata (sensitivity, dates and profile fields, each marked with where it came from), filter by name or metadata, find an exact name, set a value, delete a secret, open a secret's signed revision history, restore an earlier value as a new revision and resolve conflicting branches. Filtering and search run in the browser over the copy it verified; no query goes to the server. The read-only **Members and access** tab lists the accounts, roles and devices the signed membership chain names, removed devices, the key epoch, a pending rekey and the items a removal flagged for rotation, and says what this browser session can and cannot do. A removal ends future access only: rotating the vault key does not revoke provider keys already disclosed, so rotate those at the provider.
4. **What it never does.** It never shows, copies or stores a value: the value field is write-only and is cleared when you save. History lists each revision's device, time, key epoch, deletions and conflict branches, never a value; a revision this browser has no key for is marked unavailable / unverified. Restore and conflict resolution are explicit confirmations that write one new signed revision against the current head: a concurrent change becomes a conflict, never an overwrite, a deleted secret is not brought back, and restoring an old credential does not make it valid again at its provider, so rotate or revoke it there if it may be exposed. A conflict that includes a deletion or an unreadable branch is left to `ak secrets sync settle`. It signs no checkpoints. It cannot invite, remove or re-role members, rekey, read the recovery bundle, publish the seal key or apply queued writes: the server refuses those for a browser session.

## Part 6: Connect an AI tool with remote MCP (staging)

**Staging only: pre-release, not for production credentials.** Remote MCP lets a hosted AI tool search, describe, set and use your secrets without a local CLI. It never returns a secret value.

1. **Add the server** (staging). In your AI tool's MCP or connector settings, add `https://vault-staging.agentkit.best/mcp`. The tool finds the sign-in server through `/.well-known/oauth-protected-resource/mcp` and sends you to AgentKit to sign in and approve the access it asks for.
2. **Choose what it may do.** Each scope in plain words, with the tools it unlocks:
   - `vault-mcp:read`: see the names and descriptions of your secrets, never their values (`secrets_search`, `secrets_list`, `secrets_describe`).
   - `vault-mcp:write`: add, replace or delete secrets; it can write a value but never read one back (`secrets_set`, `secrets_delete`), or ask you to type a value it never sees (`secrets_prepare_write`, `secrets_write_status`).
   - `vault-mcp:use`: ask to use a secret, and run commands you approved on your own device with it; values go to that command only, never to the AI tool (`secrets_request`, `secrets_run`).
3. **Keep one of your devices online for reads and use** (planned: requires an `ak` version with relay support, not released yet). Reads, `request` and `run` are answered by one of your own devices that holds a relay connection open: it decrypts locally, applies its own grants and approvals, and answers. With no device online they answer `no_device_online`. `run` starts only commands that an `exec` grant pinned on that device allows, and removes the values it released from the output; output that a command encoded, split or printed in part is not caught.
4. **Writes with no device online are queued, sealed** (planned: the seal key and draining also need an `ak` version with relay support). With no device online, `secrets_set` and `secrets_delete` must name the `vault_id`. The server seals the operation to your vault's seal key and queues it (status `queued`) until one of your devices applies it as a normal signed write. The queue is write-only: nothing reads a queued value back. It works only for an owner or editor of the vault, only after an owner device has published the seal key, and not while a rekey is pending. A full queue answers `sealed_queue_full`.
5. **Type secrets the AI must not see yourself** (planned: the dashboard form is not released yet). `secrets_set` puts the value in the AI tool's own conversation and tool call, so never paste a secret into the chat for it. Instead the AI tool calls `secrets_prepare_write` with only the name (and, if it likes, a purpose) and gives you a link to the dashboard. Open it in the browser you enrolled in Part 5, check the name, the purpose and which AI tool asked, then type the value or cancel. Your browser encrypts and signs it like any other write; the AI tool learns only whether it was saved, through `secrets_write_status`. The link works once, expires within ten minutes, and only for you, signed in to your enrolled browser. `create` never overwrites a secret that already exists; replacing one needs a request for `replace`. The AI tool chooses the name and purpose, so read them before you type.
6. **Know what the server sees.** The server stores no plaintext and holds no vault key, but a remote MCP call is not end-to-end encrypted: plaintext passes through the server's memory after TLS ends. That is the value an AI tool sends with a set, until the server seals it or relays it to your device, the name and purpose of a request for you to type a secret, until the server seals them, and the names, metadata and redacted `run` output your device sends back on their way to the AI tool. It is never logged, stored or put in an error. AI tools do not check device signatures, so they trust the server for what a result says. See [ADR 0002](https://github.com/bestagentkits/ak-vault/blob/main/docs/adr/0002-browser-device-relay-and-remote-mcp.md), decision D7.
7. **Disconnect.** In your AgentKit account, open Connected apps and disconnect **AgentKit Vault (AI tools)**. The next request with that grant is refused, and a link it asked for no longer works.

Call budgets per AI tool and per account, relay deadlines, the queue size and lifetime, and the write-request link lifetime and caps are owned by [`worker/src/limits.ts`](https://github.com/bestagentkits/ak-vault/blob/main/worker/src/limits.ts) and published by `GET /v1/meta` where remote access is on.

## Part 7: Remove a browser (staging)

**Staging only: pre-release, not for production credentials.**

1. **Find its device ID** (preview). The dashboard header shows the first eight characters as "Device …", and the CLI lists every device.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets devices list
   ```
2. **Remove it and rotate the vault key** (preview). Run it from an owner device. Removal moves the vault to a new key so the browser cannot read new writes. It asks for the vault password and the current recovery key. Use `--reason lost`, `stolen` or `compromised` when that fits better. It cannot take back what the browser already decrypted: if the browser may be compromised, rotate those secrets at their provider. When the removed browser next syncs, it is refused and deletes its own device key.
   ```sh
   # PREVIEW: hidden in the released CLI, unsupported, syntax may change
   ak secrets devices remove <device-prefix> --reason retired
   ```
3. **End its sign-in.** If Connected apps lists **AgentKit Vault dashboard**, disconnect it too.

## Keep reading

- [How it works](https://vault.agentkit.best/how-it-works/index.md)
- [Security model](https://vault.agentkit.best/security/index.md)
- [FAQ](https://vault.agentkit.best/faq/index.md)
