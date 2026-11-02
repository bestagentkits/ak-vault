# Status

One page for what is live, what is a preview and what is gated. It records state
and links to the owner of each fact; it does not replace
[release gates](./security/release-gates.md) (the go/no-go contract) or the
[runbooks](./operations/runbooks.md). Recheck live state before relying on a row:
this page is a record of the repository at the commit you are reading, not a
live probe.

**Nothing here is generally available.** Do not store production credentials in
sync, the dashboard or remote MCP. Where a row says "on in production", that is an
owner decision taken before the gate passed, not a review sign-off
([owner waivers](./security/release-gates.md#owner-waivers)); the owner's review is
not an independent third-party review.

## Surfaces

| Surface | State | Who can reach it | Gate |
|---|---|---|---|
| Local vault (`ak secrets`, no sync) | Available in the released CLI. Works offline; with sync off it makes zero network requests. | Anyone with the CLI | None of this repository's gates; owned by [bestagentkits/agentkit](https://github.com/bestagentkits/agentkit) |
| Sync (`ak secrets sync`, Worker sync API) | **Preview.** The Worker is live in production (`VAULT_SYNC_ENABLED=true`). The CLI commands are hidden and unsupported in the released `ak` 3.0.0 ([agentkit#2626](https://github.com/bestagentkits/agentkit/issues/2626)); removal and recovery need `v3.0.0-beta.31` or later. | A logged-in user who runs the hidden commands | [Release gates](./security/release-gates.md), issue [#8](https://github.com/bestagentkits/ak-vault/issues/8). Open: red-team scenario 13 follow-ups and the other items listed there. |
| Browser dashboard (`/app`) | **Pre-release.** On in production since 2026-11-01 by owner decision, before its gate ([#203](https://github.com/bestagentkits/ak-vault/issues/203)). The browser is an enrolled device and decrypts with its own keys. | An enrolled account | [Remote access gates](./security/release-gates.md#remote-access-gates), issue [#101](https://github.com/bestagentkits/ak-vault/issues/101) |
| Remote MCP (`/mcp`) and device relay | **Pre-release.** Same flag and decision as the dashboard. Reads and `run` need an online device whose `ak` has relay support, which is not in a released CLI. With no device online, a set or delete is sealed and queued. | An authorized MCP client of an enrolled account | Same as the dashboard |
| Device-sealed input requests (`/input`) | **Pre-release.** On in production on top of remote access ([ADR 0004](./adr/0004-device-sealed-input-requests.md)). | The requesting account, recorded device only | Same as the dashboard |
| Recovery kit email backup | Design accepted, implementation in progress ([ADR 0005](./adr/0005-client-encrypted-recovery-kit-email-backup.md)). | Not available | Not started as a gate |
| Member invitations | Proposed, not implemented ([ADR 0003](./adr/0003-owner-signed-member-invitations.md)). | Not available | None |

The flags that switch each surface are owned by `worker/wrangler.jsonc`,
`worker/src/env.ts` and the [remote access runbook](./operations/runbooks.md#remote-access);
read them, not this table, to learn what a given deploy serves. Sync can be turned
off with the [kill switch](./operations/runbooks.md#emergency-kill-switch); remote
access can be turned off on its own with
[remote access off](./operations/runbooks.md#remote-access-off).

## Remote MCP plaintext boundary

The zero-knowledge claim covers sync: the server stores ciphertext and wrapped keys
and holds no key that opens them. **It does not cover remote MCP in transit.**
Remote MCP is a hosted endpoint, so TLS ends at the Worker and plaintext passes
through Worker memory during a call
([ADR 0002](./adr/0002-browser-device-relay-and-remote-mcp.md) D7):

| Plaintext in Worker memory | For how long |
|---|---|
| The value an AI tool sends with a set | Until the Worker seals it or relays it to your device |
| The name and purpose of a `secrets_prepare_write` request | Until the Worker seals them |
| Names, metadata and redacted `run` output a device returns | On their way to the AI tool |

What holds regardless: the Worker holds no vault key; it never logs, stores or
puts this plaintext in an error ([data classification](./security/data-classification.md));
MCP tools never return a secret value. What does not: an MCP client does not verify
device signatures, so it trusts the Worker for what a result says, and a Worker
compromise during a call could read the values above. Do not describe remote MCP as
end-to-end or zero-knowledge in transit. For a secret an AI must not see, use
`secrets_prepare_write` and type the value in an enrolled browser, never in chat.
The attack analysis is in the [threat model](./security/threat-model.md).

## Releases

This repository publishes Go module tags (`go/v*`); the CLI that users run is
released from [bestagentkits/agentkit](https://github.com/bestagentkits/agentkit).
A `go/v*` tag is a library version for that CLI, not a product release, so it
carries no ak-vault release notes of its own, and **no GitHub release exists for
these tags**: [#218](https://github.com/bestagentkits/ak-vault/issues/218) tracks
publishing one for each CLI-facing tag, marked as a pre-release while sync is not
GA, with the same state as the table above in its notes.

## Keeping this page true

Change this page in the same pull request that changes a row: a flag flipped in
`worker/wrangler.jsonc`, a gate ticked in release gates, an `ak` release that
exposes or hides a command. When it disagrees with those owners, they win and this
page is the bug. The landing page, `llms.txt` and the README link here instead of
restating the table.
