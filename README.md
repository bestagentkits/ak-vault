# ak-vault

Opt-in, local-first, end-to-end encrypted sync for AgentKit secrets (`ak secrets`)
between your trusted devices. The server stores ciphertext and a small, documented
set of operational metadata; it never holds a key that can decrypt your secrets.

Landing page: https://vault.agentkit.best

## Status

- **Design: Proposed.** [ADR 0001](./docs/adr/0001-opt-in-zero-knowledge-sync.md)
  awaits owner approval and an external cryptographic review.
- **Security review: pending.** Tracked on
  [#8](https://github.com/bestagentkits/ak-vault/issues/8).
- **Sync is not generally available.** Do not store production credentials in it.
  The production sync API is switched on ahead of the external review, under an
  owner waiver recorded on #8, but ak-web does not issue production vault tokens
  yet, so no client can sync with it. Open items are in the
  [release gates](./docs/security/release-gates.md).

AgentKit's local vault works without this service and without a network
connection. Sync is off unless you turn it on.

## Why

AgentKit vault v1 keeps secrets on one machine. Using them on a second device, and
later in shared or CI vaults, needs sync that does not trust the server with the
secrets, does not lose concurrent edits, and does not let a stale device bring back
a deleted credential. The reasoning and the limits are in the
[ADR](./docs/adr/0001-opt-in-zero-knowledge-sync.md) and the
[threat model](./docs/security/threat-model.md).

## What is in this repository

| Path | Contents |
|---|---|
| `docs/protocol/v1/spec.md` | Normative protocol v1 wire spec |
| `protocol/v1/vectors/` | Deterministic test vectors shared by every implementation |
| `packages/protocol/` | TypeScript reference implementation |
| `go/` | Go implementation |
| `worker/` | Cloudflare Worker and per-vault SQLite Durable Object; `worker/public/` is the landing page |
| `docs/` | Design, security and operations docs ([index](./docs/README.md)) |

The AgentKit CLI and Desktop client live in
[bestagentkits/agentkit](https://github.com/bestagentkits/agentkit); account
login and vault tokens in [bestagentkits/ak-web](https://github.com/bestagentkits/ak-web).

## Contributing

Requires Node 22+, pnpm (version pinned in `package.json`) and Go.

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
cd go && go test ./...
```

Read [AGENTS.md](./AGENTS.md) before starting: it covers the issue and label
workflow, security rules, and what a spec change requires. Reviews follow
[REVIEW.md](./REVIEW.md).

- Issues: https://github.com/bestagentkits/ak-vault/issues
- Epic: [#1](https://github.com/bestagentkits/ak-vault/issues/1)

Do not post exploit details or secrets in public issues. Report vulnerabilities
privately through GitHub's
[private vulnerability reporting](https://github.com/bestagentkits/ak-vault/security/advisories/new).

## License

[MIT](./LICENSE)
