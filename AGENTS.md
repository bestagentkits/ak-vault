# ak-vault collaborator guide

Instructions for humans and AI agents working in this repository. `CLAUDE.md`
points here. Review judgment lives in [REVIEW.md](./REVIEW.md); design rationale in
[ADR 0001](./docs/adr/0001-opt-in-zero-knowledge-sync.md); the wire contract in the
[protocol v1 spec](./docs/protocol/v1/spec.md). Navigation: [docs/README.md](./docs/README.md).

## Cold start

1. Read [README.md](./README.md), then the doc that owns your question via
   [docs/README.md](./docs/README.md).
2. Read the issue you are working on and its parent epic
   ([#1](https://github.com/bestagentkits/ak-vault/issues/1)).
3. Read nearby source, tests and vectors before changing behavior. Plans and reports
   under `plans/` are records, not current authority.

## Layout

| Path | Contents |
|---|---|
| `docs/protocol/v1/spec.md` | Normative wire spec |
| `protocol/v1/vectors/` | Deterministic cross-language test vectors (JSON) |
| `packages/protocol/` | TypeScript reference implementation and vector generator |
| `go/` | Go implementation that must reproduce every vector |
| `worker/` | Cloudflare Worker + per-vault SQLite Durable Object (`src/`, `test/`) |
| `worker/public/` | Landing page served at https://vault.agentkit.best |
| `docs/` | ADR, security, operations docs |

Commands and scripts are owned by `package.json` files; check them before relying
on the list below.

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm vectors          # regenerate protocol/v1/vectors via packages/protocol
cd go && go test ./...   # also: pnpm test:go
```

Node 22+ and pnpm (version pinned in `package.json`) are required.

## Security rules (non-negotiable)

- Never log, return in errors, emit as metrics, or write to fixtures any plaintext
  secret value or secret **name**, token, proof, key, or recovery material. See
  [data classification](./docs/security/data-classification.md).
- No custom cryptography. Use only the primitives and libraries in the spec.
- Fail closed: unknown version, algorithm, event type, epoch or signature, and any
  auth or revocation lookup error, is a refusal.
- No last-writer-wins, no server-side decryption, no server-authored membership.
- Never commit `.env`, `.dev.vars`, tokens, keys, account identifiers or personal
  data. Test data is synthetic.
- The Worker never receives the ak-web CLI HS256 signing key.
- Production deploys only through the protected `production` GitHub Environment.

## Spec and vector changes

A change to the spec or any wire behavior requires, in the same PR:

1. updating `docs/protocol/v1/spec.md`;
2. regenerating vectors with `pnpm vectors` and committing them;
3. TypeScript **and** Go suites green against the new vectors;
4. updating the [threat model](./docs/security/threat-model.md) if a guarantee or
   limitation changed.

Never widen a stated guarantee without vectors or tests that prove it.

## Collaboration protocol

Issues are the coordination surface. Labels: `in progress`, `blocked`, `in review`,
`done`, `shipped`, `ai-handle`.

**Before starting an issue**

- Check its labels and assignee. If someone else holds `in progress`, do not start;
  coordinate on the issue.
- Assign yourself and add `in progress`.
- One issue per branch and per worktree. Do not mix issues.

**While working**

- Blocked by a dependency or decision: add `blocked` and comment the reason and
  what would unblock it. Remove `blocked` when it clears.
- Found an **unrelated** bug, gap or hardening opportunity: open a new issue with
  the `ai-handle` label instead of widening scope.
- Found a **related or duplicate** issue: comment on it referencing the current
  issue (and vice versa when useful).

**Finishing**

1. Collect evidence: exact commands run and their results at the current head.
   Never claim done without it.
2. Review in an **isolated subagent context** (fresh reviewer, no implementation
   history) against [REVIEW.md](./REVIEW.md). Set `in review` while it runs; fix
   blockers and re-review.
3. Open the PR with `Closes #N`, the evidence, docs impact, and links to related
   issues. Set `done` (PR opened).
4. After merge to `main`, set `shipped`.
5. Clean up: remove test caches and temporary state you created (`.wrangler/`,
   coverage, temp dirs) and stop any dev servers or watchers you started.

**Commits and pushes**

- Conventional commits, focused, no AI attribution, no internal plan or finding IDs.
- Do not force-push `main`. Do not bypass hooks or weaken tests to get green.
- `main` is protected by a repository ruleset: changes land through a pull request
  whose CI checks (TypeScript, Go cross-verification, secret scan) are green; deletion
  and non-fast-forward pushes are blocked. A green CI run on `main` triggers the
  Deploy workflow (staging, then the gated production environment).
- Delegated agents do not commit, push or merge unless explicitly assigned.

## Release gate

Sync is not GA. Production sync stays behind `VAULT_SYNC_ENABLED=false` until every
item in [release gates](./docs/security/release-gates.md) is met at the release
commit, including an external review recorded on
[#8](https://github.com/bestagentkits/ak-vault/issues/8). No agent may self-attest
that review.

## Operations

How to operate the service is owned by
[runbooks](./docs/operations/runbooks.md). Never write tokens, account IDs or
customer names into docs, plans, issues or reports.

## Documentation

Docs own why and where; code, tests, vectors and config own what and how. Link to
the owner instead of copying commands, limits or inventories. Update docs when a
guarantee, contract, workflow or operational route changes.
