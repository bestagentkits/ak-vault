# ak-vault documentation

Start with the root [README](../README.md) and [AGENTS.md](../AGENTS.md). Use this
page to find the owner of a question.

| Question | Owner |
|---|---|
| Why opt-in zero-knowledge sync, and what was rejected? | [ADR 0001](./adr/0001-opt-in-zero-knowledge-sync.md) |
| Exact wire format, primitives, encodings, errors | [Protocol v1 spec](./protocol/v1/spec.md) (normative) |
| Who can attack what, and which test proves the defense? | [Threat model](./security/threat-model.md) |
| What the server can see; logging and retention rules | [Data classification](./security/data-classification.md) |
| Devices, rekey, recovery, compromise response | [Key lifecycle and recovery](./security/key-lifecycle-and-recovery.md) |
| What must be true before GA | [Release gates](./security/release-gates.md) |
| Which tests exercised each red-team scenario, and what they found | [Red-team evidence](./security/red-team-evidence.md) |
| How to run the real CLI on two devices against a local Worker (soak, latency, disclosure) | [Docker two-device e2e](../e2e/docker/README.md) |
| Incidents, kill switch, rollback, restore, key rotation | [Runbooks](./operations/runbooks.md) |
| What it costs on Cloudflare | [Cost model](./operations/cost-model.md) |
| What the rollback, restore and kill-switch rehearsals and the cost run showed | [Rehearsal log](./operations/rehearsal-2026-10.md) |
| Landing page visual design | [Design guidelines](./design-guidelines.md) |
| How to review a change | [REVIEW.md](../REVIEW.md) |

Executable owners:

- Deterministic vectors: `protocol/v1/vectors/`
- TypeScript reference implementation: `packages/protocol/`
- Go implementation: `go/`
- Worker, Durable Object, limits and tests: `worker/src/`, `worker/test/`
- Two-device Docker e2e (real `ak`, fake ak-web, local Worker): `e2e/docker/`
- Platform log disclosure scan on a throwaway lab Worker: `worker/scripts/platform-log-scan/`
- Cost measurement on a lab Worker with the staging configuration: `worker/scripts/cost-measurement/`
- Landing page: `worker/public/`
- CI/CD: `.github/workflows/`

Work in progress and audit reports live under `plans/`; they are records, not
current authority.
