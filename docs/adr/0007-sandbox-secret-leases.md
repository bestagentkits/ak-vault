# ADR 0007: Sandbox secret leases

- **Status:** Accepted on 2026-11-26 by the owner (owner instruction in chat, recorded by an agent on the owner's behalf). Leases stay off until `VAULT_LEASES_ENABLED` is turned on through a reviewed config PR and the gated Deploy workflow.
- **Proposed:** 2026-11-16
- **Amends:** the new-endpoint row of the [REVIEW.md](../../REVIEW.md) hard rejection
  criteria and the remote-access route list in
  [AGENTS.md](../../AGENTS.md#security-rules-non-negotiable), both widened in the same
  pull request by the `leases` routes only; spec §9 item 4 (a second non-member path).
- **Tracking:** [#242](https://github.com/bestagentkits/ak-vault/issues/242); CLI half
  [agentkit#3189](https://github.com/bestagentkits/agentkit/issues/3189)
- **Wire contract:** [spec §3.14](../protocol/v1/spec.md#314-sandbox-secret-leases) and the
  routes in §9.6. The spec wins if they disagree.

## Context

Cloud sandboxes (hosted agents, CI-like runners, disposable VMs) need a few secrets for
one run. Enrolling each sandbox as a vault device gives it the vault-wide key (§3: a vault
key decrypts every item), which is far more than the run needs and outlives it. The
remote MCP relay (ADR 0002) keeps values out of the sandbox but needs an online device for
every call. ADR 0006 approvals only authorise a member device that already holds the
value. We want a person to pre-approve exactly which values one sandbox gets, for how
long, without the Worker learning names or values.

## Decision

1. **D1: A lease is requested by a non-member sandbox key.** The sandbox generates, per
   lease, a one-time X25519 lease key and an Ed25519 request key, both held in memory (or a
   `0600` temp file deleted at expiry). It seals the subject (env var → secret reference,
   purpose) to the epoch's seal key (§3.6 construction, its own HKDF `info` and AAD `ctx`)
   and signs the request with the request key. The Worker sees the account, the sandbox's
   request device ID, sizes and times, never a name or value.
2. **D2: Who authenticates the sandbox.** No new session kind. The sandbox calls the lease
   routes with a vault token of the **requesting account** (`sub` a current member
   account, never anonymous) whose `did` is the kid of its request key, presented in
   `AKV-Device-Key` and proven by the usual per-request proof, the same shape as the
   recovery identity (§3.5). Admitted kinds: `api_key_device` (an AgentKit API key
   exchanged for a revocable device session: what a sandbox has) and `email_otp` (a person
   signing in inside the sandbox). `machine` is refused: a machine session belongs to an
   enrolled machine device, which already holds the vault key and has no use for a lease.
   `browser` and `input` are refused. The `did` must not be a current or removed member
   device. Live revocation is always consulted, so revoking the API key session stops the
   sandbox's fetch.
3. **D3: The person binds the request with the lease code.** The request is self-signed,
   so nothing but the person ties it to their sandbox: a holder of a leaked API key or the
   Worker itself could publish a look-alike request with its own lease key. The sandbox
   prints the **lease code**, the full request digest (`b64(SHA-256(cjson(request)))`, 43
   characters, no truncation), and the approving device refuses to open or grant a request
   whose digest differs from the code the person typed or pasted (`forbidden`). A short
   comparison code is not used because whoever fabricates the request could grind it.
4. **D4: Approve-and-seal is one signed grant from an enrolled human device.** A human
   `owner`/`editor` device of the same account (the CLI with the agent-ancestor guard, or a
   future `/app` flow) opens the subject, shows it, and on approval seals exactly the
   approved values (a subset of the requested vars) to the lease key with an expiry no later
   than `ts + ttl_s`, and signs the grant with its device key. A deny is signed too and
   carries no values. The Worker checks the grant's signature against the approver's current
   `sign_pub`, account binding and single decision; the approver is never the requester
   (a non-member cannot be a member device anyway).
5. **D5: Single-use delivery.** The sandbox collects the grant with `POST …/fetch`, a
   mutation that returns the grant once and deletes its ciphertext in the same transaction.
   A lost response means a new lease. An owner/editor device may revoke a lease before it
   is fetched (the ciphertext is deleted); after the fetch there is no clawback.
6. **D6: The sandbox verifies what it can.** It checks the grant binds its own request
   (lease ID, account, digest), its expiry, its AEAD under the in-memory lease key, that
   every var was requested, and the grant signature under the carried `approver_key`. It
   cannot check that key against membership (it holds no chain); a sandbox MAY pin the
   approver device IDs out of band, and then refuses any other approver.
7. **D7: Gated, off by default.** The routes answer `404` unless remote access and
   `VAULT_LEASES_ENABLED` are both set. No dashboard UI or MCP tool is part of this ADR.

## Honest boundary

- **The sandbox agent can read every approved value.** A lease hands plaintext to the
  sandbox environment for the lease lifetime, like `run`. Approve only what the run needs.
- **The Worker sees only ciphertext** and lease metadata (account, request device ID,
  approver device ID, decision, counts, sizes, times). It never sees a reference or value.
- **Withheld or forged answers.** The Worker can withhold a grant (the lease fails closed
  at expiry). Because the sandbox cannot verify membership, a malicious Worker could seal
  values of its own choosing to the lease key under a key it invents; with an approver pin
  the sandbox refuses that. Without a pin this departs from the "withhold, never forge"
  line of ADR 0006, for injected values only: it never discloses a vault value.
- **Seal-key substitution exposes references, not values.** The sandbox cannot verify the
  seal-key document chain; a malicious Worker that serves its own seal key learns the
  requested references (names). The CLI accepts a pinned seal-key fingerprint.
- **A leaked API key now gains more:** besides its member-device rights it can publish
  lease requests (each needs the person's lease code to be granted) and read the
  seal-key document of every vault of that account.
- An unfetched allow dies with its approver: removing the approving device, changing its
  role, or a rekey revokes it before release.
- No clawback after fetch; revoking the account session stops future fetches only.

## Consequences

- New spec section §3.14 with `lease.json` vectors reproduced by TypeScript and Go,
  including tamper, wrong key, expiry, replay onto another request, wrong digest,
  non-approved var and self-grant refusals.
- Spec §9 item 4 gains a second non-member path; REVIEW.md and AGENTS.md route lists name
  the lease routes and their auth.
- The CLI half (`ak secrets lease request`, the lease branch of `ak secrets approvals
  approve`, `ak secrets run --lease`) lives in agentkit.

## Owner decisions

On 2026-11-19 the owner told an agent to decide the open questions and record the result;
an agent recorded these decisions on the owner's behalf. They settle the questions below,
not the ADR itself; the owner accepted the ADR on 2026-11-26.

1. **Unpinned approver: accepted for the pre-release preview, pin recommended.** Without a
   pin a malicious Worker can inject values of its choosing, but cannot read a vault value;
   the CLI keeps the approver pin optional and the docs recommend it for any credential that
   matters. Revisit before GA (making the pin the default is the expected outcome).
2. **`email_otp` admitted alongside `api_key_device`.** Both are revocable account sessions
   under the same lease-identity checks, live revocation and per-account budget; a person
   signing in inside a sandbox is a real use, and admitting it adds no path the API key does
   not already have.
3. **24-hour ceiling kept** (`ttl_s` 60..86400). Long enough for a working day or a long CI
   job, short enough that a forgotten lease dies the same day; shorter leases are the
   requester's choice.
4. **Budget kept at 60 lease-identity calls per minute per account.** A request, a few status
   polls and one fetch per lease fit easily; abuse is bounded. Tune from staging data.
5. **Seal key refused while `rekey_required` is set.** `GET …/leases/seal-key` and
   `POST …/leases` answer `409 rekey_required` until the vault is rekeyed, because a removed
   device may still derive that epoch's seal key and would read the requested references;
   this matches the MCP seal-key rule (spec §3.6). Implemented and tested in this PR.
