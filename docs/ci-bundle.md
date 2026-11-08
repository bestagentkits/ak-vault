# CI bundle

The CI bundle lets a protected CI job use an explicitly selected set of secrets
from a trusted `ak secrets` vault, with no cloud ak-vault access, no interactive
step and no plaintext secret file. It is **not** cloud sync, not protocol v1 and
not zero-knowledge hosted CI. It is independent of sync: it works with the
local-only vault, and sync can stay off.

The CLI is owned by [`bestagentkits/agentkit`](https://github.com/bestagentkits/agentkit)
(`ak secrets bundle` and `ak secrets run --bundle`; check `ak secrets bundle --help`
for the current flags). This page owns the file format, the threat model and the
operating procedure. Tracking issue: [#239](https://github.com/bestagentkits/ak-vault/issues/239)
(Phase 1 only; OIDC and hosted retrieval are a separate, deferred evaluation).

## Format (version 1)

A bundle file is the line `AK-CI-BUNDLE v1` followed by an
[age](https://age-encryption.org) file in ASCII armor, encrypted to one X25519
recipient. Confidentiality and tamper detection come from age (X25519 key
agreement, ChaCha20-Poly1305 in authenticated 64 KiB chunks). There is no custom
cryptography. The decrypted payload is JSON:

| Field | Meaning |
|---|---|
| `version` | `1`. Any other value is refused. |
| `profile` | Trust-boundary label (`a-z0-9-_`, 1-64). Bound inside the encryption. |
| `createdAt` | RFC 3339 UTC creation time. Informational. |
| `entries[]` | `{env, value}`: the variable name and the secret. At most 64. |

Rules a reader enforces, all fail closed:

- file at most 256 KiB, payload at most 192 KiB, one value at most 16 KiB;
- the first line must be exactly the magic line; a `v2` or later line is refused;
- unknown JSON fields, trailing data, duplicate variable names (case-insensitive),
  empty values and no entries are refused;
- variable names pass the same rule as `ak secrets run --env`, so a bundle cannot
  set `PATH`, `LD_*`, `NODE_OPTIONS`, `GIT_*`, proxy or other runtime-steering
  variables;
- the payload `profile` must equal the profile the job asks for (`--profile`), so
  a staging bundle handed to a production job is refused after it authenticates.

The bundle carries no vault ref names, grants, membership, device keys, recovery
material or metadata. It carries only the variable names and values you selected.
Each seal uses a fresh age file key, so two bundles of the same payload differ.

The CI decryption key is an age X25519 identity created by
`ak secrets bundle keygen`, dedicated to one trust boundary. It is never the
personal vault's passphrase, recovery key or a device key.

## Threat model

What the bundle protects, and what it does not.

| Property | Statement |
|---|---|
| At rest | The file is safe to store in a repository, artifact or cache **only as long as the key stays secret**. Anyone with the bundle and the key reads **every** included value. |
| Key holder | The CI provider holds the decryption key (its secret store), and so can read the bundle. A CI provider compromise exposes the bundled values. |
| At runtime | The runner decrypts in memory and the child process receives plaintext in its environment. The program, anything it starts, and any process of the same user on the runner can read it. |
| Compromised job | A malicious or compromised job step can read the key and the values and exfiltrate them. The bundle does not prevent this and is not workload-side zero knowledge. |
| Revocation | A copy of a bundle cannot be revoked remotely. Rotating the underlying secret at its provider is the only revocation. |
| Refresh | Updating or rotating is an operator action: re-run `bundle create` on the trusted device and replace the CI copy. |
| Log redaction | Output is struck of the delivered values. This is best effort: it misses encoded, split, reversed or otherwise transformed forms. It is not a control. |
| Wrong environment | A bundle made for another profile, sealed to another key, altered, truncated or oversized is refused and no program starts. |
| Fork and untrusted code | Secrets must not reach untrusted pull-request code. See the workflow rules below. `ak secrets run --bundle` also refuses `pull_request_target` under GitHub Actions. |

Not in Phase 1: OIDC, machine enrollment, a cloud retrieval endpoint, per-secret
cryptographic access control, team RBAC, a CI-provider matrix, central revocation.

## Operating it

### Create

```sh
# Trusted owner device. One key and one bundle per trust boundary.
ak secrets bundle keygen --key-out ./ci-production.key
#   prints the public recipient (age1...); the key file is 0600 and never printed.

ak secrets bundle create --profile ci-production \
  --encrypt-for age1... \
  --secret DEPLOY_TOKEN=<vault ref> \
  --output ci-production.akv

# Load the key into the protected CI environment's secret store, then delete it.
gh secret set AK_CI_DECRYPT_KEY --env production < ci-production.key
shred -u ci-production.key 2>/dev/null || rm -P ci-production.key
```

### Use in GitHub Actions

```yaml
name: deploy
on:
  push:
    branches: [main]            # reviewed code only; never pull_request_target
permissions:
  contents: read                # minimal GITHUB_TOKEN
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production     # required reviewers + branch restriction live here
    steps:
      - uses: actions/checkout@<full commit sha>   # pin by SHA
        with:
          persist-credentials: false
      - name: Install ak (pinned)
        run: ./scripts/install-ak.sh <pinned version and checksum>
      - name: Deploy
        env:
          AK_CI_DECRYPT_KEY: ${{ secrets.AK_CI_DECRYPT_KEY }}
        run: ak secrets run --bundle ci/ci-production.akv --profile ci-production -- ./deploy.sh
```

Repository settings that make this safe:

- Put the key in an **Environment** secret (not a repository secret) on
  `production`, with required reviewers and a deployment branch rule limited to
  `main`. Use a separate environment, key and bundle for staging.
- Never trigger a job that holds the key from `pull_request_target`, from forks,
  or from a workflow a pull request can edit. Fork `pull_request` runs get no
  secrets, so the key is empty and `run --bundle` refuses.
- Pin every action by commit SHA, pin the `ak` version, and review changes to the
  workflow and to `deploy.sh` with code-owner review.
- Do not upload the bundle, the key or the job environment as an artifact or
  cache, and do not enable step debug logging on the deploy job.
- The program after `--` is yours: it receives the values. Run only reviewed
  code, and avoid interpreters fed untrusted input.

### Update or rotate a secret

1. Rotate the secret at its provider.
2. Update it in the trusted vault (`ak secrets rotate` or `set`).
3. Re-run `bundle create` with the same recipient and replace `ci-production.akv`
   through a reviewed commit. The old bundle still decrypts with the old values
   until they are revoked at the provider.

### Rotate the CI decryption key

1. `bundle keygen` a new key for the boundary and `bundle create` a new bundle
   sealed to its recipient.
2. Update the environment secret and merge the new bundle together.
3. Delete the old key everywhere. Old bundle copies stay decryptable by the old
   key, so also rotate the secrets they hold if that key may have leaked.

### Compromised runner or key

Treat every value in every bundle the key opens as exposed.

1. Rotate those secrets at their providers first.
2. Disable the environment or remove the CI secret so no further job can decrypt.
3. Generate a new key, re-create and replace the bundle, and re-enable.
4. Review the provider audit logs for use of the old values, and record the
   incident on an issue (never the values).

### Key or bundle lost

A lost key cannot be recovered. Create a new key and bundle from the vault.
The vault is the source of truth, so nothing else is lost.

## Evidence

The negative and end-to-end behavior is exercised by the agentkit test suite:
wrong key, tampered, truncated, oversized and malformed files, wrong profile,
missing key, `pull_request_target`, a value or the key leaking into output, and
the key variable not reaching the child (`secretscmd` bundle tests and
`internal/runtime/secrets/cibundle`). A real-binary test builds `ak` and runs the
CI half in an empty home with no vault, no terminal and a scrubbed environment
(`TestCIBundleFreshRunner` in `apps/cli`).

Open: a run of this on a GitHub-hosted fresh runner (a workflow that checks out a
pinned `ak`, decrypts an example bundle and scans the recorded logs and artifacts)
is tracked on [#239](https://github.com/bestagentkits/ak-vault/issues/239); the
Phase 1 definition of done waits on it.
