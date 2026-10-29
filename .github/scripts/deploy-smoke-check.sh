#!/usr/bin/env bash
# Post-deploy smoke for one Worker environment, run by the Deploy workflow after
# each deploy and usable by hand (read-only GETs, no credentials):
#
#   .github/scripts/deploy-smoke-check.sh <base-url> <wrangler-env>
#
# <wrangler-env> is `staging`, or an empty string for production (the top-level
# Wrangler config, as `wrangler deploy --env=""`). Needs `pnpm install` first: the
# expected sync flag is read with Wrangler's own config reader from worker/, so it
# is the VAULT_SYNC_ENABLED value that deploy applied to this environment.
#
# Checks, each probe:
#   - GET /healthz answers 200 and reports `sync_enabled` equal to the config value
#     (the Worker treats anything other than exactly "true" as off);
#   - an unauthenticated GET on a synthetic vault answers 401 with sync on, or 503
#     with the `sync_disabled` code with sync off;
#   - GET / (landing page) answers 200.
# Edge propagation after a deploy is not atomic, so it probes until REQUIRED_PASSES
# consecutive probes pass, and fails after MAX_ATTEMPTS. It prints status codes and
# booleans only; response bodies are never printed.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <base-url> <wrangler-env (staging, or \"\" for production)>" >&2
  exit 2
fi
base_url="${1%/}"
wrangler_env="$2"
case "$base_url" in
  https://* | http://127.0.0.1:* | http://localhost:*) ;;
  *) echo "::error::base URL must be https (or a local wrangler dev URL)" >&2; exit 2 ;;
esac

max_attempts="${SMOKE_MAX_ATTEMPTS:-24}"
interval_s="${SMOKE_INTERVAL_SECONDS:-5}"
required_passes="${SMOKE_REQUIRED_PASSES:-3}"
# A well-formed vault ID (16 zero bytes, base64url) that no client creates; the request
# is refused by the kill switch or the missing token before any vault is touched.
synthetic_vault_path="/v1/vaults/AAAAAAAAAAAAAAAAAAAAAA/membership"

worker_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../worker" && pwd)"
expected="$(
  cd "$worker_dir" &&
    WRANGLER_LOG=error SMOKE_WRANGLER_ENV="$wrangler_env" node --input-type=module -e '
      import { unstable_readConfig } from "wrangler";
      const env = process.env.SMOKE_WRANGLER_ENV || undefined;
      const config = unstable_readConfig({ env });
      process.stdout.write(config.vars?.VAULT_SYNC_ENABLED === "true" ? "true" : "false");
    '
)"
if [ "$expected" != "true" ] && [ "$expected" != "false" ]; then
  echo "::error::could not read VAULT_SYNC_ENABLED from the Wrangler config" >&2
  exit 1
fi
echo "environment=${wrangler_env:-production} expected_sync_enabled=${expected}"

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

# Prints the HTTP status of a GET (000 on a transport failure) and leaves the body in $body.
get_status() {
  : >"$body"
  curl -sS -o "$body" -w '%{http_code}' --max-time 10 "${base_url}$1" 2>/dev/null || true
}

probe() {
  local health_status health_sync vault_status vault_sync_disabled landing_status ok=true

  health_status="$(get_status /healthz)"
  health_sync="$(jq -r 'if (.sync_enabled | type) == "boolean" then .sync_enabled else "missing" end' "$body" 2>/dev/null || echo missing)"

  vault_status="$(get_status "$synthetic_vault_path")"
  vault_sync_disabled="$(jq -r '.error.code == "sync_disabled"' "$body" 2>/dev/null || echo false)"

  landing_status="$(get_status /)"

  [ "$health_status" = "200" ] && [ "$health_sync" = "$expected" ] || ok=false
  if [ "$expected" = "true" ]; then
    [ "$vault_status" = "401" ] || ok=false
  else
    [ "$vault_status" = "503" ] && [ "$vault_sync_disabled" = "true" ] || ok=false
  fi
  [ "$landing_status" = "200" ] || ok=false

  echo "healthz=${health_status} sync_enabled=${health_sync} vault_probe=${vault_status} sync_disabled=${vault_sync_disabled} landing=${landing_status} pass=${ok}"
  [ "$ok" = "true" ]
}

passes=0
for attempt in $(seq 1 "$max_attempts"); do
  printf 'attempt %s: ' "$attempt"
  if probe; then
    passes=$((passes + 1))
    if [ "$passes" -ge "$required_passes" ]; then
      echo "smoke passed: ${passes} consecutive probes agree with the config"
      exit 0
    fi
  else
    passes=0
  fi
  if [ "$attempt" -lt "$max_attempts" ]; then sleep "$interval_s"; fi
done

echo "::error::smoke failed: the deployed Worker did not match the Wrangler config (sync flag ${expected}) in ${required_passes} consecutive probes within ${max_attempts} attempts" >&2
exit 1
