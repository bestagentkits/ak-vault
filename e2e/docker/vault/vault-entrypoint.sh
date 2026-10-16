#!/usr/bin/env bash
# Starts the Worker under `wrangler dev --env staging` for the e2e stack.
#
# - Refuses to start with Cloudflare credentials in the environment, or with a
#   .dev.vars or .env file in the worker directory: nothing here may depend on
#   a real secret, and wrangler would load those files.
# - Trusts fake-akweb as issuer: VAULT_ISSUER is the origin devices use for
#   ak-web, VAULT_JWKS_JSON is fake-akweb's ephemeral public key, read from the
#   volume it shares with this service.
# - The revocation webhook secret, also ephemeral, is passed through an
#   --env-file on tmpfs, so wrangler treats it as a secret and never prints it.
# - --local-upstream keeps request.url equal to the loopback origin devices
#   sign their proofs for (they reach this port through a local forwarder).
# - Durable Object state persists in /state across restarts (the kill-switch
#   scenario restarts this service); the log is appended to /logs/worker.log
#   so the disclosure scan sees every run of it.
set -euo pipefail

: "${VAULT_SYNC_ENABLED:?set VAULT_SYNC_ENABLED}"
: "${VAULT_ISSUER:?set VAULT_ISSUER}"
: "${VAULT_AUDIENCE:?set VAULT_AUDIENCE}"
SHARED_DIR="${SHARED_DIR:-/shared}"
PORT="${VAULT_PORT:-8787}"
UPSTREAM="${VAULT_AUDIENCE#http://}"

die() { printf 'vault-entrypoint: %s\n' "$*" >&2; exit 2; }

for name in $(compgen -e); do
  case "$name" in CLOUDFLARE_*|CF_*) die "Cloudflare credentials must not reach this container" ;; esac
done
shopt -s nullglob dotglob
for f in /app/worker/.dev.vars* /app/worker/.env*; do
  die "refusing to start: $(basename "$f") exists in the worker directory"
done
shopt -u nullglob dotglob

case "$VAULT_SYNC_ENABLED" in true|false) ;; *) die "VAULT_SYNC_ENABLED must be true or false" ;; esac

# fake-akweb publishes its key and the webhook secret at startup.
for _ in $(seq 1 60); do
  [[ -s "$SHARED_DIR/jwks.json" && -s "$SHARED_DIR/webhook-secret" ]] && break
  sleep 1
done
[[ -s "$SHARED_DIR/jwks.json" && -s "$SHARED_DIR/webhook-secret" ]] || die "fake-akweb did not publish its JWKS and webhook secret"
JWKS="$(cat "$SHARED_DIR/jwks.json")"

ENV_DIR="$(mktemp -d /run/vault/env.XXXXXX)"
umask 077
printf 'REVOCATION_WEBHOOK_SECRET=%s\n' "$(cat "$SHARED_DIR/webhook-secret")" > "$ENV_DIR/worker.env"

mkdir -p /logs/wrangler /state
# wrangler's own debug log goes to the scanned log volume as well.
export WRANGLER_LOG_PATH=/logs/wrangler
exec > >(tee -a /logs/worker.log) 2>&1
printf '=== vault start %s sync_enabled=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$VAULT_SYNC_ENABLED"

exec npx --no-install wrangler dev --env staging \
  --ip 0.0.0.0 --port "$PORT" --local-upstream "$UPSTREAM" \
  --persist-to /state \
  --env-file "$ENV_DIR/worker.env" \
  --show-interactive-dev-session=false \
  --var "VAULT_SYNC_ENABLED:$VAULT_SYNC_ENABLED" \
  --var "VAULT_ISSUER:$VAULT_ISSUER" \
  --var "VAULT_AUDIENCE:$VAULT_AUDIENCE" \
  --var "VAULT_JWKS_JSON:$JWKS"
