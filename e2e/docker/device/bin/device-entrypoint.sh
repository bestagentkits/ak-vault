#!/usr/bin/env bash
# Device container startup.
#
# The CLI accepts plain http only for loopback origins, so a device reaches
# the vault and fake-akweb through local TCP forwarders on 127.0.0.1. The
# Worker sees the same loopback origin (wrangler --local-upstream), so the
# CLI runs with its production proof wiring. Disconnecting this container
# from the stack network takes the device offline, forwarders included.
set -euo pipefail

die() { printf 'device-entrypoint: %s\n' "$*" >&2; exit 2; }

for name in $(compgen -e); do
  case "$name" in CLOUDFLARE_*|CF_*) die "Cloudflare credentials must not reach this container" ;; esac
done
[[ -d /run/e2e && -w /run/e2e ]] || die "/run/e2e must be a writable tmpfs"

# A fresh synthetic file-backend passphrase per container, on tmpfs only.
umask 077
if [[ ! -s "$E2E_PASSPHRASE_FILE" ]]; then
  printf 'e2e-synthetic-passphrase-%s' "$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" > "$E2E_PASSPHRASE_FILE"
fi
mkdir -p "$HOME/e2e-logs" "$AGENTKIT_HOME"

socat TCP-LISTEN:8787,bind=127.0.0.1,fork,reuseaddr TCP:vault:8787 &
socat TCP-LISTEN:8788,bind=127.0.0.1,fork,reuseaddr TCP:fake-akweb:8788 &

# The background sync service: `ak secrets sync now --watch` under a
# supervisor that starts it once sync is enabled and restarts it when it
# stops (an auth failure, a removed device, a restarted server).
exec /usr/local/bin/sync-service-supervisor.sh
