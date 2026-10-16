#!/usr/bin/env bash
# Keeps this device's background sync service running: the real
# `ak secrets sync now --watch --json`, under the pty driver so the file
# backend can read its passphrase. It starts once sync is enabled, and is
# restarted when it exits (--watch stops on an auth failure, a removed
# device or sync turned off; the scenarios expect that and check it).
#
# Control files in /run/e2e:
#   service.disabled  present: keep the service stopped
#   service.pid       the running driver's PID
# Every cycle's NDJSON line goes to ~/e2e-logs/sync-service.ndjson; the
# supervisor adds {"e2e":"service_start"|"service_exit"} lines around them.
set -uo pipefail

CTL=/run/e2e
LOG="$HOME/e2e-logs"
INTERVAL="${E2E_SYNC_INTERVAL:-5s}"
CONFIG="$AGENTKIT_HOME/secrets/sync/config.json"

now_ms() { date +%s%3N; }

sync_enabled() {
  [[ -s "$CONFIG" ]] && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("enabled") is True else 1)' "$CONFIG" 2>/dev/null
}

trap 'kill -TERM "$(cat "$CTL/service.pid" 2>/dev/null)" 2>/dev/null; exit 0' TERM INT

while true; do
  if [[ -e "$CTL/service.disabled" ]] || ! sync_enabled; then
    sleep 1
    continue
  fi
  printf '{"e2e":"service_start","ts_ms":%s}\n' "$(now_ms)" >> "$LOG/sync-service.ndjson"
  ak-pty-driver.py run --timeout 604800 -- ak secrets sync now --watch --interval "$INTERVAL" --json \
    >> "$LOG/sync-service.ndjson" 2>> "$LOG/sync-service.err" &
  pid=$!
  echo "$pid" > "$CTL/service.pid"
  wait "$pid"
  code=$?
  rm -f "$CTL/service.pid"
  printf '{"e2e":"service_exit","code":%s,"ts_ms":%s}\n' "$code" "$(now_ms)" >> "$LOG/sync-service.ndjson"
  sleep 2
done
