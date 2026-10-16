#!/usr/bin/env bash
# Device-side helper the scenario runner calls through `docker compose exec`.
# Every step uses the real `ak` CLI; values arrive on stdin and are never
# printed. Output is one JSON object per call where a result is reported.
#
#   e2e-device.sh login EMAIL
#   e2e-device.sh init-vault                      file backend vault (recovery key kept on tmpfs)
#   e2e-device.sh set REF                         value on stdin; prints {"ts_ms"}
#   e2e-device.sh delete REF                      prints {"ts_ms"}
#   e2e-device.sh has REF                         exit 0 present, 1 absent, 2 listing failed
#   e2e-device.sh value-hash REF                  prints sha256:<hex> of the local value
#   e2e-device.sh wait-present REF TIMEOUT_S [SHA256]
#   e2e-device.sh wait-absent REF TIMEOUT_S       both print {"ok","ts_ms","polls"}
#   e2e-device.sh sync-now                        one cycle, NDJSON line on stdout, CLI exit code
#   e2e-device.sh status                          `ak secrets sync status --json`
#   e2e-device.sh device-id | session-sid
#   e2e-device.sh put-file NAME                   stdin to /run/e2e/NAME (0600; synthetic secrets only)
#   e2e-device.sh revoke sid|did ID [webhook-only]  the account page's revoke, via fake-akweb's test hook
#   e2e-device.sh attention-codes FILE            item codes a sync result reported (never refs)
#   e2e-device.sh conflicts-open                  open conflicts per `sync status --json`
#   e2e-device.sh members                         vault device IDs per `devices list --json`, sorted
#   e2e-device.sh service start|stop|exits|log-mark|log-has MARK REGEX
#   e2e-device.sh ak ARGS...                      any ak command under the pty driver (stdout passes through)
set -euo pipefail

CTL=/run/e2e
LOG="$HOME/e2e-logs"
DRIVER=ak-pty-driver.py
CONFIG="$AGENTKIT_HOME/secrets/sync/config.json"

now_ms() { date +%s%3N; }
die() { printf 'e2e-device: %s\n' "$*" >&2; exit 2; }

run_ak() { "$DRIVER" run -- ak "$@"; }

# refs prints the local store's refs, one per line (metadata only). It fails
# (exit 2) when the CLI fails or its output is not the expected envelope, so
# an error is never mistaken for an empty store.
refs() {
  local out
  out=$(ak secrets list --json) || return 2
  python3 -c '
import json, sys
try:
    doc = json.loads(sys.argv[1])
    rows = doc["data"]
    if doc.get("kind") != "secrets.list" or not isinstance(rows, list):
        raise ValueError
    for row in rows:
        print(row["ref"])
except (ValueError, KeyError, TypeError):
    sys.exit(2)
' "$out" || return 2
}

# has_ref REF: 0 present, 1 absent, 2 the store could not be listed.
has_ref() {
  local out
  out=$(refs) || return 2
  grep -qxF -- "$1" <<< "$out" && return 0
  return 1
}

value_hash() { "$DRIVER" reveal "$1"; }

# wait_present retries a failed listing (it cannot produce a false pass);
# wait_absent fails on one (an error must never read as "absent").
wait_present() {
  local ref=$1 timeout=$2 want=${3:-} polls=0 deadline seen
  deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    polls=$((polls + 1))
    if has_ref "$ref"; then
      seen=$(now_ms)
      if [[ -z "$want" ]] || [[ "$(value_hash "$ref" 2>/dev/null || true)" == "sha256:$want" ]]; then
        printf '{"ok":true,"ts_ms":%s,"polls":%s}\n' "$seen" "$polls"
        return 0
      fi
    fi
    sleep 0.25
  done
  printf '{"ok":false,"ts_ms":%s,"polls":%s}\n' "$(now_ms)" "$polls"
  return 1
}

wait_absent() {
  local ref=$1 timeout=$2 polls=0 deadline rc
  deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    polls=$((polls + 1))
    rc=0
    has_ref "$ref" || rc=$?
    case "$rc" in
      1) printf '{"ok":true,"ts_ms":%s,"polls":%s}\n' "$(now_ms)" "$polls"; return 0 ;;
      0) ;;
      *) printf '{"ok":false,"error":"list_failed","ts_ms":%s,"polls":%s}\n' "$(now_ms)" "$polls"; return 2 ;;
    esac
    sleep 0.25
  done
  printf '{"ok":false,"ts_ms":%s,"polls":%s}\n' "$(now_ms)" "$polls"
  return 1
}

set_value() {
  local ref=$1 tmp
  tmp=$(mktemp "$CTL/value.XXXXXX")
  trap 'rm -f "$tmp"' RETURN
  cat > "$tmp"
  [[ -s "$tmp" ]] || die "set: empty value on stdin"
  run_ak secrets set "$ref" --value-file "$tmp" --force --json > /dev/null
  printf '{"ts_ms":%s}\n' "$(now_ms)"
}

service() {
  case "$1" in
    start)
      rm -f "$CTL/service.disabled"
      ;;
    stop)
      touch "$CTL/service.disabled"
      local pid
      pid=$(cat "$CTL/service.pid" 2>/dev/null || true)
      [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 150); do
        [[ -e "$CTL/service.pid" ]] || return 0
        sleep 0.2
      done
      die "the sync service did not stop within 30 s"
      ;;
    exits)
      # Exit codes of service runs that ended, oldest first.
      { grep -h '"e2e":"service_exit"' "$LOG/sync-service.ndjson" 2>/dev/null || true; } \
        | python3 -c 'import json,sys; print(" ".join(str(json.loads(l)["code"]) for l in sys.stdin))'
      ;;
    log-mark)
      # Line counts of the service's stdout and stderr logs, for log-has.
      printf '%s:%s\n' "$({ wc -l < "$LOG/sync-service.ndjson"; } 2>/dev/null || echo 0)" "$({ wc -l < "$LOG/sync-service.err"; } 2>/dev/null || echo 0)"
      ;;
    log-has)
      # log-has MARK REGEX: an extended regex matches either log after MARK.
      local n=${2%%:*} e=${2##*:}
      { tail -n +"$((n + 1))" "$LOG/sync-service.ndjson" 2>/dev/null; tail -n +"$((e + 1))" "$LOG/sync-service.err" 2>/dev/null; } | grep -E -- "$3" > /dev/null
      ;;
    *) die "service start|stop|exits|log-mark|log-has" ;;
  esac
}

json_field() {
  python3 -c '
import json, sys
def find(node, key):
    if isinstance(node, dict):
        if key in node and isinstance(node[key], str):
            return node[key]
        for v in node.values():
            r = find(v, key)
            if r: return r
    elif isinstance(node, list):
        for v in node:
            r = find(v, key)
            if r: return r
    return ""
print(find(json.load(open(sys.argv[1])), sys.argv[2]))
' "$1" "$2"
}

put_file() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "put-file: bad name"
  umask 077
  cat > "$CTL/$1.tmp" && mv "$CTL/$1.tmp" "$CTL/$1"
}

# revoke sid|did ID [webhook-only]
revoke() {
  local field only=false
  case "$1" in sid) field=revoke_sids ;; did) field=revoke_dids ;; *) die "revoke sid|did ID [webhook-only]" ;; esac
  [[ "${3:-}" == webhook-only ]] && only=true
  python3 - "$AGENTKIT_REGISTRY_URL/__e2e/revoke" "$field" "$2" "$only" <<'PY'
import json, sys, urllib.request
url, field, value, only = sys.argv[1:]
body = {field: [value], "webhook_only": only == "true"}
req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                             headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as resp:
    sys.exit(0 if resp.status == 200 else 1)
PY
}

# attention_codes prints the code of every item a sync result reported, in
# `attention` and in the `discarded`, `repaired`, `skipped_repair` and
# `quarantined` lists, space separated. Never a ref.
attention_codes() {
  python3 -c '
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(0)
data = doc.get("data") or {}
out = []
for key in ("attention", "discarded", "repaired", "skipped_repair", "quarantined"):
    out += [item.get("code") or key for item in (data.get(key) or [])]
print(" ".join(out))
' "$1"
}

conflicts_open() {
  run_ak secrets sync status --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"].get("conflicts") or []))'
}

members() {
  run_ak secrets devices list --json | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
rows = data if isinstance(data, list) else data.get("devices", [])
print(" ".join(sorted(r["device_id"] for r in rows)))
'
}

cmd=${1:-}
shift || true
case "$cmd" in
  login) "$DRIVER" login "$1" > /dev/null ;;
  init-vault)
    # The file backend's vault, sealed under the synthetic passphrase. Its
    # recovery key stays on tmpfs; the scenarios never need it.
    run_ak secrets recovery init --label e2e --print-to "$CTL/file-vault-recovery.key" > /dev/null
    ;;
  set) set_value "$1" ;;
  delete) run_ak secrets delete "$1" --json > /dev/null; printf '{"ts_ms":%s}\n' "$(now_ms)" ;;
  has) rc=0; has_ref "$1" || rc=$?; exit "$rc" ;;
  value-hash) value_hash "$1" ;;
  wait-present) wait_present "$@" ;;
  wait-absent) wait_absent "$@" ;;
  sync-now) run_ak secrets sync now --json ;;
  status) run_ak secrets sync status --json ;;
  device-id) json_field "$CONFIG" device_id ;;
  session-sid) json_field "$AGENTKIT_HOME/auth/session.json" sessionId ;;
  service) service "$@" ;;
  put-file) put_file "$1" ;;
  revoke) revoke "$@" ;;
  attention-codes) attention_codes "$1" ;;
  conflicts-open) conflicts_open ;;
  members) members ;;
  ak) run_ak "$@" ;;
  *) die "unknown command: ${cmd:-<none>}" ;;
esac
