# shellcheck shell=bash
# Shared helpers for run.sh: logging, synthetic data, results and timing.
# Values and refs are synthetic and generated per run; they are kept in
# memory (and in the disclosure needle list) and never printed.

E2E_TZ=Asia/Saigon

log() { printf '[%s] %s\n' "$(TZ=$E2E_TZ date +%H:%M:%S)" "$*" >&2; }
die() { printf 'run.sh: %s\n' "$*" >&2; exit 2; }

now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

rand_hex() { od -An -tx1 -N"${1:-8}" /dev/urandom | tr -d ' \n'; }

# Every synthetic ref and value this run creates is appended to NEEDLES_FILE
# (a 0600 file in a private temp dir, removed at teardown); the disclosure
# scan searches the vault's state and logs for each of them. A file, not an
# array, because refs and values are created inside $(...) and subshells.

# new_ref PREFIX: a fresh synthetic ref, recorded as a needle.
new_ref() {
  local ref
  ref="E2E_${1}_$(rand_hex 5 | tr a-f A-F)"
  printf '%s\n' "$ref" >> "$NEEDLES_FILE"
  printf '%s' "$ref"
}

# new_value LABEL: a fresh synthetic value, recorded as a needle.
new_value() {
  local value
  value="e2e-synthetic-${1}-$(rand_hex 12)"
  printf '%s\n' "$value" >> "$NEEDLES_FILE"
  printf '%s' "$value"
}

sha256_of() { printf '%s' "$1" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }

# json_get JSON KEY: a top-level field of a one-line JSON object.
json_get() { python3 -c 'import json,sys; v=json.loads(sys.argv[1]).get(sys.argv[2]); print("" if v is None else str(v).lower() if isinstance(v,bool) else v)' "$1" "$2"; }

# ---- results ----

# RESULTS_DIR/results.tsv: scenario<TAB>status<TAB>duration_ms<TAB>detail
# RESULTS_DIR/latency.tsv: kind<TAB>ms (propagation samples)
RESULT_ROWS=0
RESULT_FAILS=0

record_result() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS_DIR/results.tsv"
  RESULT_ROWS=$((RESULT_ROWS + 1))
  [[ "$2" == PASS ]] || RESULT_FAILS=$((RESULT_FAILS + 1))
}

record_latency() { printf '%s\t%s\n' "$1" "$2" >> "$RESULTS_DIR/latency.tsv"; }

# Scenario steps report through these; a failed check ends the scenario.
# Detail lines go to a file because checks often run inside $(...).
# Details never carry a ref or a value.
DETAIL_FILE=/dev/null
note() { printf '%s\n' "$*" >> "$DETAIL_FILE"; log "  $*"; }
fail() { printf 'FAIL: %s\n' "$*" >> "$DETAIL_FILE"; log "  FAIL: $*"; return 1; }

# run_scenario NAME FUNCTION: runs FUNCTION in a subshell with errexit, so a
# failed step stops only that scenario, and records PASS or FAIL with its
# duration and detail lines.
run_scenario() {
  local name=$1 fn=$2 start end status detail
  DETAIL_FILE=$(mktemp "$RESULTS_DIR/.detail.XXXXXX")
  log "scenario: $name"
  start=$(now_ms)
  # Not under `if`: bash ignores errexit in a condition, subshells included.
  local rc
  set +e
  ( set -e; "$fn" )
  rc=$?
  set -e
  if (( rc == 0 )); then status=PASS; else status=FAIL; fi
  end=$(now_ms)
  detail=$(python3 -c 'import sys; print(" | ".join(l.strip() for l in open(sys.argv[1]) if l.strip()))' "$DETAIL_FILE")
  rm -f "$DETAIL_FILE"
  DETAIL_FILE=/dev/null
  record_result "$name" "$status" "$((end - start))" "$detail"
  log "scenario: $name $status ($(( (end - start) / 1000 )) s)"
}

# latency_stats FILE KIND: "n=.. p50=.. p95=.. max=.." in ms for KIND samples.
latency_stats() {
  python3 - "$1" "$2" <<'PY'
import sys
path, kind = sys.argv[1:]
try:
    xs = sorted(int(l.split("\t")[1]) for l in open(path) if l.split("\t")[0] == kind)
except OSError:
    xs = []
if not xs:
    print("n=0"); sys.exit(0)
def pct(p):
    # nearest-rank percentile
    k = max(0, min(len(xs) - 1, -(-len(xs) * p // 100) - 1))
    return xs[int(k)]
print(f"n={len(xs)} p50={pct(50)} p95={pct(95)} max={xs[-1]}")
PY
}

print_results() {
  python3 - "$RESULTS_DIR/results.tsv" <<'PY'
import sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
w = max([len("scenario")] + [len(r[0]) for r in rows])
print(f"{'scenario':<{w}}  {'result':<6}  {'time':>8}  detail")
print(f"{'-'*w}  ------  --------  ------")
for name, status, ms, detail in rows:
    print(f"{name:<{w}}  {status:<6}  {int(ms)/1000:>7.1f}s  {detail}")
PY
}
