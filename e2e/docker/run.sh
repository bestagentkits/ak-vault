#!/usr/bin/env bash
# Two-device secrets-sync end-to-end run in Docker. See README.md.
#
#   e2e/docker/run.sh [--agentkit-dir DIR] [--agentkit-ref REF]
#                     [--scenarios a,b,...] [--soak DURATION] [--keep]
#
# Builds the vault (this checkout's Worker under wrangler dev), fake-akweb
# and two devices running the real `ak` from agentkit at REF, enrolls both
# devices in one vault, runs the scenarios, scans the vault's state and log
# for disclosures, prints a pass/fail table, tears everything down, and
# exits non-zero when anything failed.
# Runs on the macOS system bash (3.2): helpers called inside $(...) check
# every step explicitly instead of relying on errexit there.
set -euo pipefail
shopt -s inherit_errexit 2> /dev/null || true

E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$E2E_DIR/../.." && pwd)

# shellcheck source=lib/common.sh
source "$E2E_DIR/lib/common.sh"
# shellcheck source=lib/stack.sh
source "$E2E_DIR/lib/stack.sh"
# shellcheck source=lib/device.sh
source "$E2E_DIR/lib/device.sh"
# shellcheck source=lib/scenarios-data.sh
source "$E2E_DIR/lib/scenarios-data.sh"
# shellcheck source=lib/scenarios-membership.sh
source "$E2E_DIR/lib/scenarios-membership.sh"
# shellcheck source=lib/soak.sh
source "$E2E_DIR/lib/soak.sh"
# shellcheck source=lib/disclosure.sh
source "$E2E_DIR/lib/disclosure.sh"

ALL_SCENARIOS=(propagation concurrent_writes tombstone offline_catch_up kill_switch session_revocation device_removal recovery)

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

AGENTKIT_DIR=${AGENTKIT_DIR:-$(cd "$REPO_DIR/.." && pwd)/agentkit}
AGENTKIT_REF=${AGENTKIT_REF:-origin/dev}
SCENARIOS=("${ALL_SCENARIOS[@]}")
SOAK_SECONDS=0
KEEP=false

while (( $# )); do
  case "$1" in
    --agentkit-dir) AGENTKIT_DIR=${2:?}; shift 2 ;;
    --agentkit-ref) AGENTKIT_REF=${2:?}; shift 2 ;;
    --scenarios) IFS=, read -r -a SCENARIOS <<< "${2:?}"; shift 2 ;;
    --soak) SOAK_SECONDS=$(duration_s "${2:?}"); shift 2 ;;
    --keep) KEEP=true; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'run.sh: unknown argument: %s\n' "$1" >&2; usage 2 ;;
  esac
done
for s in "${SCENARIOS[@]}"; do
  [[ " ${ALL_SCENARIOS[*]} " == *" $s "* ]] || die "unknown scenario: $s (known: ${ALL_SCENARIOS[*]})"
done

for tool in docker git python3 od; do command -v "$tool" > /dev/null || die "$tool is required"; done
docker compose version > /dev/null 2>&1 || die "docker compose v2 is required"

# No real credential may reach the build or the containers: drop Cloudflare
# variables from this process, and refuse local secret files in the worker.
for name in $(compgen -e); do
  case "$name" in CLOUDFLARE_*|CF_*) unset "$name" ;; esac
done
for f in "$REPO_DIR"/worker/.dev.vars* "$REPO_DIR"/worker/.env*; do
  [[ -e "$f" ]] && die "refusing to run with $(basename "$f") in worker/: the e2e stack uses synthetic credentials only"
done

export VAULT_COMMIT
VAULT_COMMIT=$(git -C "$REPO_DIR" rev-parse HEAD)
# Everything baked into the vault image; uncommitted or untracked changes
# there mark the results as not reproducible from the commit alone.
[[ -z "$(git -C "$REPO_DIR" status --porcelain -- worker packages/protocol e2e/docker/vault e2e/docker/scanner)" ]] \
  || VAULT_COMMIT="$VAULT_COMMIT-dirty"
export_agentkit "$AGENTKIT_DIR" "$AGENTKIT_REF"

RUN_ID=$(TZ=$E2E_TZ date +%Y%m%d-%H%M%S)
RESULTS_DIR="$E2E_DIR/.results/$RUN_ID"
mkdir -p "$RESULTS_DIR/logs"
: > "$RESULTS_DIR/results.tsv"
: > "$RESULTS_DIR/latency.tsv"
PRIVATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/akvault-e2e.XXXXXX")
chmod 700 "$PRIVATE_DIR"
NEEDLES_FILE="$PRIVATE_DIR/needles"
(umask 077; : > "$NEEDLES_FILE")

teardown() {
  local code=$?
  set +e
  if [[ -n "$(compose ps -aq 2> /dev/null)" ]]; then
    stack_logs
    for d in device-a device-b; do compose cp "$d:/home/dev/e2e-logs" "$RESULTS_DIR/logs/$d" > /dev/null 2>&1; done
  fi
  if [[ "$KEEP" == true ]]; then
    log "--keep: the stack is still running; stop it with: docker compose -p $COMPOSE_PROJECT down -v"
  else
    stack_down
    if ! stack_is_gone; then
      log "teardown left containers, volumes or networks of project $COMPOSE_PROJECT behind"
      (( code == 0 )) && code=1
    fi
  fi
  rm -rf "$PRIVATE_DIR"
  exit "$code"
}
trap teardown EXIT
trap 'exit 130' INT TERM

{
  printf 'run_id\t%s\n' "$RUN_ID"
  printf 'ak_vault_commit\t%s\n' "$VAULT_COMMIT"
  printf 'agentkit_ref\t%s\n' "$AGENTKIT_REF"
  printf 'agentkit_sha\t%s\n' "$AGENTKIT_SHA"
  printf 'docker\t%s\n' "$(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')"
  printf 'sync_interval\t%s\n' "${E2E_SYNC_INTERVAL:-5s}"
} > "$RESULTS_DIR/meta.tsv"

log "run $RUN_ID: ak-vault $VAULT_COMMIT, agentkit $AGENTKIT_REF ($AGENTKIT_SHA)"
stack_down
stack_build
stack_up
start=$(now_ms)
setup_devices
record_result setup PASS $(( $(now_ms) - start )) "login, file vault, enable (genesis), add device by SAS"

# The soak runs on the healthy, enrolled pair: before the first scenario that
# touches the kill switch, sessions or membership, or last.
PLAN=()
soak_planned=false
for s in "${SCENARIOS[@]}"; do
  case "$s" in
    kill_switch|session_revocation|device_removal|recovery)
      if (( SOAK_SECONDS > 0 )) && [[ "$soak_planned" == false ]]; then PLAN+=(soak); soak_planned=true; fi ;;
  esac
  PLAN+=("$s")
done
if (( SOAK_SECONDS > 0 )) && [[ "$soak_planned" == false ]]; then PLAN+=(soak); fi

for s in "${PLAN[@]}"; do
  run_scenario "$s" "scenario_$s"
done
run_scenario disclosure scenario_disclosure

printf '\nak-vault %s | agentkit %s (%s) | %s\n\n' "$VAULT_COMMIT" "$AGENTKIT_REF" "$AGENTKIT_SHA" "$(TZ=$E2E_TZ date '+%F %T %Z')"
print_results | tee "$RESULTS_DIR/summary.txt"
printf '\nlatency (ms) A->B %s | B->A %s\n' "$(latency_stats "$RESULTS_DIR/latency.tsv" a_to_b)" "$(latency_stats "$RESULTS_DIR/latency.tsv" b_to_a)" | tee -a "$RESULTS_DIR/summary.txt"
printf 'results: %s\n' "$RESULTS_DIR"
if (( RESULT_FAILS > 0 )); then
  printf '%s of %s checks FAILED\n' "$RESULT_FAILS" "$RESULT_ROWS"
  exit 1
fi
printf 'all %s checks passed\n' "$RESULT_ROWS"
