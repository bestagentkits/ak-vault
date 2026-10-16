# shellcheck shell=bash
# --soak DURATION: alternate writes A->B and B->A for DURATION, each new
# value timed until the other device holds it, then deleted again so the
# stores stay small (deletes exercise tombstones). Reports the error rate
# and p50/p95/max propagation latency; a sample over the 60 s gate counts as
# a gate breach, a failure or a timeout as an error.

SOAK_PAUSE_S=${SOAK_PAUSE_S:-3}

# duration_s 90s|30m|2h|45: seconds.
duration_s() {
  [[ "$1" =~ ^([0-9]+)([smh]?)$ ]] || die "bad duration: $1 (use e.g. 600s, 30m, 2h)"
  case "${BASH_REMATCH[2]}" in
    h) echo $((BASH_REMATCH[1] * 3600)) ;;
    m) echo $((BASH_REMATCH[1] * 60)) ;;
    *) echo "${BASH_REMATCH[1]}" ;;
  esac
}

scenario_soak() {
  local end n=0 errors=0 breaches=0 from to kind ms
  end=$(( $(date +%s) + SOAK_SECONDS ))
  while (( $(date +%s) < end )); do
    n=$((n + 1))
    if (( n % 2 )); then from=device-a to=device-b kind=soak_a_to_b; else from=device-b to=device-a kind=soak_b_to_a; fi
    if ms=$(soak_once "$from" "$to" "$kind"); then
      (( ms >= GATE_MS )) && breaches=$((breaches + 1))
    else
      errors=$((errors + 1))
      log "  soak iteration $n failed"
    fi
    printf '%s\t%s\t%s\t%s\n' "$n" "$kind" "${ms:-}" "$(TZ=$E2E_TZ date +%FT%T%z)" >> "$RESULTS_DIR/soak.tsv"
    sleep "$SOAK_PAUSE_S"
  done
  note "soak ${SOAK_SECONDS}s: $n iterations, $errors error(s) ($(python3 -c "print(f'{100*$errors/max($n,1):.2f}')")%), $breaches over the gate"
  note "A->B $(latency_stats "$RESULTS_DIR/latency.tsv" soak_a_to_b) ms"
  note "B->A $(latency_stats "$RESULTS_DIR/latency.tsv" soak_b_to_a) ms"
  (( n > 0 && errors == 0 && breaches == 0 )) || fail "the soak saw errors or gate breaches"
}

# soak_once FROM TO KIND: one timed write, then its delete; prints the ms.
# Explicit checks, not errexit: this runs as an `if` condition.
soak_once() {
  local ref value t0 t1
  ref=$(new_ref SOAK) && value=$(new_value soak) || return 1
  t0=$(set_value "$1" "$ref" "$value") || return 1
  t1=$(wait_seen "$2" "$ref" "$value" $((GATE_MS / 1000 + 30))) || return 1
  record_latency "$3" $((t1 - t0))
  delete_ref "$1" "$ref" > /dev/null || return 1
  wait_gone "$2" "$ref" 90 > /dev/null || return 1
  printf '%s' $((t1 - t0))
}
