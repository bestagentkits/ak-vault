# shellcheck shell=bash
# Data scenarios: propagation latency, concurrent writes and conflicts,
# delete tombstones, and an offline device catching up. Each runs under
# run_scenario (errexit subshell); a failed check ends that scenario only.

GATE_MS=60000          # release gate: set on A visible on B in under 60 s
PROPAGATION_SAMPLES=${PROPAGATION_SAMPLES:-5}

# A set on one device, observed on the other: records a latency sample.
# measure_propagation FROM TO KIND
measure_propagation() {
  local ref value t0 t1
  ref=$(new_ref PROP) && value=$(new_value prop) || return 1
  t0=$(set_value "$1" "$ref" "$value") || return 1
  t1=$(wait_seen "$2" "$ref" "$value" $((GATE_MS / 1000 + 30))) || return 1
  record_latency "$3" $((t1 - t0))
  printf '%s' $((t1 - t0))
}

scenario_propagation() {
  local i ms worst=0
  for i in $(seq 1 "$PROPAGATION_SAMPLES"); do
    ms=$(measure_propagation device-a device-b a_to_b)
    (( ms > worst )) && worst=$ms
  done
  ms=$(measure_propagation device-b device-a b_to_a)
  note "A->B $(latency_stats "$RESULTS_DIR/latency.tsv" a_to_b) ms; B->A ${ms} ms"
  (( worst < GATE_MS )) || fail "A->B worst ${worst} ms is not under the ${GATE_MS} ms gate"
}

scenario_concurrent_writes() {
  # 1. Simultaneous writes to different refs: both land on both devices.
  local ra rb va vb pa pb
  ra=$(new_ref CONC); va=$(new_value conc-a)
  rb=$(new_ref CONC); vb=$(new_value conc-b)
  set_value device-a "$ra" "$va" > /dev/null & pa=$!
  set_value device-b "$rb" "$vb" > /dev/null & pb=$!
  wait "$pa" && wait "$pb" || fail "a concurrent write failed"
  wait_seen device-b "$ra" "$va" 90 > /dev/null
  wait_seen device-a "$rb" "$vb" 90 > /dev/null
  note "parallel writes to distinct refs merged"

  # 2. The same ref edited on both devices before either syncs: a preserved
  #    conflict, never last-writer-wins; settle on B propagates B's value.
  local ref base ea eb code codes
  ref=$(new_ref CONFLICT); base=$(new_value base)
  ea=$(new_value edit-a); eb=$(new_value edit-b)
  set_value device-a "$ref" "$base" > /dev/null
  wait_seen device-b "$ref" "$base" 90 > /dev/null
  trap 'dev device-a service start; dev device-b service start' EXIT
  dev device-a service stop; dev device-b service stop
  set_value device-a "$ref" "$ea" > /dev/null
  set_value device-b "$ref" "$eb" > /dev/null
  code=$(sync_now device-a conflict-a.json)
  [[ "$code" == 0 ]] || fail "A's push of its edit exited $code"
  code=$(sync_now device-b conflict-b.json)
  codes=$(attention_of device-b conflict-b.json)
  [[ " $codes " == *" conflict "* ]] || fail "B reported no conflict (exit $code, attention: ${codes:-none})"
  [[ "$code" == 12 ]] || fail "B's conflicted cycle exited $code, want 12 (attention)"
  want_value device-b "$ref" "$eb"
  sync_now device-a conflict-a2.json > /dev/null
  want_value device-a "$ref" "$ea"
  [[ "$(dev device-a conflicts-open)" == 1 && "$(dev device-b conflicts-open)" == 1 ]] || fail "each device should list one open conflict"
  note "concurrent edit kept on both sides as a conflict (B exit 12)"

  dev device-b ak secrets sync settle "$ref" --keep local --json > /dev/null || fail "settle on B failed"
  sync_now device-a settle-a.json > /dev/null
  sync_now device-b settle-b.json > /dev/null
  sync_now device-a settle-a2.json > /dev/null
  want_value device-a "$ref" "$eb"
  want_value device-b "$ref" "$eb"
  [[ "$(dev device-a conflicts-open)" == 0 && "$(dev device-b conflicts-open)" == 0 ]] || fail "a conflict stayed open after settle"
  note "settle --keep local on B converged both devices"
}

scenario_tombstone() {
  # 1. A delete propagates.
  local ref value t0 t1
  ref=$(new_ref DEL); value=$(new_value del)
  set_value device-a "$ref" "$value" > /dev/null
  wait_seen device-b "$ref" "$value" 90 > /dev/null
  t0=$(delete_ref device-a "$ref")
  t1=$(wait_gone device-b "$ref" 90)
  record_latency delete_a_to_b $((t1 - t0))
  note "delete reached B in $((t1 - t0)) ms"

  # 2. A stale edit made before the delete was seen is discarded, not
  #    resurrected.
  local ref2 v2 stale code codes
  ref2=$(new_ref DEL); v2=$(new_value del); stale=$(new_value stale)
  set_value device-a "$ref2" "$v2" > /dev/null
  wait_seen device-b "$ref2" "$v2" 90 > /dev/null
  trap 'dev device-b service start' EXIT
  dev device-b service stop
  delete_ref device-a "$ref2" > /dev/null
  code=$(sync_now device-a tomb-a.json)
  [[ "$code" == 0 ]] || fail "A's push of the delete exited $code"
  set_value device-b "$ref2" "$stale" > /dev/null
  code=$(sync_now device-b tomb-b.json)
  codes=$(attention_of device-b tomb-b.json)
  [[ " $codes " == *" discarded_deleted_remotely "* ]] || fail "B's stale edit was not reported as discarded (exit $code, attention: ${codes:-none})"
  want_absent device-b "$ref2"
  sync_now device-a tomb-a2.json > /dev/null
  want_absent device-a "$ref2"
  note "stale edit after delete discarded on B (exit $code); not resurrected on A"
}

scenario_offline_catch_up() {
  local gone gv refs=() vals=() i r v b_ref b_val code t_on t last=0 offline_s=${OFFLINE_SECONDS:-20}
  gone=$(new_ref OFF); gv=$(new_value off)
  set_value device-a "$gone" "$gv" > /dev/null
  wait_seen device-b "$gone" "$gv" 90 > /dev/null

  trap 'device_ensure_online device-b' EXIT
  device_offline device-b
  note "B disconnected from the stack network"
  for i in 1 2 3; do
    r=$(new_ref OFF); v=$(new_value off)
    refs+=("$r"); vals+=("$v")
    set_value device-a "$r" "$v" > /dev/null
  done
  delete_ref device-a "$gone" > /dev/null
  b_ref=$(new_ref OFF); b_val=$(new_value off-b)
  set_value device-b "$b_ref" "$b_val" > /dev/null
  code=$(sync_now device-b offline-b.json)
  [[ "$code" == 11 ]] || fail "B's offline cycle exited $code, want 11 (unavailable)"
  sleep "$offline_s"
  for r in "${refs[@]}"; do want_absent device-b "$r"; done

  device_online device-b
  t_on=$(now_ms)
  for i in 0 1 2; do
    t=$(wait_seen device-b "${refs[$i]}" "${vals[$i]}" 300)
    (( t > last )) && last=$t
  done
  t=$(wait_gone device-b "$gone" 300); (( t > last )) && last=$t
  t=$(wait_seen device-a "$b_ref" "$b_val" 300); (( t > last )) && last=$t
  record_latency offline_catch_up $((last - t_on))
  note "offline ${offline_s}s (B exit 11); caught up 3 sets, 1 delete and B's offline write $((last - t_on)) ms after reconnect"
}
