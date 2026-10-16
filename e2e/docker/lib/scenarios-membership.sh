# shellcheck shell=bash
# Account and membership scenarios: session revocation through the ak-web
# webhook, the Worker's kill switch, device removal with rekey, and recovery
# with the recovery kit. They run after the data scenarios, in this order:
# removal leaves B fenced out and recovery brings it back as a new device.

# result_field SERVICE FILE KEY: a field of data in a JSON envelope on the device.
result_field() {
  dev_sh "$1" "python3 -c 'import json,sys; v=(json.load(open(sys.argv[1])).get(\"data\") or {}).get(sys.argv[2]); print(\"\" if v is None else v)' /run/e2e/$2 $3"
}

scenario_session_revocation() {
  local sid ref value t0 t1 mark
  sid=$(dev device-b session-sid)
  [[ -n "$sid" ]] || fail "B has no ak-web session ID"
  mark=$(dev device-b service log-mark)
  # The account page's "sign out this session", but webhook only: fake-akweb
  # keeps the session valid and keeps minting vault tokens for it, so B can
  # only be refused by the Worker honouring the signed revocation webhook.
  dev device-a revoke sid "$sid" webhook-only || fail "the revocation webhook was not delivered"
  wait_service_exit device-b 14 90
  dev device-b service log-has "$mark" '"server_code": ?"unauthorized"' \
    || fail "B stopped, but not on the Worker's unauthorized refusal"
  note "the Worker refused B's revoked session (401 unauthorized); B's service stopped with exit 14"
  ref=$(new_ref REVOKED); value=$(new_value revoked)
  set_value device-a "$ref" "$value" > /dev/null
  sleep 12
  want_absent device-b "$ref"
  t0=$(now_ms)
  dev device-b login "$OWNER_EMAIL" > /dev/null || fail "B could not sign in again"
  t1=$(wait_seen device-b "$ref" "$value" 120)
  note "after signing in again (new session) B caught up in $((t1 - t0)) ms"
}

scenario_kill_switch() {
  local ref value code t_on t1 exits_a exits_b
  trap 'vault_restart true > /dev/null 2>&1 || true' EXIT
  exits_a=$(service_exit_codes device-a)
  exits_b=$(service_exit_codes device-b)
  vault_restart false
  ref=$(new_ref KILL); value=$(new_value kill)
  set_value device-a "$ref" "$value" > /dev/null || fail "a local write failed while sync was off"
  code=$(sync_now device-a kill-a.json)
  [[ "$code" == 11 ]] || fail "A's cycle with the kill switch off exited $code, want 11"
  dev_sh device-a 'grep -q server_disabled /run/e2e/kill-a.json /run/e2e/kill-a.json.err' \
    || fail "A's refused cycle did not report server_disabled"
  note "kill switch off: local write kept, cycle exit 11 server_disabled"
  sleep 10
  want_absent device-b "$ref"
  vault_restart true
  t_on=$(now_ms)
  t1=$(wait_seen device-b "$ref" "$value" 300)
  record_latency kill_switch_resume $((t1 - t_on))
  [[ "$(service_exit_codes device-a)" == "$exits_a" && "$(service_exit_codes device-b)" == "$exits_b" ]] \
    || fail "a background service stopped instead of backing off while sync was off"
  note "kill switch on: B received the held write $((t1 - t_on)) ms later; services kept running"
}

scenario_device_removal() {
  local epoch rotate ref value from_b vfb members
  dev_sh device-a "ak-pty-driver.py run -- ak secrets devices remove ${B_ID:0:8} --reason retired \
    --password-file /run/e2e/vault-password --recovery-key-file /run/e2e/recovery-key --yes --json > /run/e2e/remove.json" \
    || fail "A could not remove B (devices remove)"
  epoch=$(result_field device-a remove.json key_epoch)
  rotate=$(result_field device-a remove.json needs_rotate_count)
  (( epoch >= 2 )) || fail "the key epoch did not advance (got ${epoch:-none})"
  (( rotate >= 1 )) || fail "the removal flagged no secret for rotation"
  members=$(dev device-a members)
  [[ "$members" == "$A_ID" ]] || fail "the removed device is still listed as a member"
  note "B removed: key epoch $epoch, $rotate secret(s) flagged for rotation"

  wait_service_exit device-b 14 90
  note "B's sync service stopped with exit 14 (device removed)"

  ref=$(new_ref AFTER_REMOVE); value=$(new_value after-remove)
  set_value device-a "$ref" "$value" > /dev/null
  sync_now device-a after-remove-a.json > /dev/null
  from_b=$(new_ref FROM_REMOVED); vfb=$(new_value from-removed)
  set_value device-b "$from_b" "$vfb" > /dev/null
  [[ "$(sync_now device-b removed-b.json)" == 14 ]] || fail "the removed device's cycle did not exit 14"
  sleep 12
  sync_now device-a after-remove-a2.json > /dev/null
  want_absent device-b "$ref"
  want_absent device-a "$from_b"
  note "no secret crossed in either direction after the removal"
  # Recovery checks that the post-removal write reaches the recovered device.
  printf '%s\t%s\n' "$ref" "$value" | dev device-b put-file after-remove.ref
}

scenario_recovery() {
  local ref value members old_key new_key t0 t1 codes old_b=$B_ID
  dev_sh device-b 'test -s /run/e2e/after-remove.ref' || fail "recovery needs the device removal scenario first"
  IFS=$'\t' read -r ref value < <(dev_sh device-b 'cat /run/e2e/after-remove.ref')

  # The person carries the recovery kit and vault password to the device.
  dev_sh device-a 'cat /run/e2e/recovery-kit' | dev device-b put-file recovery-kit
  dev_sh device-a 'cat /run/e2e/vault-password' | dev device-b put-file vault-password
  dev_sh device-b 'umask 077; printf "e2e-synthetic-vault-password-%s" "$(od -An -tx1 -N12 /dev/urandom | tr -d " \n")" > /run/e2e/new-vault-password'

  trap 'dev device-a service start; dev device-b service start' EXIT
  dev device-a service stop
  dev device-b service stop
  dev_sh device-b 'ak-pty-driver.py run -- ak secrets sync disable --purge --yes --json > /run/e2e/disable.json' \
    || fail "B could not purge its removed sync state"
  dev_sh device-b "ak-pty-driver.py run -- ak secrets sync recover --recovery-kit /run/e2e/recovery-kit --use password \
    --password-file /run/e2e/vault-password --new-password-file /run/e2e/new-vault-password \
    --recovery-kit-out /run/e2e/recovery-kit-2 --keep $A_ID --vault-origin \"\$E2E_VAULT_ORIGIN\" --yes --json > /run/e2e/recover.json" \
    || fail "sync recover on B failed"
  note "B recovered with the kit: $(result_field device-b recover.json items_restored) item(s) restored, key epoch $(result_field device-b recover.json key_epoch)"
  B_ID=$(dev device-b device-id)
  [[ -n "$B_ID" && "$B_ID" != "$old_b" ]] || fail "the recovered B is not a new device"
  want_value device-b "$ref" "$value"
  want_value device-b "$SEED_REF" "$SEED_VALUE"

  # Compared by hash on the device; each key must be present and non-empty.
  old_key=$(dev_sh device-b 'k=$(sed -n "s/^recovery key: //p" /run/e2e/recovery-kit); [ -n "$k" ] && printf %s "$k" | sha256sum | cut -c1-64') \
    || fail "the original recovery kit holds no recovery key"
  new_key=$(dev_sh device-b 'k=$(sed -n "s/^recovery key: //p" /run/e2e/recovery-kit-2); [ -n "$k" ] && printf %s "$k" | sha256sum | cut -c1-64') \
    || fail "recovery wrote no new recovery kit"
  [[ "$old_key" != "$new_key" ]] || fail "recovery did not rotate the recovery key"

  [[ "$(sync_now device-a recovery-a.json)" =~ ^(0|12)$ ]] || fail "A's first cycle after the recovery failed"
  codes=$(attention_of device-a recovery-a.json)
  [[ " $codes " == *" recovery_enrollment "* ]] || fail "A did not report the recovery enrollment (attention: ${codes:-none})"
  members=$(dev device-a members)
  [[ "$members" == "$(printf '%s\n' "$A_ID" "$B_ID" | sort | paste -sd' ' -)" ]] || fail "after recovery the members are not exactly A and recovered B"
  note "A reported recovery_enrollment; members are A and the recovered B; recovery key rotated"

  dev device-a service start
  dev device-b service start
  t0=$(measure_propagation device-a device-b post_recovery)
  t1=$(measure_propagation device-b device-a post_recovery)
  note "after recovery A->B ${t0} ms, B->A ${t1} ms"
}
