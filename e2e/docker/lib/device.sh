# shellcheck shell=bash
# Device operations, each a real `ak` command inside device-a or device-b
# (through device/bin/e2e-device.sh), and the two-device setup.

# dev SERVICE ARGS...: e2e-device.sh in a device container.
dev() { local svc=$1; shift; compose exec -T "$svc" e2e-device.sh "$@"; }

# dev_sh SERVICE SCRIPT: a shell snippet in a device container.
dev_sh() { compose exec -T "$1" bash -c "$2"; }

# set_value SERVICE REF VALUE: prints the ms timestamp after the write.
set_value() { printf '%s' "$3" | dev "$1" set "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ts_ms"])'; }

delete_ref() { dev "$1" delete "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ts_ms"])'; }

# want_value SERVICE REF VALUE: the local store holds exactly VALUE.
want_value() {
  local got
  got=$(dev "$1" value-hash "$2" 2>/dev/null) || { fail "$1 lacks a ref it should hold"; return 1; }
  [[ "$got" == "sha256:$(sha256_of "$3")" ]] || { fail "$1 holds a different value than expected"; return 1; }
}

# want_absent SERVICE REF: the local store was listed and REF is not in it.
# A listing error fails the check; it never reads as "absent".
want_absent() {
  local rc=0
  dev "$1" has "$2" || rc=$?
  case "$rc" in
    1) return 0 ;;
    0) fail "$1 holds a ref that should be absent" ;;
    *) fail "$1 could not list its store (exit $rc)" ;;
  esac
}

# wait_seen SERVICE REF VALUE TIMEOUT_S: prints the ms timestamp at which
# SERVICE first held VALUE under REF; fails after TIMEOUT_S.
wait_seen() {
  local out
  out=$(dev "$1" wait-present "$2" "$4" "$(sha256_of "$3")") || { fail "$1 did not receive a value within $4 s"; return 1; }
  json_get "$out" ts_ms
}

wait_gone() {
  local out rc=0
  out=$(dev "$1" wait-absent "$2" "$3") || rc=$?
  case "$rc" in
    0) json_get "$out" ts_ms ;;
    1) fail "$1 still held a deleted ref after $3 s" ;;
    *) fail "$1 could not list its store while waiting for a delete (exit $rc)" ;;
  esac
}

# sync_now SERVICE OUTFILE: one sync cycle; the JSON result goes to OUTFILE
# inside the container (/run/e2e) and the CLI exit code is printed.
sync_now() {
  local code=0
  dev_sh "$1" "e2e-device.sh sync-now > /run/e2e/$2 2>/run/e2e/$2.err" || code=$?
  printf '%s' "$code"
}

attention_of() { dev "$1" attention-codes "/run/e2e/$2"; }

# service_exit_codes SERVICE: exit codes of the background service so far.
service_exit_codes() { dev "$1" service exits; }

# wait_service_exit SERVICE CODE TIMEOUT_S: the background service stopped
# with CODE after this call started (exits recorded before it are ignored).
wait_service_exit() {
  local before after=() deadline i codes
  codes=$(service_exit_codes "$1") || { fail "cannot read $1's service exits"; return 1; }
  read -r -a after <<< "$codes"
  before=${#after[@]}
  deadline=$(( $(date +%s) + $3 ))
  while (( $(date +%s) < deadline )); do
    codes=$(service_exit_codes "$1") || { fail "cannot read $1's service exits"; return 1; }
    read -r -a after <<< "$codes"
    for (( i = before; i < ${#after[@]}; i++ )); do
      [[ "${after[$i]}" == "$2" ]] && return 0
    done
    sleep 1
  done
  fail "$1's sync service did not stop with exit $2 within $3 s (new exits: ${after[*]:$before})"
}

# ---- setup ----

# setup_devices: both devices log in to fake-akweb as the same synthetic
# account, open a file-backend vault, A enables sync (genesis) and B joins
# with the SAS flow, approved on A. Leaves both background services running.
setup_devices() {
  local join offer sas
  OWNER_EMAIL="e2e-owner-$(rand_hex 4)@example.invalid"
  for d in device-a device-b; do
    dev "$d" login "$OWNER_EMAIL" > /dev/null || die "$d: ak login failed"
    dev "$d" init-vault || die "$d: could not open the file-backend vault"
  done

  SEED_REF=$(new_ref SEED)
  SEED_VALUE=$(new_value seed)
  set_value device-a "$SEED_REF" "$SEED_VALUE" > /dev/null || die "device-a: secrets set failed"

  # Genesis on A. The vault password is synthetic and stays on A's tmpfs; the
  # runner reads it only to hand it to the disclosure scan.
  dev_sh device-a 'umask 077; printf "e2e-synthetic-vault-password-%s" "$(od -An -tx1 -N12 /dev/urandom | tr -d " \n")" > /run/e2e/vault-password
    ak-pty-driver.py run -- ak secrets sync enable --password-file /run/e2e/vault-password \
      --recovery-kit-out /run/e2e/recovery-kit --vault-origin "$E2E_VAULT_ORIGIN" --json > /run/e2e/enable.json
    sed -n "s/^recovery key: //p" /run/e2e/recovery-kit > /run/e2e/recovery-key
    test -s /run/e2e/recovery-key' || die "device-a: sync enable failed"

  # B asks to join; A approves after comparing the 6-digit code B will show.
  dev_sh device-b 'ak-pty-driver.py run -- ak secrets devices add --label device-b --vault-origin "$E2E_VAULT_ORIGIN" --json > /run/e2e/add-request.json' \
    || die "device-b: devices add (request) failed"
  join=$(dev_sh device-b 'python3 -c "import json; print(json.load(open(\"/run/e2e/add-request.json\"))[\"data\"][\"join_code\"])"')
  dev_sh device-a 'rm -rf /run/e2e/approve && mkdir -p /run/e2e/approve'
  compose exec -T device-a ak-pty-driver.py approve "$join" /run/e2e/approve > "$RESULTS_DIR/logs/approve.log" 2>&1 &
  local approve_pid=$!
  for _ in $(seq 1 240); do
    dev_sh device-a 'test -s /run/e2e/approve/sas' && break
    sleep 0.5
  done
  offer=$(dev_sh device-a 'cat /run/e2e/approve/offer') || die "device-a: approve never showed an offer"
  sas=$(dev_sh device-a 'cat /run/e2e/approve/sas')
  [[ "$sas" =~ ^[0-9]{6}$ ]] || die "device-a: approve showed no 6-digit code"

  # B runs the offer with the code it was shown by A's person, which the CLI
  # checks against the one it derives; A then confirms the same code.
  compose exec -T device-b ak-pty-driver.py run -- ak secrets devices add --offer "$offer" --confirm-sas "$sas" \
    --vault-origin http://127.0.0.1:8787 --json > "$RESULTS_DIR/logs/add-offer.json" 2>> "$RESULTS_DIR/logs/add-offer.err" &
  local add_pid=$!
  dev_sh device-a 'echo y > /run/e2e/approve/answer'
  wait "$approve_pid" || die "device-a: devices approve failed (see logs/approve.log)"
  wait "$add_pid" || die "device-b: devices add --offer failed (see logs/add-offer.err)"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; sys.exit(0 if d.get("status")=="joined" else 1)' \
    "$RESULTS_DIR/logs/add-offer.json" || die "device-b did not join"

  A_ID=$(dev device-a device-id)
  B_ID=$(dev device-b device-id)
  [[ -n "$A_ID" && -n "$B_ID" && "$A_ID" != "$B_ID" ]] || die "the devices do not hold distinct device IDs"
  wait_seen device-b "$SEED_REF" "$SEED_VALUE" 90 > /dev/null || die "device-b never received the seeded secret"
  log "setup: two devices enrolled in one vault"
}
