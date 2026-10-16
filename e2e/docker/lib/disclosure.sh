# shellcheck shell=bash
# Disclosure check: after the scenarios, stop the Worker and search its
# persisted Durable Object state and its logs for every synthetic secret
# name and value this run created, and for the run's credentials: each
# device's file-backend passphrase and file-vault recovery key, the vault
# passwords, the sync recovery keys, the revocation webhook secret, and
# ak-web token markers. None may appear, in any encoding the scanner covers
# (scanner/disclosure-scan.mjs).
#
# The needles are collected into a 0600 file in the run's private temp dir
# (removed at teardown) and reach the scanner on stdin; they are never
# printed, and the scanner reports only counts and needle indexes. Every
# source must contribute, so a failed read can never shrink the search.

# Markers of ak-web credentials: session and refresh token prefixes minted
# by fake-akweb, and the base64url header of its ES256 access tokens.
TOKEN_MARKERS=(e2e-session- e2e-refresh- eyJhbGciOiJFUzI1NiIs)

# add_needles LABEL SERVICE SCRIPT: append the non-empty, non-comment lines
# of at least 16 characters SCRIPT prints in SERVICE; fail when it prints none.
add_needles() {
  local lines
  lines=$(compose exec -T "$2" sh -c "$3" | awk 'length($0) >= 16 && $0 !~ /^#/') || { fail "could not read the $1 for the scan"; return 1; }
  [[ -n "$lines" ]] || { fail "no $1 to scan for"; return 1; }
  printf '%s\n' "$lines" >> "$SCAN_NEEDLES"
}

collect_needles() {
  SCAN_NEEDLES="$PRIVATE_DIR/scan-needles"
  (umask 077; cat "$NEEDLES_FILE" > "$SCAN_NEEDLES") || return 1
  [[ $(wc -l < "$SCAN_NEEDLES") -ge 2 ]] || { fail "no synthetic refs or values were recorded"; return 1; }
  printf '%s\n' "${TOKEN_MARKERS[@]}" >> "$SCAN_NEEDLES"
  local d
  for d in device-a device-b; do
    add_needles "$d file-backend passphrase" "$d" 'cat /run/e2e/passphrase' || return 1
    # Only the age identity line, not the file's descriptive header.
    add_needles "$d file-vault recovery key" "$d" 'grep "^AGE-SECRET-KEY-" /run/e2e/file-vault-recovery.key' || return 1
  done
  add_needles "vault password" device-a 'cat /run/e2e/vault-password' || return 1
  add_needles "sync recovery key" device-a 'sed -n "s/^recovery key: //p" /run/e2e/recovery-kit' || return 1
  # Present only after the recovery scenario ran.
  if compose exec -T device-b test -s /run/e2e/recovery-kit-2; then
    add_needles "new vault password" device-b 'cat /run/e2e/new-vault-password' || return 1
    add_needles "rotated recovery key" device-b 'sed -n "s/^recovery key: //p" /run/e2e/recovery-kit-2' || return 1
  fi
  add_needles "revocation webhook secret" vault 'cat /shared/webhook-secret' || return 1
}

scenario_disclosure() {
  local report summary expected
  collect_needles
  expected=$(sort -u "$SCAN_NEEDLES" | grep -c .)
  vault_stop || fail "could not stop the vault for the scan"
  report=$(scan_vault_state < "$SCAN_NEEDLES") || true
  printf '%s\n' "$report" > "$RESULTS_DIR/disclosure.json"
  summary=$(python3 - "$report" "$expected" <<'PY'
import json, sys
try:
    r = json.loads(sys.argv[1])
except ValueError:
    print("the scanner produced no report"); sys.exit(1)
if r.get("error"):
    print("scan error: " + r["error"]); sys.exit(1)
if r["needles"] != int(sys.argv[2]):
    print(f"the scanner read {r['needles']} needles, expected {sys.argv[2]}"); sys.exit(1)
hits = len(r["hits"])
print(f"{r['needles']} needles in {r['encodings']} encodings over {r['files']} files "
      f"({r['bytes']} bytes) and {r['sqlite_tables']} tables in {r['sqlite_databases']} SQLite db: {hits} hit(s)")
sys.exit(0 if r.get("ok") and hits == 0 else 1)
PY
  ) || fail "${summary:-the scan failed} (see disclosure.json)"
  note "$summary"
}
