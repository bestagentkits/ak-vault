# shellcheck shell=bash
# The compose stack: agentkit source export, build, start, stop, kill-switch
# restart and network moves. Every container, volume and network lives in
# the compose project "akvault-e2e", and teardown removes all of it.

COMPOSE_PROJECT=akvault-e2e
E2E_NETWORK="${COMPOSE_PROJECT}_e2e"

compose() { docker compose -f "$E2E_DIR/compose.yaml" -p "$COMPOSE_PROJECT" "$@"; }

# container_of SERVICE: the container ID of a running service.
container_of() { compose ps -q "$1"; }

# export_agentkit DIR REF: archive apps/cli at REF into .cache and export
# AGENTKIT_SRC_DIR and AGENTKIT_SHA for the device build. Read-only on the
# agentkit checkout: `git archive` of a resolved commit, nothing else.
export_agentkit() {
  local dir=$1 ref=$2 sha dest
  [[ -d "$dir/.git" || -f "$dir/.git" ]] || die "not an agentkit checkout: $dir (set --agentkit-dir)"
  sha=$(git -C "$dir" rev-parse --verify "${ref}^{commit}" 2>/dev/null) || die "agentkit ref not found: $ref (fetch it first)"
  dest="$E2E_DIR/.cache/agentkit-$sha"
  # One export is kept: earlier ones are removed (they are re-created on demand).
  find "$E2E_DIR/.cache" -mindepth 1 -maxdepth 1 -name 'agentkit-*' ! -name "agentkit-$sha" -exec rm -rf {} + 2> /dev/null || true
  if [[ ! -f "$dest/.complete" ]]; then
    rm -rf "$dest"
    mkdir -p "$dest"
    git -C "$dir" archive "$sha" apps/cli | tar -x -C "$dest" || die "git archive of agentkit $sha failed"
    : > "$dest/.complete"
  fi
  export AGENTKIT_SRC_DIR="$dest" AGENTKIT_SHA="$sha"
}

stack_build() {
  log "building images (agentkit $AGENTKIT_SHA, ak-vault $VAULT_COMMIT)"
  compose build >> "$RESULTS_DIR/build.log" 2>&1 || { tail -40 "$RESULTS_DIR/build.log" >&2; die "image build failed (see build.log)"; }
  local label
  label=$(docker image inspect akvault-e2e-vault:local --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
  [[ "$label" == "$VAULT_COMMIT" ]] || die "the vault image is from $label, not $VAULT_COMMIT"
}

stack_up() {
  log "starting the stack"
  E2E_SYNC_ENABLED=true compose up -d --wait --wait-timeout 180 >> "$RESULTS_DIR/stack.log" 2>&1 \
    || { compose ps >&2; die "the stack did not become healthy"; }
}

# stack_logs: keep every service's log with the results.
stack_logs() {
  local svc
  for svc in vault fake-akweb device-a device-b; do
    compose logs --no-color --timestamps "$svc" > "$RESULTS_DIR/logs/$svc.log" 2>&1 || true
  done
}

SCAN_CONTAINER="${COMPOSE_PROJECT}-scan"

stack_down() {
  docker rm -f "$SCAN_CONTAINER" > /dev/null 2>&1 || true
  compose down -v --remove-orphans --timeout 10 >> "$RESULTS_DIR/stack.log" 2>&1 || true
}

# stack_is_gone: no container, volume or network of the project is left.
stack_is_gone() {
  local filter="label=com.docker.compose.project=$COMPOSE_PROJECT"
  [[ -z "$(docker ps -aq --filter "$filter")$(docker volume ls -q --filter "$filter")$(docker network ls -q --filter "$filter")" ]]
}

# vault_restart true|false: recreate the vault with the kill switch set,
# keeping its Durable Object state volume.
vault_restart() {
  log "  restarting the vault with VAULT_SYNC_ENABLED=$1"
  E2E_SYNC_ENABLED=$1 compose up -d --no-deps --force-recreate --wait --wait-timeout 120 vault >> "$RESULTS_DIR/stack.log" 2>&1
}

# vault_stop / vault_start: stop the Worker so its SQLite files are closed
# for the disclosure scan.
vault_stop() { compose stop --timeout 20 vault >> "$RESULTS_DIR/stack.log" 2>&1; }

device_offline() { docker network disconnect "$E2E_NETWORK" "$(container_of "$1")"; }
device_online() { docker network connect --alias "$1" "$E2E_NETWORK" "$(container_of "$1")"; }

# device_ensure_online SERVICE: reconnect only when disconnected (cleanup path).
device_ensure_online() {
  local nets
  nets=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(container_of "$1")")
  [[ " $nets " == *" $E2E_NETWORK "* ]] || device_online "$1"
}

# scan_vault_state: run the disclosure scanner over the vault's state and
# log volumes in a one-off container of the vault image (no network). The
# needles arrive on stdin and are never written into the container.
scan_vault_state() {
  docker run --rm -i --name "$SCAN_CONTAINER" --label "com.docker.compose.project=$COMPOSE_PROJECT" \
    --network none --user node \
    -v "${COMPOSE_PROJECT}_vault-state:/state:ro" -v "${COMPOSE_PROJECT}_vault-logs:/logs:ro" \
    --entrypoint node akvault-e2e-vault:local --no-warnings /app/e2e/disclosure-scan.mjs /state /logs
}
