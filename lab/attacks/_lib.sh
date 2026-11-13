#!/usr/bin/env bash
# LAB ONLY. Shared helpers for the attack simulation scripts. Sourced, not run.
# Everything here is executed by the host and dispatched into containers with
# `docker compose exec`.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$LAB_DIR/docker-compose.yml"

# Credentials baked into the lab targets (Dockerfile.target). Lab only.
LAB_USER=alice
LAB_PASS=alice

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=5
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
)

dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

# run_in <service> <command...>: run in the container, wait for it to finish.
run_in() {
  local svc="$1"; shift
  dc exec -T "$svc" "$@"
}

# bg_in <service> <command...>: run detached in the container and return at once.
bg_in() {
  local svc="$1"; shift
  dc exec -d "$svc" "$@"
}

is_running() {
  case " $(dc ps --status running --services 2>/dev/null | tr '\n' ' ') " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

require_up() {
  local svc
  for svc in "$@"; do
    if ! is_running "$svc"; then
      echo "ERROR: service '$svc' is not running." >&2
      echo "Start the lab first: docker compose -f $COMPOSE_FILE up -d --build" >&2
      exit 1
    fi
  done
}

banner() {
  local title="$1" simulates="$2" attck="$3"
  echo "============================================================"
  echo "$title"
  echo "Simulates: $simulates"
  echo "ATT&CK:    $attck"
  echo "============================================================"
}
