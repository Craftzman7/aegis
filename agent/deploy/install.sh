#!/bin/sh
# Install and enroll the Aegis agent.
#   sudo ./install.sh --server https://aegis.example.workers.dev --token TOKEN [--binary ./aegis-agent-linux-amd64]
set -eu

SERVER=""; TOKEN=""; BINARY=""; DATA_DIR=/var/lib/aegis

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token)  TOKEN="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$SERVER" ] && [ -n "$TOKEN" ] || { echo "usage: $0 --server URL --token TOKEN [--binary PATH]" >&2; exit 2; }

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
[ -n "$BINARY" ] || BINARY="$HERE/../dist/aegis-agent-linux-$ARCH"
[ -f "$BINARY" ] || { echo "binary not found: $BINARY (build with 'make build-linux')" >&2; exit 1; }

install -m 0755 "$BINARY" /usr/local/bin/aegis-agent
install -d -m 0755 /etc/aegis
install -d -m 0700 "$DATA_DIR"
cat > /etc/aegis/agent.yaml <<CFG
server_url: $SERVER
data_dir: $DATA_DIR
log_level: info
CFG
chmod 0600 /etc/aegis/agent.yaml

/usr/local/bin/aegis-agent enroll --config /etc/aegis/agent.yaml --token "$TOKEN"

if [ -d /run/systemd/system ]; then
  install -m 0644 "$HERE/aegis-agent.service" /etc/systemd/system/aegis-agent.service
  systemctl daemon-reload
  systemctl enable --now aegis-agent.service
  echo "aegis-agent is running: journalctl -u aegis-agent -f"
else
  echo "systemd not detected; start manually: aegis-agent run --config /etc/aegis/agent.yaml"
fi
