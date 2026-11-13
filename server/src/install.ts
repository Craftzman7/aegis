/** Installer served at GET /install.sh. `__SERVER__` is replaced with the request origin (overridable with --server). */
export const INSTALL_SH = `#!/bin/sh
# Aegis agent installer. Usage: curl -fsSL __SERVER__/install.sh | sudo sh -s -- --token TOKEN [--server URL]
set -eu

SERVER="__SERVER__"
TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TOKEN" ] || { echo "error: --token is required" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 1; }
SERVER="\${SERVER%/}"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BIN=/usr/local/bin/aegis-agent
echo "==> downloading aegis-agent ($ARCH)"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$SERVER/releases/agent/latest/aegis-agent-linux-$ARCH" -o "$BIN.new"
else
  wget -qO "$BIN.new" "$SERVER/releases/agent/latest/aegis-agent-linux-$ARCH"
fi
chmod 0755 "$BIN.new"
mv "$BIN.new" "$BIN"

mkdir -p /etc/aegis /var/lib/aegis
chmod 0700 /var/lib/aegis
cat > /etc/aegis/agent.yaml <<EOF_CFG
server_url: $SERVER
data_dir: /var/lib/aegis
EOF_CFG
chmod 0644 /etc/aegis/agent.yaml

cat > /etc/systemd/system/aegis-agent.service <<'EOF_UNIT'
[Unit]
Description=Aegis security agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-agent run --config /etc/aegis/agent.yaml
Restart=always
RestartSec=5
User=root
NoNewPrivileges=false
StateDirectory=aegis

[Install]
WantedBy=multi-user.target
EOF_UNIT

echo "==> enrolling"
"$BIN" enroll --server "$SERVER" --token "$TOKEN"

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --now aegis-agent
  echo "==> aegis-agent installed and running"
else
  echo "==> enrolled; systemd not running here, so start the agent yourself:"
  echo "    nohup $BIN run --config /etc/aegis/agent.yaml >/var/log/aegis-agent.log 2>&1 &"
fi
`;
