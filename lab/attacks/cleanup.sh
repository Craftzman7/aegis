#!/usr/bin/env bash
# LAB ONLY. Reverts the attack simulations on target1 and target2, and stops the helper
# processes on the attacker. It does NOT touch agent state, the agent key, or the
# audit log. For a full reset use: docker compose -f lab/docker-compose.yml down -v
# Idempotent: safe to run when nothing is left to clean.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "cleanup" \
  "Reverts 01-08 artifacts on target1/target2 and stops attacker helpers" \
  "n/a"

for t in target1 target2; do
  if ! is_running "$t"; then
    echo "[$t] not running, skipping"
    continue
  fi
  echo "[$t] reverting"
  run_in "$t" sh -c '
    # 03: hidden binary and its PID file
    if [ -f /tmp/.x.pid ]; then kill "$(cat /tmp/.x.pid)" 2>/dev/null || true; fi
    rm -f /tmp/.x.pid /tmp/.x
    # 04: reverse shells (timeout wrapper and the bash -i child)
    pkill -f "[t]imeout [0-9]+ bash -i" 2>/dev/null || true
    pkill -f "^bash -i$" 2>/dev/null || true
    pkill -f "[d]ev/tcp/attacker/4444" 2>/dev/null || true
    # 02: backdoor account
    userdel backdoor 2>/dev/null || true
    # 05: cron persistence
    rm -f /etc/cron.d/aegis-lab-persist
    if crontab -l 2>/dev/null | grep -q aegis-lab; then
      crontab -l | grep -v aegis-lab | crontab - || true
    fi
    # 06: authorized_keys entry and the generated key
    if [ -f /root/.ssh/authorized_keys ]; then
      grep -v aegis-lab /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.tmp || true
      mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
    fi
    rm -f /tmp/aegis-lab-key /tmp/aegis-lab-key.pub
    echo "target cleanup done"
  ' || true
done

if is_running attacker; then
  echo "[attacker] stopping helpers"
  run_in attacker sh -c "
    pkill -f '[h]ttp.server 8000' 2>/dev/null || true
    pkill -f '[n]c -l -p 4444' 2>/dev/null || true
    rm -rf /srv/aegis-payload /tmp/aegis-revshell.txt /tmp/aegis-http.log
  " || true
else
  echo "[attacker] not running, skipping"
fi

echo "Cleanup finished. Agent-side rollbacks (block_ip, kill_process, etc.) are separate: use the dashboard rollback action."
