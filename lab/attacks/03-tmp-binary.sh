#!/usr/bin/env bash
# LAB ONLY. Simulates a hidden binary run from /tmp: copies /bin/sleep to /tmp/.x and runs
# it detached as a long-lived process. The PID is kept in /tmp/.x.pid so re-runs do not
# start duplicates.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "03 Binary run from /tmp" \
  "Copies /bin/sleep to hidden /tmp/.x and runs it in the background (sleep 3600)" \
  "T1036.005 Defense Evasion: Masquerading: Match Legitimate Name or Location; T1564.001 Defense Evasion: Hide Artifacts: Hidden Files and Directories"

require_up target1

run_in target1 sh -c '
  pidf=/tmp/.x.pid
  if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
    echo "already running as pid $(cat "$pidf")"
  else
    cp -f /bin/sleep /tmp/.x && chmod 755 /tmp/.x
    nohup /tmp/.x 3600 >/dev/null 2>&1 </dev/null &
    echo $! > "$pidf"
    echo "started /tmp/.x as pid $(cat "$pidf")"
  fi
'

echo "Done. Expect a process-from-/tmp anomaly. A kill_process approval should target this PID."
