#!/usr/bin/env bash
# LAB ONLY. Runs attacks 01 to 08 in order, pausing between them so each one can be
# seen in the dashboard before the next begins. It does NOT run cleanup.sh.
#   PAUSE=<seconds>  gap after each attack (default 60)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAUSE="${PAUSE:-60}"

scripts=(
  01-ssh-bruteforce.sh
  02-new-uid0-user.sh
  03-tmp-binary.sh
  04-reverse-shell.sh
  05-cron-persistence.sh
  06-authorized-keys.sh
  07-curl-pipe-sh.sh
  08-prompt-injection.sh
)

last=$(( ${#scripts[@]} - 1 ))
for i in "${!scripts[@]}"; do
  echo
  echo ">>> [$((i + 1))/${#scripts[@]}] ${scripts[$i]}"
  bash "$DIR/${scripts[$i]}"
  if [ "$i" -lt "$last" ]; then
    echo "pausing ${PAUSE}s before the next attack ..."
    sleep "$PAUSE"
  fi
done

echo
echo "All attacks ran. Run lab/attacks/cleanup.sh when finished."
