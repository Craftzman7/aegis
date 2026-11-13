#!/usr/bin/env bash
# LAB ONLY. Simulates a backdoor account: a second user "backdoor" with UID 0 on target1.
# Idempotent: does nothing if the account already exists.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "02 New UID 0 user" \
  "Creates account 'backdoor' with UID 0 on target1 (useradd -o -u 0)" \
  "T1136.001 Persistence: Create Account: Local Account"

require_up target1

run_in target1 sh -c '
  if id backdoor >/dev/null 2>&1; then
    echo "backdoor already exists"
  else
    useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor
    echo "created backdoor"
  fi
  id backdoor
  grep "^backdoor:" /etc/passwd
'

echo "Done. The agent should flag a new UID 0 account. Its disable_user action must refuse uid 0."
