#!/usr/bin/env bash
# LAB ONLY. Simulates an SSH password brute force against target1 from the attacker
# container: 30 wrong guesses for alice, then one correct login.
# Idempotent: it only creates failed/successful auth events. Safe to re-run.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

banner "01 SSH brute force" \
  "30 wrong password guesses for alice against target1, then one correct login" \
  "T1110.001 Credential Access: Brute Force: Password Guessing"

require_up attacker target1

for i in $(seq 1 30); do
  echo "[attempt $i/30] wrong password"
  run_in attacker sshpass -p "wrong-guess-$i" ssh "${SSH_OPTS[@]}" "$LAB_USER@target1" true </dev/null >/dev/null 2>&1 || true
  sleep 0.5
done

echo "[success] correct password for $LAB_USER"
run_in attacker sshpass -p "$LAB_PASS" ssh "${SSH_OPTS[@]}" "$LAB_USER@target1" 'id; hostname' </dev/null

echo "Done. Expect ~30 failed password events and 1 accepted login in target1 /var/log/auth.log."
