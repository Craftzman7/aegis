#!/usr/bin/env bash
# LAB ONLY. Entrypoint for the Aegis lab target containers (no systemd).
#
# 1. starts rsyslog (so sshd writes /var/log/auth.log), sshd, cron
# 2. starts auditd and loads a few audit rules (best effort: kernel audit may be
#    unavailable under Docker Desktop, in which case this only warns)
# 3. enrolls the agent once if it is not enrolled yet (AEGIS_TOKEN is one-time)
# 4. execs `aegis-agent run` so the agent receives signals directly
set -euo pipefail

AGENT_BIN=/usr/local/bin/aegis-agent
AGENT_KEY=/var/lib/aegis/agent.key   # PROTOCOL.md section 1: agent key, written at enroll

log() { echo "[lab-entrypoint] $*"; }

if [ ! -x "$AGENT_BIN" ]; then
  log "ERROR: $AGENT_BIN is missing or not executable."
  log "Build the agent first (make -C agent build-linux-arm64 or build-linux-amd64)"
  log "and check AEGIS_ARCH matches the binary you built."
  exit 1
fi

mkdir -p /run/sshd /var/lib/aegis /var/log/audit
ssh-keygen -A >/dev/null 2>&1 || true   # creates only the missing host keys

# --- logging -----------------------------------------------------------------
if ! rsyslogd 2>/dev/null; then
  log "WARN: rsyslogd failed to start; /var/log/auth.log will be missing"
fi

# --- sshd and cron -----------------------------------------------------------
if ! /usr/sbin/sshd; then
  log "ERROR: sshd failed to start"
  exit 1
fi
log "sshd started"

if ! cron; then
  log "WARN: cron failed to start"
fi

# --- auditd (best effort) ----------------------------------------------------
if auditd 2>/dev/null; then
  if auditctl -s >/dev/null 2>&1; then
    auditctl -a always,exit -F arch=b64 -S execve -k aegis-exec || true
    for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/cron.d \
             /var/spool/cron/crontabs /root/.ssh/authorized_keys; do
      if [ -e "$f" ]; then
        auditctl -w "$f" -p wa -k aegis-identity || true
      fi
    done
    log "auditd running, audit rules loaded"
  else
    log "WARN: auditd started but audit status is unavailable (no kernel audit here?)"
  fi
else
  log "WARN: auditd not usable in this container (Docker Desktop often has no kernel audit)"
fi

# --- agent enrollment (once) -------------------------------------------------
if [ -s "$AGENT_KEY" ]; then
  log "already enrolled ($AGENT_KEY exists); skipping enrollment"
elif [ -n "${AEGIS_TOKEN:-}" ]; then
  : "${AEGIS_SERVER:?AEGIS_SERVER must be set (default http://host.docker.internal:8787)}"
  log "enrolling with $AEGIS_SERVER"
  "$AGENT_BIN" enroll --server "$AEGIS_SERVER" --token "$AEGIS_TOKEN"
else
  log "ERROR: not enrolled and AEGIS_TOKEN is empty."
  log "Create an enrollment token and set AEGIS_TOKEN_<TARGET> (see lab/README.md)."
  exit 1
fi

# Do not leave the one-time token in the agent's environment.
unset AEGIS_TOKEN

log "starting agent"
exec "$AGENT_BIN" run
