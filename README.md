# Aegis

An autonomous blue-team SOC. A small agent on each Linux host detects suspicious activity. An LLM analyst on Cloudflare investigates it the way a tier-3 responder would: it pulls evidence from the host, re-assesses, and proposes containment. A human approves anything disruptive from a web dashboard.

```
 Linux host                         Cloudflare
┌────────────────────┐ signed HTTPS ┌──────────────────────────────────────────┐
│ aegis-agent (Go)   │ ───────────▶ │ Worker: ingest ─▶ Queue ─▶ Workflow      │
│  collectors        │              │   AI analyst (Workers AI, DeepSeek V4.1) │
│  Sigma + native    │ ◀─ WebSocket │   policy gate (authoritative)            │
│  executor          │ signed cmds  │ D1 · R2 · Vectorize · Durable Objects    │
└────────────────────┘              │ Dashboard (behind Cloudflare Access)     │
                                    └──────────────────────────────────────────┘
```

## How an incident flows

1. **Detect.** The agent watches auth logs, processes (`/proc`, auditd), network connections, file integrity and users. It evaluates Sigma rules plus native and baseline detectors locally, and ships only anomalies.
2. **Correlate.** The server groups anomalies per host into incidents and starts an investigation Workflow.
3. **Investigate.** The AI returns a verdict, severity and confidence, plus typed requests from a fixed vocabulary.
4. **Gate.** Every request is checked against bounds:
   - **Tier 0** (evidence collection, watches, shadow-mode rules) runs automatically.
   - **Tier 1** (kill, block, quarantine, disable user, isolate, suppress, disable rule) waits for human approval.
5. **Act.** Commands are Ed25519-signed and executed by the agent's allowlisted executor. Results flow back and the AI re-analyzes, for up to a few rounds.
6. **Learn.** Analyst verdicts (true or false positive) are stored in Vectorize memory and inform later triage.

## Quick start

```sh
# Look at the UI with mock data
cd dashboard && npm install && VITE_MOCK=1 npm run dev

# Full local loop: Worker + Docker lab + attack scripts
#   see lab/README.md
```

Deploying to your own Cloudflare account: `server/scripts/deploy.sh`, then the Access setup in [docs/OPERATIONS.md](docs/OPERATIONS.md).

Installing the agent on a host: create an enrollment token under **Settings** in the dashboard, then run on the host:

```sh
curl -fsSL https://<your-worker>/install.sh | sudo sh -s -- --token <token> --server https://<your-worker>
```

## Docs

- [AGENTS.md](AGENTS.md): repo map, commands, invariants. Start here before changing code.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): agent ⇄ server ⇄ dashboard contract.
- [docs/OPERATIONS.md](docs/OPERATIONS.md): deploy, enroll, debug incidents, change the model.
- [agent/README.md](agent/README.md): agent internals.
- [lab/README.md](lab/README.md): end-to-end lab and attack simulations.
- [docs/PLAN.md](docs/PLAN.md): the original design document.

## Known limitations

- YARA scanning is a stub, and Sigma count aggregations are not supported.
- File integrity is checked by rehashing every 15 s, not by inotify.
- auditd usually isn't available in Docker Desktop. Process detection then falls back to `/proc` polling, which can miss very short-lived processes.
- Isolation pins the server's IPs at isolation time. If they change during isolation, the agent goes offline until the TTL expires.
- There is no agent auto-update.
