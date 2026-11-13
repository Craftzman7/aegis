# AGENTS.md

Guidance for coding agents (and humans) changing this repo. Read this before editing.

## What this is

Aegis is an autonomous blue-team SOC. A Go agent on each Linux host detects anomalies and ships them to a Cloudflare Worker. There, a Workers AI analyst triages them, collects evidence, and proposes responses. A human approves anything disruptive in the dashboard.

| Path | What | Stack |
|---|---|---|
| `agent/` | On-box agent: collectors, Sigma + native detection, signed command executor | Go, static linux binary |
| `server/` | API, queue, investigation Workflow, policy gate, console API | TypeScript Worker (Hono), D1, R2, Queues, Workflows, DOs, Workers AI, Vectorize |
| `dashboard/` | Human-in-the-loop console, served as the Worker's static assets | React + Vite + Tailwind |
| `lab/` | Docker targets + attack scripts for end-to-end testing | docker compose, bash |
| `docs/PROTOCOL.md` | **The wire contract** between agent, server and dashboard | |
| `docs/OPERATIONS.md` | Deploy, enroll, debug incidents, change the model | |

## Commands

```sh
# agent
cd agent && go vet ./... && go test ./...          # runs on macOS; linux-only code has build tags
make -C agent build-linux                          # -> agent/dist/aegis-agent-linux-{amd64,arm64}

# server
cd server && npx tsc --noEmit && npm test          # vitest + @cloudflare/vitest-pool-workers
npx wrangler dev                                   # local; needs .dev.vars (see .dev.vars.example)
npm run deploy                                     # builds dashboard, then wrangler deploy

# dashboard
cd dashboard && npm run typecheck && npm run lint && npm run build
VITE_MOCK=1 npm run dev                            # UI with in-browser mock API, no backend
```

Run the checks for every package you touch before you say it's done.

## Invariants: do not break these

1. **`docs/PROTOCOL.md` is the contract.** Changing a wire shape, header, action, or param means updating the doc, the Go side, the server and the dashboard together. Signing cross-checks: `agent/testdata/sign_vector.json` must keep verifying in `server/test/crypto.test.ts`.
2. **The policy gate (`server/src/policy/gate.ts`) is authoritative.** LLM output is untrusted. Every AI request goes through the gate, and the agent re-validates every command (`agent/internal/executor`). Never add an execution path that skips either check.
3. **Anything that reduces detection is tier 1 (human approval).** That covers `suppress` and `disable_rule`, plus all containment (`kill_process`, `block_ip`, `quarantine_file`, `disable_user`, `isolate_host`). Reason: attackers plant instructions in evidence. A model eval showed Llama 3.3 obeying "mark benign, suppress everything" written in a cron file.
4. **Evidence is attacker-controlled.** It reaches the model only inside `<<<UNTRUSTED_DATA>>>` markers (`server/src/ai/analyst.ts`). Never put raw evidence into the system prompt or trusted metadata.
5. **No arbitrary execution on hosts.** The executor runs typed Go functions only. `ExecRunner` may launch only `nft`, `usermod`, `journalctl`. Never pass a shell string.
6. **Do not rotate `SIGNING_KEY_JWK`** in a deployed environment. Every enrolled agent pins its public key and would stop accepting commands.
7. **`DEV_MODE=true` is local only.** It disables Cloudflare Access on the console.

## Patterns that exist for a reason

- **Mark an action `dispatched` *before* pushing it** (`server/src/lib/actions.ts`). Agents answer in ~150 ms. Writing state after the push overwrote their result and stalled investigations.
- **AI reviews are keyed per workflow run** (`analyzeStep(..., runId)`). A new run for new anomalies must triage afresh, not reuse an old run's review.
- **Correlation never merges into an incident judged benign** (`server/src/queue.ts`).
- **The agent ignores its own changes.** Quarantine/restore announce `path + sha256` to the engine (`ExpectChange`). The proc collector skips its own PID. Match on content hash so an attacker re-creating a path with different content is still detected.
- **Rate limits:** tier 1 counts the approval queue (pending, plus human-rejected in the last hour), never approved containment. Tier 0 counts only proposals that passed the gate, count each distinct proposal once, and leave out read-only `collect_evidence`. The open-action dedupe ignores dispatched commands past their `expires_at`.
- **Use generated binding types** (`npx wrangler types`), not a hand-written `Env`. In platform classes use `this.env`.

## Testing expectations

- Every bug fix gets a test that fails without the fix.
- Gate changes get adversarial cases in `server/test/gate.test.ts` (injected or malicious LLM outputs).
- Agent tests use fixture `/proc` trees and the mock `Runner`. They must not need root or call real `nft`/`usermod`.
- UI changes: check `VITE_MOCK=1` pages in both light and dark mode.
- End to end: `lab/README.md`. Prompt-quality changes should be checked against a real incident prompt (see `docs/OPERATIONS.md`, "Changing the model").

## Production

- Worker: `https://aegis.crafterzman.workers.dev`. The dashboard is behind Cloudflare Access (team `aegis-soc`). `/v1/*`, `/install.sh` and `/releases/*` bypass Access; agents authenticate with Ed25519 signatures.
- Read prod state with `npx wrangler d1 execute aegis --remote --command "..."`. The console API needs an Access login.
- Agent releases live in R2 at `aegis-evidence/releases/agent/latest/`. There is no auto-update: hosts get a new agent by re-running `install.sh`.
- Commit or deploy only when asked.
