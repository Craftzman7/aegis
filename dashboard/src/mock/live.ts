import type { LiveMessage } from "../api/types";
import { ANOMALIES, HOSTS } from "./fixtures";

type Handler = (m: LiveMessage) => void;
const SAMPLES = [
  { rule_title: "SSH brute force", severity: "low", summary: "9 failed logins from 192.0.2.%n", category: "auth" },
  { rule_title: "Outbound connection to rare port", severity: "medium", summary: "curl connected to 198.51.100.%n:8081", category: "network" },
  { rule_title: "New cron entry created", severity: "medium", summary: "/etc/cron.d/job%n modified", category: "persistence" },
  { rule_title: "Sudo Privilege Escalation Attempt", severity: "low", summary: "sudo -l run by user%n", category: "process" },
];

/** Fake live feed: emits an event every few seconds. Returns an unsubscribe function. */
export function subscribeMockFeed(handler: Handler): () => void {
  let n = 100;
  const tick = () => {
    n++;
    const roll = Math.random();
    const host = HOSTS[n % HOSTS.length];
    const ts = new Date().toISOString();
    if (roll < 0.6) {
      const s = SAMPLES[n % SAMPLES.length];
      handler({ type: "anomaly", ts, data: { id: `live-${n}`, host_id: host.id, incident_id: null, ts, severity: s.severity, rule_title: s.rule_title, summary: s.summary.replace("%n", String(n % 250)), category: s.category, shadow: 0, attack_tags: [] } });
    } else if (roll < 0.8) {
      handler({ type: "host", ts, data: { id: host.id, hostname: host.hostname, status: host.status } });
    } else if (roll < 0.9) {
      handler({ type: "audit", ts, data: { id: n, actor: "agent:" + host.hostname, event: "heartbeat.ok" } });
    } else {
      handler({ type: "ai_review", ts, data: { id: `rv-live-${n}`, incident_id: ANOMALIES[0].incident_id, step: "reanalyze" } });
    }
  };
  const id = window.setInterval(tick, 3500);
  const first = window.setTimeout(tick, 800);
  return () => { window.clearInterval(id); window.clearTimeout(first); };
}
