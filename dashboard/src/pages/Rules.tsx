import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useCoverage, useCreateRule, useHosts, useRules, useSetRuleStatus } from "../api/hooks";
import type { LintResult, Rule, RuleStatus, TestResult } from "../api/types";
import { SeverityBadge, StateBadge } from "../components/badges";
import { CodeEditor } from "../components/CodeEditor";
import { AttackTags, Card, ConfirmDialog, Empty, ErrorBox, Field, JsonView, Loading, PageHeader, Tabs } from "../components/ui";
import { TACTICS, tacticOf, type Tactic } from "../lib/attack";
import { errMsg, techniqueUrl } from "../lib/format";

const STATUSES: RuleStatus[] = ["active", "shadow", "disabled"];
const NEW_YAML = `title: Suspicious Example Rule
id: ${"00000000-0000-4000-8000-000000000000"}
status: experimental
description: Describe what this detects
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/nc'
    CommandLine|contains: ' -e '
  condition: selection
falsepositives:
  - Legitimate administration
level: high
tags:
  - attack.execution
  - attack.t1059.004
`;

function RuleWorkbench({ yaml, setYaml, ruleId, readOnly }: { yaml: string; setYaml?: (s: string) => void; ruleId: string; readOnly?: boolean }) {
  const hosts = useHosts();
  const [hostId, setHostId] = useState("");
  const [lint, setLint] = useState<LintResult | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>) => { setBusy(true); setErr(null); try { await fn(); } catch (e) { setErr(errMsg(e)); } finally { setBusy(false); } };
  return (
    <div className="space-y-3">
      <CodeEditor lang="yaml" label="Sigma rule YAML" value={yaml} onChange={readOnly ? () => undefined : (setYaml ?? (() => undefined))} height="320px" />
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="btn" disabled={busy} onClick={() => void run(async () => { setLint(await api.lintRule(yaml)); })}>Lint</button>
        <select aria-label="Host to test on" className="input" value={hostId} onChange={(e) => setHostId(e.target.value)}>
          <option value="">Select host...</option>{hosts.data?.map((h) => <option key={h.id} value={h.id}>{h.hostname}</option>)}
        </select>
        <button type="button" className="btn" disabled={busy || !hostId} onClick={() => void run(async () => { setTest(await api.testRule(ruleId, hostId, yaml)); })}>Test on host (24h buffer)</button>
      </div>
      {err && <ErrorBox error={new Error(err)} />}
      {lint && (lint.ok ? <p className="text-[#2fa66a]" role="status">Lint passed.</p> : (
        <ul role="alert" className="mono space-y-0.5 text-sev-critical">{lint.errors.map((e, i) => <li key={i}>{typeof e === "string" ? e : `${e.line ? `line ${e.line}: ` : ""}${e.message}`}</li>)}</ul>
      ))}
      {test && <div><p className="mb-1">Matches in the last 24h: <strong className="mono">{test.matches ?? 0}</strong></p><JsonView value={test.samples ?? test} /></div>}
    </div>
  );
}

function NewRule({ onDone }: { onDone: () => void }) {
  const [yaml, setYaml] = useState(NEW_YAML);
  const [status, setStatus] = useState<RuleStatus>("shadow");
  const create = useCreateRule();
  return (
    <Card title="New rule">
      <div className="space-y-3">
        <RuleWorkbench yaml={yaml} setYaml={setYaml} ruleId="draft" />
        <div className="flex flex-wrap items-center gap-2">
          <Field label="Initial status"><select className="input" value={status} onChange={(e) => setStatus(e.target.value as RuleStatus)}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select></Field>
          <button type="button" className="btn btn-primary self-end" disabled={create.isPending} onClick={() => create.mutate({ yaml, status }, { onSuccess: onDone })}>Save rule</button>
          <button type="button" className="btn self-end" onClick={onDone}>Cancel</button>
        </div>
        <p className="text-[11px] text-muted">New rules start in shadow mode by default: they log matches without creating incidents until promoted.</p>
        {create.error && <ErrorBox error={create.error} />}
      </div>
    </Card>
  );
}

function RuleTable() {
  const q = useRules();
  const set = useSetRuleStatus();
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Rule | null>(null);
  const [confirm, setConfirm] = useState<{ rule: Rule; status: RuleStatus } | null>(null);
  const [creating, setCreating] = useState(false);
  const rules = useMemo(() => (q.data ?? []).filter((r) => !filter || r.status === filter), [q.data, filter]);
  const change = (rule: Rule, status: RuleStatus) => {
    if (status === "disabled" && (rule.level === "high" || rule.level === "critical")) setConfirm({ rule, status });
    else set.mutate({ id: rule.id, status });
  };
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select aria-label="Filter by status" className="input" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All statuses</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>New rule</button>
      </div>
      {creating && <NewRule onDone={() => setCreating(false)} />}
      {set.error && <ErrorBox error={set.error} />}
      <div className="card overflow-x-auto">
        {q.isLoading ? <Loading what="rules" /> : q.error ? <ErrorBox error={q.error} /> : !rules.length ? <Empty>No rules.</Empty> : (
          <table className="tbl">
            <thead><tr><th>Pack</th><th>Title</th><th>Level</th><th>Status</th><th>Hits</th><th>TP / FP</th><th>Set status</th></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.pack_name ?? r.pack_id}</td>
                  <td><button type="button" className="text-left font-medium text-accent hover:underline" onClick={() => setOpen(open?.id === r.id ? null : r)}>{r.title}</button><div><AttackTags tags={r.attack_tags} /></div></td>
                  <td><SeverityBadge severity={r.level} /></td>
                  <td><StateBadge state={r.status} /></td>
                  <td className="mono">{r.hits_total}</td>
                  <td className="mono">{r.tp_total} / {r.fp_total}</td>
                  <td><select aria-label={`Status for ${r.title}`} className="input" value={r.status} onChange={(e) => change(r, e.target.value as RuleStatus)}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {open && <Card title={open.title} actions={<button type="button" className="btn" onClick={() => setOpen(null)}>Close</button>}><RuleWorkbench yaml={open.yaml} ruleId={open.id} readOnly /></Card>}
      <ConfirmDialog open={confirm !== null} danger title="Disable detection rule" confirmLabel="Disable rule" busy={set.isPending}
        onCancel={() => setConfirm(null)} onConfirm={() => confirm && set.mutate({ id: confirm.rule.id, status: confirm.status }, { onSuccess: () => setConfirm(null) })}>
        <p>You are disabling <strong>{confirm?.rule.title}</strong>, a <strong>{confirm?.rule.level}</strong>-level rule. It will stop detecting on every host once the policy is pushed.</p>
      </ConfirmDialog>
    </div>
  );
}

function Coverage() {
  const q = useCoverage();
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const grouped = useMemo(() => {
    const g = new Map<Tactic, { id: string; rules: number; hits: number }[]>();
    for (const t of q.data?.techniques ?? []) {
      const id = t.id.replace(/^attack\./i, "").toUpperCase();
      const tac = tacticOf(id);
      g.set(tac, [...(g.get(tac) ?? []), { id, rules: Array.isArray(t.rules) ? t.rules.length : t.rules, hits: t.hits_30d }]);
    }
    return g;
  }, [q.data]);
  if (q.isLoading) return <Loading what="coverage" />;
  if (q.error) return <ErrorBox error={q.error} />;
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {TACTICS.filter((t) => grouped.has(t)).map((t) => (
        <Card key={t} title={t}>
          <ul className="flex flex-wrap gap-1.5">
            {grouped.get(t)?.map((x) => (
              <li key={x.id}>
                <a href={techniqueUrl(x.id)} target="_blank" rel="noreferrer" title={`${x.rules} rule(s), ${x.hits} hits in 30d`}
                  className="mono block rounded border px-2 py-1 hover:underline" style={{ borderColor: "var(--accent)", background: `color-mix(in srgb, var(--accent) ${Math.min(60, 10 + x.hits)}%, transparent)` }}>
                  {x.id}<span className="ml-1 text-muted">{x.rules}r/{x.hits}h</span>
                </a>
              </li>
            ))}
          </ul>
        </Card>
      ))}
      {!grouped.size && <Empty>No coverage data{rules.data?.length ? "" : " (no rules loaded)"}.</Empty>}
    </div>
  );
}

export function Rules() {
  const [tab, setTab] = useState<"rules" | "coverage">("rules");
  return (
    <>
      <PageHeader title="Detection rules" />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "rules", label: "Rules" }, { id: "coverage", label: "ATT&CK coverage" }]} />
      {tab === "rules" ? <RuleTable /> : <Coverage />}
    </>
  );
}
