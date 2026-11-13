import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { LiveMessage } from "../api/types";
import { qk, setPollMs } from "../api/hooks";
import { asRecord, short } from "../lib/format";

export type LiveStatus = "connecting" | "open" | "closed";
export interface Toast { id: number; kind: "info" | "warn" | "crit"; title: string; body?: string; href?: string }
export interface TickerItem { key: number; msg: LiveMessage }

interface LiveCtx {
  status: LiveStatus; ticker: TickerItem[]; toasts: Toast[]; dismiss: (id: number) => void;
}
const Ctx = createContext<LiveCtx | null>(null);
export function useLive(): LiveCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useLive outside LiveProvider");
  return c;
}

const POLL_MS = 15_000;
const MAX_TICKER = 60;

/** Human-readable one-liner for a live message. */
export function describeLive(m: LiveMessage): string {
  const d = asRecord(m.data);
  const s = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : "");
  switch (m.type) {
    case "anomaly": return `${s("severity") || "anomaly"}: ${s("summary")}`;
    case "incident": return `incident ${s("title")} [${s("status")}]`;
    case "ai_review": return `AI ${s("step")} review on incident ${short(s("incident_id"))}`;
    case "action": return `action ${s("action")} -> ${s("state")} (${s("proposed_by")})`;
    case "host": return `host ${s("hostname") || short(s("id"))} ${s("status")}`;
    case "audit": return `audit ${s("event")} by ${s("actor")}`;
    case "policy": return `policy v${String(d.version ?? "?")} for ${short(s("host_id"))} by ${s("created_by")}`;
  }
}

function wsUrl(): string {
  const p = location.protocol === "https:" ? "wss:" : "ws:";
  return `${p}//${location.host}/console/live`;
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [ticker, setTicker] = useState<TickerItem[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seq = useRef(0);
  const seenIncidents = useRef(new Set<string>());
  const seenActions = useRef(new Set<string>());

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback((t: Omit<Toast, "id">) => {
    const id = ++seq.current;
    setToasts((l) => [...l.slice(-4), { ...t, id }]);
    window.setTimeout(() => dismiss(id), 8000);
  }, [dismiss]);

  const handle = useCallback((m: LiveMessage) => {
    const d = asRecord(m.data);
    const inv = (key: readonly unknown[]) => void qc.invalidateQueries({ queryKey: key as unknown[] });
    const incId = typeof d.incident_id === "string" ? d.incident_id : typeof d.id === "string" && m.type === "incident" ? d.id : null;
    const hostId = typeof d.host_id === "string" ? d.host_id : typeof d.id === "string" && m.type === "host" ? d.id : null;
    switch (m.type) {
      case "anomaly": inv(qk.overview); inv(qk.incidents); if (hostId) inv(qk.host(hostId)); if (incId) inv(qk.incident(incId)); break;
      case "incident": inv(qk.overview); inv(qk.incidents); if (incId) inv(qk.incident(incId)); break;
      case "ai_review": if (incId) inv(qk.incident(incId)); break;
      case "action": inv(qk.approvals); inv(qk.overview); if (incId) inv(qk.incident(incId)); if (hostId) inv(qk.host(hostId)); break;
      case "host": inv(qk.hosts); inv(qk.overview); if (hostId) inv(qk.host(hostId)); break;
      case "audit": inv(qk.audit); break;
      case "policy": inv(["policies"]); if (hostId) inv(qk.host(hostId)); break;
    }
    setTicker((t) => [{ key: ++seq.current, msg: m }, ...t].slice(0, MAX_TICKER));

    if (m.type === "action" && d.state === "proposed" && d.tier === 1 && typeof d.id === "string" && !seenActions.current.has(d.id)) {
      seenActions.current.add(d.id);
      toast({ kind: "warn", title: "New approval needed", body: `${String(d.action)} proposed by ${String(d.proposed_by)}`, href: "/approvals" });
    }
    if (m.type === "incident" && d.severity === "critical" && typeof d.id === "string" && !seenIncidents.current.has(d.id)) {
      seenIncidents.current.add(d.id);
      toast({ kind: "crit", title: "Critical incident", body: String(d.title ?? ""), href: `/incidents/${d.id}` });
    }
  }, [qc, toast]);

  useEffect(() => {
    let stopped = false;
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let unsubMock: (() => void) | undefined;
    let attempt = 0;

    const onOpen = () => { attempt = 0; setStatus("open"); setPollMs(false); void qc.invalidateQueries(); };
    const onDown = () => { setStatus("closed"); setPollMs(POLL_MS); };

    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      ws = new WebSocket(wsUrl());
      ws.onopen = onOpen;
      ws.onmessage = (ev: MessageEvent<string>) => {
        try { handle(JSON.parse(ev.data) as LiveMessage); } catch { /* ignore malformed frame */ }
      };
      ws.onclose = () => {
        onDown();
        if (stopped) return;
        const delay = Math.min(30_000, 1000 * 2 ** attempt++) * (0.75 + Math.random() * 0.5);
        timer = window.setTimeout(connect, delay);
      };
      ws.onerror = () => ws?.close();
    };

    if (import.meta.env.VITE_MOCK) {
      void import("../mock/live").then((m) => {
        if (stopped) return;
        onOpen();
        unsubMock = m.subscribeMockFeed(handle);
      });
    } else {
      connect();
    }
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      unsubMock?.();
      if (ws) { ws.onclose = null; ws.close(); }
    };
  }, [qc, handle]);

  const value = useMemo(() => ({ status, ticker, toasts, dismiss }), [status, ticker, toasts, dismiss]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
