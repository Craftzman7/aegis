import { useEffect, useMemo, useRef, useState } from "react";
import { useAudit } from "../api/hooks";
import { Empty, ErrorBox, IncidentLink, JsonView, Loading, PageHeader } from "../components/ui";
import { fmtTime } from "../lib/format";

const ACTORS = ["ai", "human", "agent", "system"];

export function Audit() {
  const [actor, setActor] = useState("");
  const [event, setEvent] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const q = useAudit({});
  const sentinel = useRef<HTMLDivElement>(null);
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = q;
  useEffect(() => {
    const el = sentinel.current;
    if (!el) return;
    const io = new IntersectionObserver((e) => { if (e[0].isIntersecting && hasNextPage && !isFetchingNextPage) void fetchNextPage(); }, { rootMargin: "200px" });
    io.observe(el);
    return () => io.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);
  const rows = useMemo(() => (q.data?.pages.flat() ?? []).filter((r) => (!actor || r.actor.split(":")[0] === actor) && (!event || r.event.toLowerCase().includes(event.toLowerCase()))), [q.data, actor, event]);
  return (
    <>
      <PageHeader title="Audit log">
        <select aria-label="Filter by actor type" className="input" value={actor} onChange={(e) => setActor(e.target.value)}><option value="">All actors</option>{ACTORS.map((a) => <option key={a}>{a}</option>)}</select>
        <input aria-label="Filter by event" className="input" placeholder="Event (e.g. action.approved)" value={event} onChange={(e) => setEvent(e.target.value)} />
      </PageHeader>
      <div className="card overflow-x-auto">
        {q.isLoading ? <Loading what="audit log" /> : q.error ? <ErrorBox error={q.error} /> : !rows.length ? <Empty>No entries.</Empty> : (
          <table className="tbl">
            <thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Incident</th><th>Detail</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono whitespace-nowrap">{fmtTime(r.ts)}</td><td className="mono">{r.actor}</td><td className="mono font-semibold">{r.event}</td>
                  <td>{r.incident_id ? <IncidentLink id={r.incident_id} /> : "-"}</td>
                  <td className="min-w-48">{r.detail == null ? "-" : open === r.id ? <JsonView value={r.detail} /> : <button type="button" className="text-muted underline-offset-2 hover:text-fg hover:underline" onClick={() => setOpen(r.id)}>View JSON</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div ref={sentinel} className="p-2 text-center text-muted">{isFetchingNextPage ? "Loading more..." : hasNextPage ? "" : rows.length ? "End of log" : ""}</div>
      </div>
    </>
  );
}
