import { Hono } from "hono";
import { agent } from "./routes/agent";
import { consoleApp } from "./routes/console";
import { INSTALL_SH } from "./install";
import { handleQueue, type TriageMessage } from "./queue";
import { handleScheduled } from "./scheduled";
import { errMsg, logError } from "./lib/util";

export { HostDO } from "./do/HostDO";
export { FleetDO } from "./do/FleetDO";
export { InvestigationWorkflow } from "./workflows/investigation";

const app = new Hono<{ Bindings: Env }>();

app.onError((e, c) => {
  logError("unhandled", e, { path: c.req.path });
  return c.json({ error: "internal error", detail: c.env.DEV_MODE === "true" ? errMsg(e) : undefined }, 500);
});

app.get("/healthz", (c) => c.json({ ok: true }));

app.route("/v1", agent);
app.route("/console", consoleApp);

app.get("/install.sh", (c) => {
  const origin = new URL(c.req.url).origin;
  return new Response(INSTALL_SH.replaceAll("__SERVER__", origin), { headers: { "content-type": "text/x-shellscript; charset=utf-8", "cache-control": "no-store" } });
});

app.get("/releases/agent/latest/:file", async (c) => {
  const f = c.req.param("file");
  if (f !== "aegis-agent-linux-amd64" && f !== "aegis-agent-linux-arm64") return c.json({ error: "not found" }, 404);
  const o = await c.env.EVIDENCE.get(`releases/agent/latest/${f}`);
  if (!o) return c.json({ error: "release not uploaded" }, 404);
  return new Response(o.body, { headers: { "content-type": "application/octet-stream", etag: o.httpEtag, "content-length": String(o.size) } });
});

app.notFound((c) => (c.req.path.startsWith("/v1/") || c.req.path.startsWith("/console/") ? c.json({ error: "not found" }, 404) : c.env.ASSETS.fetch(c.req.raw)));

export default {
  fetch: app.fetch,
  queue: (batch: MessageBatch<unknown>, env: Env) => handleQueue(batch as MessageBatch<TriageMessage>, env),
  scheduled: (controller: ScheduledController, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(handleScheduled(controller, env));
  },
} satisfies ExportedHandler<Env>;
