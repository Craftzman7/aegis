import { DurableObject } from "cloudflare:workers";

/** Dashboard live fan-out. One global instance; hibernating WebSockets. */
export class FleetDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("expected websocket", { status: 426 });
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].send(JSON.stringify({ type: "hello", data: { clients: this.ctx.getWebSockets().length }, ts: new Date().toISOString() }));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  /** RPC: broadcast `{type,data,ts}` to every connected dashboard. */
  publish(type: string, data: unknown): number {
    const msg = JSON.stringify({ type, data, ts: new Date().toISOString() });
    let n = 0;
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(msg);
        n++;
      } catch {
        /* closed socket; runtime will clean up */
      }
    }
    return n;
  }

  webSocketMessage(): void {
    /* dashboards send nothing meaningful (keepalive "ping" handled by auto-response) */
  }
  webSocketClose(ws: WebSocket, code: number): void {
    try {
      ws.close(code === 1005 ? 1000 : code, "closed");
    } catch {
      /* already closed */
    }
  }
  webSocketError(ws: WebSocket): void {
    try {
      ws.close(1011, "error");
    } catch {
      /* ignore */
    }
  }
}
