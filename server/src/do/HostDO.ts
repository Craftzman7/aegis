import { DurableObject } from "cloudflare:workers";
import type { SignedEnvelope } from "../types";

const PING_INTERVAL_MS = 25_000;

interface CmdRow extends Record<string, SqlStorageValue> {
  id: string;
  envelope: string;
  expires_at: number;
}

/** One per host: command channel (WebSocket push + durable pending store for poll fallback). */
export class HostDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS cmds (id TEXT PRIMARY KEY, envelope TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)",
      );
    });
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("expected websocket", { status: 426 });
    // A host has a single live channel: replace older sockets.
    for (const old of this.ctx.getWebSockets()) {
      try {
        old.close(1000, "replaced");
      } catch {
        /* ignore */
      }
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    // Flush anything pending right away.
    for (const env of this.pending()) this.send(pair[1], { type: "command", envelope: env });
    await this.scheduleAlarm();
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  private send(ws: WebSocket, msg: unknown): boolean {
    try {
      ws.send(JSON.stringify(msg));
      return true;
    } catch {
      return false;
    }
  }

  private broadcast(msg: unknown): number {
    let n = 0;
    for (const ws of this.ctx.getWebSockets()) if (this.send(ws, msg)) n++;
    return n;
  }

  private pending(): SignedEnvelope[] {
    const now = Date.now();
    this.ctx.storage.sql.exec("DELETE FROM cmds WHERE expires_at < ?", now);
    return this.ctx.storage.sql
      .exec<CmdRow>("SELECT id, envelope, expires_at FROM cmds ORDER BY created_at")
      .toArray()
      .map((r) => JSON.parse(r.envelope) as SignedEnvelope);
  }

  /** RPC: store a signed command and push it if the agent is connected. */
  async pushCommand(commandId: string, envelope: SignedEnvelope, expiresAtMs: number): Promise<{ delivered: boolean }> {
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO cmds(id, envelope, expires_at, created_at) VALUES (?,?,?,?)",
      commandId,
      JSON.stringify(envelope),
      expiresAtMs,
      Date.now(),
    );
    const delivered = this.broadcast({ type: "command", envelope }) > 0;
    return { delivered };
  }

  /** RPC: poll fallback; unacked, unexpired commands. */
  pendingCommands(): SignedEnvelope[] {
    return this.pending();
  }

  /** RPC: result received; drop from pending store. */
  ack(commandId: string): void {
    this.ctx.storage.sql.exec("DELETE FROM cmds WHERE id=?", commandId);
  }

  /** RPC: tell the agent to fetch /v1/policy. */
  notifyPolicy(version: number): number {
    return this.broadcast({ type: "policy_updated", version });
  }

  isConnected(): boolean {
    return this.ctx.getWebSockets().length > 0;
  }

  private async scheduleAlarm(): Promise<void> {
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null) await this.ctx.storage.setAlarm(Date.now() + PING_INTERVAL_MS);
  }

  async alarm(): Promise<void> {
    const sockets = this.ctx.getWebSockets();
    this.pending(); // prune expired
    if (sockets.length > 0) {
      this.broadcast({ type: "ping" });
      await this.ctx.storage.setAlarm(Date.now() + PING_INTERVAL_MS);
    }
  }

  webSocketMessage(): void {
    /* agent -> server frames are not used (results go over HTTPS); any frame proves liveness */
  }
  webSocketClose(ws: WebSocket, code: number): void {
    try {
      ws.close(code === 1005 ? 1000 : code, "closed");
    } catch {
      /* ignore */
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
