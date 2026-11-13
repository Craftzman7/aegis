import type { IncidentRow } from "../types";
import { publish } from "./fleet";

export const getIncident = (env: Env, id: string) => env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(id).first<IncidentRow>();

export async function publishIncident(env: Env, id: string): Promise<void> {
  const row = await getIncident(env, id);
  if (row) await publish(env, "incident", row as unknown as Record<string, unknown>);
}

export const isClosed = (status: string) => status.startsWith("closed");
