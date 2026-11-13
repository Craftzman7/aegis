import { fleetStub } from "./stubs";
import type { FleetEventType } from "../types";
import { logError, parseRow } from "./util";

/** Fan out a live event to dashboards. Never throws: live feed is best effort. */
export async function publish(env: Env, type: FleetEventType, row: Record<string, unknown>): Promise<void> {
  try {
    await fleetStub(env).publish(type, parseRow(row));
  } catch (e) {
    logError("fleet.publish failed", e, { type });
  }
}
