import { beforeEach, describe, expect, it } from "vitest";
import { buildGateContext } from "../src/policy/gate";
import { createAction } from "../src/lib/actions";
import { cleanDb, enrollHost, mkEnv } from "./helpers";

beforeEach(cleanDb);

describe("buildGateContext tier-1 rate count", () => {
  it("ignores gate rejections and counts repeated proposals once", async () => {
    const { env } = mkEnv();
    const h = await enrollHost(env);
    const add = (state: "proposed" | "rejected", ip: string) =>
      createAction(env, { id: crypto.randomUUID(), incident_id: null, host_id: h.id, action: "block_ip", params: { ip, ttl_seconds: 3600 }, tier: 1, kind: "command", state, proposed_by: "ai" });
    for (let i = 0; i < 10; i++) await add("rejected", "198.51.100.7"); // gate rejections
    await add("proposed", "198.51.100.8");
    await add("proposed", "198.51.100.8"); // same proposal again
    await add("proposed", "198.51.100.9");
    const ctx = await buildGateContext(env, { hostId: h.id, source: "ai", mode: "autonomous", thresholds: {}, serverEndpoints: [], requests: [] });
    expect(ctx.tier1LastHour).toBe(2);
  });
});
