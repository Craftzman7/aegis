import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { HostDO } from "../src/do/HostDO";

describe("HostDO pending command store", () => {
  it("stores, polls, acks and expires commands", async () => {
    const stub = env.HOST.getByName("host-x") as DurableObjectStub<HostDO>;
    const e = (id: string) => ({ payload: btoa(id), sig: "s" });
    expect((await stub.pushCommand("c1", e("c1"), Date.now() + 60_000)).delivered).toBe(false);
    await stub.pushCommand("c2", e("c2"), Date.now() - 1);
    expect((await stub.pendingCommands()).map((x) => atob(x.payload))).toEqual(["c1"]);
    await stub.ack("c1");
    expect(await stub.pendingCommands()).toEqual([]);
    expect(await stub.isConnected()).toBe(false);
    expect(await stub.notifyPolicy(3)).toBe(0);
    await runInDurableObject(stub, async (inst: HostDO) => { await inst.alarm(); });
  });
});
