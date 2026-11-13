import { beforeEach, describe, expect, it } from "vitest";
import { createAction, dispatchAction, getAction, setActionState } from "../src/lib/actions";
import { cleanDb, enrollHost, mkEnv } from "./helpers";

beforeEach(cleanDb);

describe("dispatchAction", () => {
  it("does not overwrite a result the agent posted while the push was in flight", async () => {
    const { env: base } = mkEnv();
    const h = await enrollHost(base);
    // Fake HostDO: the agent answers (POST /v1/results) before pushCommand returns.
    const HOST = { getByName: () => ({ pushCommand: async (id: string) => { await setActionState(base, id, "succeeded", { result: { ok: 1 } }); return { delivered: true }; } }) };
    const env = Object.assign(Object.create(base), { HOST }) as Env;
    const a = await createAction(env, { id: crypto.randomUUID(), incident_id: null, host_id: h.id, action: "collect_evidence", params: { kind: "netconns" }, tier: 0, kind: "command", state: "approved", proposed_by: "ai" });
    const out = await dispatchAction(env, a, "ai");
    expect(out.state).toBe("succeeded");
    expect((await getAction(env, a.id))?.state).toBe("succeeded");
  });
});
