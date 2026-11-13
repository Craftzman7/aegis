import type { FleetDO } from "../do/FleetDO";
import type { HostDO } from "../do/HostDO";

export function hostStub(env: Env, hostId: string): DurableObjectStub<HostDO> {
  return env.HOST.getByName(hostId) as DurableObjectStub<HostDO>;
}
export function fleetStub(env: Env): DurableObjectStub<FleetDO> {
  return env.FLEET.getByName("global") as DurableObjectStub<FleetDO>;
}
