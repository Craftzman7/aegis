import { useMutation, useQuery, useQueryClient, useInfiniteQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { ActionName, AutonomyMode, JsonObject, PolicyBody, RuleStatus } from "./types";

export const qk = {
  me: ["me"], overview: ["overview"], hosts: ["hosts"], host: (id: string) => ["host", id],
  autonomy: ["autonomy"], incidents: ["incidents"], incident: (id: string) => ["incident", id],
  approvals: ["approvals"], audit: ["audit"], rules: ["rules"], coverage: ["coverage"],
  policies: (id: string) => ["policies", id],
} as const;

/** Poll interval used when the live WebSocket is down. Set by LiveProvider via setPollMs. */
let pollMs: number | false = false;
export const setPollMs = (v: number | false) => { pollMs = v; };
const live = () => pollMs;

export const useMe = () => useQuery({ queryKey: qk.me, queryFn: api.me, staleTime: Infinity });
export const useOverview = () => useQuery({ queryKey: qk.overview, queryFn: api.overview, refetchInterval: live });
export const useHosts = () => useQuery({ queryKey: qk.hosts, queryFn: api.hosts, refetchInterval: live });
export const useHost = (id: string) => useQuery({ queryKey: qk.host(id), queryFn: () => api.host(id), refetchInterval: live });
export const useGlobalAutonomy = () => useQuery({ queryKey: qk.autonomy, queryFn: api.getAutonomy, refetchInterval: live });
export const useIncidents = (f: { status?: string; severity?: string; host?: string }) =>
  useQuery({ queryKey: [...qk.incidents, f], queryFn: () => api.incidents(f), refetchInterval: live });
export const useIncident = (id: string) => useQuery({ queryKey: qk.incident(id), queryFn: () => api.incident(id), refetchInterval: live });
export const useApprovals = () => useQuery({ queryKey: qk.approvals, queryFn: api.approvals, refetchInterval: live });
export const useRules = () => useQuery({ queryKey: qk.rules, queryFn: api.rules });
export const useCoverage = () => useQuery({ queryKey: qk.coverage, queryFn: api.coverage });
export const usePolicies = (hostId: string) => useQuery({ queryKey: qk.policies(hostId), queryFn: () => api.policies(hostId) });

export function useAudit(f: { actor?: string; event?: string }) {
  return useInfiniteQuery({
    queryKey: [...qk.audit, f],
    queryFn: async ({ pageParam }) => api.audit({ limit: 50, before: pageParam }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length >= 50 ? last[last.length - 1]?.id : undefined),
    refetchInterval: live,
  });
}

/** Mutation helper that invalidates a set of query-key prefixes on success. */
function useInvalidating<V, R>(fn: (v: V) => Promise<R>, keys: readonly (readonly unknown[])[]) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => { keys.forEach((k) => void qc.invalidateQueries({ queryKey: k as unknown[] })); },
  });
}
const ALL = [qk.overview, qk.incidents, ["incident"], qk.approvals, qk.hosts, ["host"], qk.audit] as const;

export const useVerdict = () => useInvalidating((v: { id: string; verdict: "true_positive" | "false_positive"; note: string }) => api.verdict(v.id, v.verdict, v.note), ALL);
export const useApprove = () => useInvalidating((v: { id: string; params?: JsonObject; ttl_seconds?: number }) => api.approve(v.id, { params: v.params, ttl_seconds: v.ttl_seconds }), ALL);
export const useReject = () => useInvalidating((v: { id: string; reason: string }) => api.reject(v.id, v.reason), ALL);
export const useRollback = () => useInvalidating((id: string) => api.rollback(id), ALL);
export const useManualAction = () => useInvalidating((v: { host_id: string; action: ActionName; params: JsonObject; incident_id?: string }) => api.manualAction(v), ALL);
export const useSetHostAutonomy = () => useInvalidating((v: { id: string; mode: AutonomyMode | null }) => api.setHostAutonomy(v.id, v.mode), [qk.hosts, ["host"], qk.audit]);
export const useSetAutonomy = () => useInvalidating((mode: AutonomyMode) => api.setAutonomy(mode), [qk.autonomy, qk.overview, qk.audit]);
export const useSetRuleStatus = () => useInvalidating((v: { id: string; status: RuleStatus }) => api.setRuleStatus(v.id, v.status), [qk.rules, qk.coverage, qk.audit]);
export const useCreateRule = () => useInvalidating((v: { yaml: string; status: RuleStatus }) => api.createRule(v.yaml, v.status), [qk.rules, qk.coverage]);
export const useSetPolicy = () => useInvalidating((v: { hostId: string; body: PolicyBody; reason: string }) => api.setPolicy(v.hostId, v.body, v.reason), [["policies"], ["host"], qk.hosts, qk.audit]);
