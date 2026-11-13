// Technique -> tactic grouping for the coverage matrix (parent technique id; common subset).
export const TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Other",
] as const;
export type Tactic = (typeof TACTICS)[number];

const MAP: Record<string, Tactic> = {
  T1190: "Initial Access", T1133: "Initial Access", T1078: "Initial Access", T1566: "Initial Access",
  T1059: "Execution", T1053: "Execution", T1204: "Execution", T1106: "Execution", T1203: "Execution",
  T1098: "Persistence", T1136: "Persistence", T1543: "Persistence", T1547: "Persistence", T1546: "Persistence", T1505: "Persistence", T1037: "Persistence",
  T1068: "Privilege Escalation", T1548: "Privilege Escalation", T1055: "Privilege Escalation",
  T1070: "Defense Evasion", T1036: "Defense Evasion", T1027: "Defense Evasion", T1562: "Defense Evasion", T1222: "Defense Evasion", T1140: "Defense Evasion", T1574: "Defense Evasion",
  T1110: "Credential Access", T1003: "Credential Access", T1552: "Credential Access", T1555: "Credential Access", T1556: "Credential Access",
  T1082: "Discovery", T1083: "Discovery", T1057: "Discovery", T1018: "Discovery", T1049: "Discovery", T1033: "Discovery", T1087: "Discovery",
  T1021: "Lateral Movement", T1570: "Lateral Movement",
  T1005: "Collection", T1560: "Collection", T1113: "Collection",
  T1071: "Command and Control", T1105: "Command and Control", T1095: "Command and Control", T1572: "Command and Control", T1573: "Command and Control",
  T1048: "Exfiltration", T1041: "Exfiltration", T1567: "Exfiltration",
  T1486: "Impact", T1489: "Impact", T1496: "Impact", T1531: "Impact", T1485: "Impact",
};
export function tacticOf(technique: string): Tactic {
  return MAP[technique.split(".")[0].toUpperCase()] ?? "Other";
}
