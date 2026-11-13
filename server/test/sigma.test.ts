import { describe, expect, it } from "vitest";
import { zipSync, strToU8 } from "fflate";
import { lintSigma } from "../src/sigma/lint";
import { extractLinuxRules } from "../src/sigma/sync";

const GOOD = `title: Curl Pipe Bash
id: 9d1b0b0e-0c5e-4a46-bb0d-6d4e1a1b2c3d
status: test
description: x
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  filter:
    User: root
  condition: selection and not filter
falsepositives:
  - admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.004
`;

describe("sigma lint", () => {
  it("accepts a valid rule and extracts metadata", () => {
    const r = lintSigma(GOOD);
    expect(r.ok).toBe(true);
    expect(r.rule).toMatchObject({ id: "9d1b0b0e-0c5e-4a46-bb0d-6d4e1a1b2c3d", level: "high", logsource: "linux/process_creation" });
    expect(r.rule?.tags).toContain("attack.t1059.004");
    expect(r.rule?.falsepositives).toEqual(["admin scripts"]);
  });
  it.each([
    ["title", GOOD.replace(/^title:.*\n/m, "")],
    ["id", GOOD.replace(/^id:.*\n/m, "")],
    ["logsource", GOOD.replace(/logsource:\n  product: linux\n  category: process_creation\n/, "")],
    ["detection", GOOD.replace(/detection:[\s\S]*falsepositives/, "falsepositives")],
    ["condition", GOOD.replace(/  condition:.*\n/, "")],
    ["level", GOOD.replace(/^level:.*\n/m, "")],
  ])("flags missing %s", (name, y) => {
    const r = lintSigma(y);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toContain(name);
  });
  it("flags undefined selection in condition, bad level, bad yaml, non-mapping, empty", () => {
    expect(lintSigma(GOOD.replace("selection and not filter", "selection and not nothere")).errors.join()).toContain("nothere");
    expect(lintSigma(GOOD.replace("level: high", "level: urgent")).ok).toBe(false);
    expect(lintSigma("a: [unclosed").ok).toBe(false);
    expect(lintSigma("- a\n- b").ok).toBe(false);
    expect(lintSigma("").ok).toBe(false);
    expect(lintSigma("x".repeat(70000)).ok).toBe(false);
  });
  it("supports wildcard conditions", () => {
    expect(lintSigma(GOOD.replace("selection and not filter", "1 of sel* ").replace("selection:", "sel1:")).ok).toBe(true);
  });
});

describe("sigma zip extraction", () => {
  it("keeps only rules/linux yml", () => {
    const zip = zipSync({
      "rules/linux/process_creation/a.yml": strToU8(GOOD),
      "rules/windows/process_creation/w.yml": strToU8(GOOD),
      "rules/linux/README.md": strToU8("x"),
      "rules-emerging-threats/linux/x.yml": strToU8(GOOD),
    });
    const out = extractLinuxRules(zip);
    expect(out.map((o) => o.path)).toEqual(["rules/linux/process_creation/a.yml"]);
  });
});
