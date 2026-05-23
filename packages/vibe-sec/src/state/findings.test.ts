import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  appendFinding,
  appendFindings,
  readFindings,
  readFindingsDeduped,
  validateFinding,
  makeFinding,
  type Finding,
} from "./findings.js";
import { findingsPath } from "./paths.js";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-test-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function fixtureFinding(id: string, over: Partial<Finding> = {}): Finding {
  return makeFinding({
    id,
    primary_concern: "secret-detection",
    severity_base: "high",
    severity_tier_adjusted: "critical",
    confidence: 0.92,
    finding_type: "leaked-aws-key",
    title: "Committed AWS access key",
    tier: "public-facing",
    fix_class: "inline",
    tool_of_record: "in-house",
    ...over,
  });
}

describe("findings.jsonl writer + reader", () => {
  it("appends two findings, reads back both, line-count = 2", () => {
    appendFinding(tmp, fixtureFinding("sec-001"));
    appendFinding(tmp, fixtureFinding("sec-002"));

    const back = readFindings(tmp);
    expect(back).toHaveLength(2);
    expect(back.map((f) => f.id).sort()).toEqual(["sec-001", "sec-002"]);

    const raw = fs.readFileSync(findingsPath(tmp), "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    expect(lines).toHaveLength(2);
  });

  it("round-trips a finding through schema validation", () => {
    const f = fixtureFinding("sec-042", {
      secondary_concerns: ["owasp-survey", "config-posture"],
      owasp_2021: "A01",
      references: ["OWASP-A01-2021", "CWE-862"],
    });
    appendFinding(tmp, f);
    const [back] = readFindings(tmp);
    expect(validateFinding(back)).toEqual([]);
    expect(back).toEqual(f);
  });

  it("rejects an invalid finding via schema validation", () => {
    const bad = { schema_version: 2, id: "", confidence: 5 };
    const problems = validateFinding(bad);
    expect(problems.length).toBeGreaterThan(0);
    expect(problems.some((p) => p.includes("schema_version"))).toBe(true);
    expect(problems.some((p) => p.includes("confidence"))).toBe(true);
  });

  it("dedupes by id — same id appended twice counts once (last wins)", () => {
    appendFinding(tmp, fixtureFinding("sec-100", { confidence: 0.5 }));
    appendFinding(tmp, fixtureFinding("sec-100", { confidence: 0.99 }));
    appendFinding(tmp, fixtureFinding("sec-101"));

    expect(readFindings(tmp)).toHaveLength(3); // raw count
    const deduped = readFindingsDeduped(tmp);
    expect(deduped).toHaveLength(2);
    const reDetected = deduped.find((f) => f.id === "sec-100");
    expect(reDetected?.confidence).toBe(0.99); // last write wins
  });

  it("skips corrupt lines rather than throwing", () => {
    appendFinding(tmp, fixtureFinding("sec-ok"));
    fs.appendFileSync(findingsPath(tmp), "{ not valid json\n");
    appendFinding(tmp, fixtureFinding("sec-ok-2"));
    expect(readFindings(tmp)).toHaveLength(2);
  });

  it("returns [] when findings.jsonl does not exist", () => {
    expect(readFindings(tmp)).toEqual([]);
  });

  it("appendFindings writes many in one call", () => {
    appendFindings(tmp, [fixtureFinding("a"), fixtureFinding("b"), fixtureFinding("c")]);
    expect(readFindings(tmp)).toHaveLength(3);
  });
});
