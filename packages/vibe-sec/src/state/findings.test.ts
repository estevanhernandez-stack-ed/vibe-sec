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
  dedupeByLocation,
  normalizePath,
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

// ─── Regression: multi-root path-normalized de-dupe (Fix 4, WSYATM dogfood) ──
// In a multi-package repo with no root package.json, a file scanned via the repo
// root AND a sub-root surfaces with different relative prefixes + different ids,
// so id-dedup misses it. dedupeByLocation collapses by canonical location.
describe("dedupeByLocation — multi-root duplicate collapse (regression)", () => {
  it("normalizePath lowercases, forward-slashes, strips leading ./", () => {
    expect(normalizePath("Functions\\Src\\Quiz.JS")).toBe("functions/src/quiz.js");
    expect(normalizePath("./src/a.ts")).toBe("src/a.ts");
    expect(normalizePath(null)).toBe("");
  });

  it("collapses the same file reached via two package roots into one finding", () => {
    // Same physical quiz.js: full repo-relative path vs functions/-root-relative.
    const a = fixtureFinding("rl-001", {
      primary_concern: "rate-limiting",
      finding_type: "llm-endpoint-unauthenticated",
      file: "functions/src/games/quiz.js",
      line: 208,
    });
    const b = fixtureFinding("rl-002", {
      primary_concern: "rate-limiting",
      finding_type: "llm-endpoint-unauthenticated",
      file: "src/games/quiz.js",
      line: 208,
    });
    const deduped = dedupeByLocation([a, b]);
    expect(deduped).toHaveLength(1);
    // The longer (more-qualified) path wins.
    expect(deduped[0]!.file).toBe("functions/src/games/quiz.js");
  });

  it("keeps DISTINCT files with the same basename apart", () => {
    const a = fixtureFinding("rl-001", { file: "functions/quiz.js", line: 1 });
    const b = fixtureFinding("rl-002", { file: "backend/quiz.js", line: 1 });
    // Neither path is a suffix of the other → both survive.
    expect(dedupeByLocation([a, b])).toHaveLength(2);
  });

  it("keeps different lines / concerns / types apart", () => {
    const base = { file: "functions/src/games/quiz.js", primary_concern: "rate-limiting" as const };
    const a = fixtureFinding("x1", { ...base, finding_type: "llm-endpoint-unauthenticated", line: 208 });
    const b = fixtureFinding("x2", { ...base, finding_type: "llm-endpoint-unauthenticated", line: 999 });
    const c = fixtureFinding("x3", { ...base, finding_type: "other-thing", line: 208 });
    expect(dedupeByLocation([a, b, c])).toHaveLength(3);
  });

  it("collapses duplicate file===null advisories by concern+type+title", () => {
    const a = fixtureFinding("d1", {
      primary_concern: "dependency-cve",
      finding_type: "dependency-scan-not-performed",
      title: "scan not performed",
      file: null,
    });
    const b = fixtureFinding("d2", {
      primary_concern: "dependency-cve",
      finding_type: "dependency-scan-not-performed",
      title: "scan not performed",
      file: null,
    });
    expect(dedupeByLocation([a, b])).toHaveLength(1);
  });

  it("does not collapse a partial-segment suffix match (foo.js vs ofoo.js)", () => {
    const a = fixtureFinding("p1", { file: "a/foo.js", line: 1 });
    const b = fixtureFinding("p2", { file: "ofoo.js", line: 1 });
    // "a/foo.js" ends with "foo.js" but boundary check uses ofoo.js vs foo.js:
    // "ofoo.js" does not end on a "/" boundary relative to "a/foo.js" tail.
    expect(dedupeByLocation([a, b])).toHaveLength(2);
  });
});
