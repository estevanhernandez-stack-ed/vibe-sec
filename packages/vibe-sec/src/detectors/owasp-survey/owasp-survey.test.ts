import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanSurveyRules } from "./survey-rules.js";
import { scanSsrf } from "./ssrf-shallow.js";
import { scanDynamicCodeSinks } from "./dynamic-code-sinks.js";
import { dualTag } from "./dual-tag.js";
import { scanOwaspSurvey, tagFinding } from "./index.js";
import { surveyToFinding, ssrfToFinding, dynamicCodeToFinding } from "../to-findings.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-owasp-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

const semgrepPresent = { probe: () => ({ name: "semgrep" as const, present: true, version: "1.0" }) };
const semgrepAbsent = { probe: () => ({ name: "semgrep" as const, present: false, version: null }) };

describe("dual OWASP 2021/2025 tagging", () => {
  it("maps SSRF A10-2021 to A01-2025 with a shift note", () => {
    const tags = dualTag("A10");
    expect(tags.owasp_2021).toBe("A10");
    expect(tags.owasp_2025).toBe("A01");
    expect(tags.reclassified).toBe(true);
    expect(tags.shiftNote).toMatch(/Broken Access Control/);
  });

  it("maps Vulnerable Components A06-2021 to Supply Chain A03-2025", () => {
    const tags = dualTag("A06");
    expect(tags.owasp_2025).toBe("A03");
  });

  it("keeps a stable category without a shift note", () => {
    const tags = dualTag("A01");
    expect(tags.owasp_2025).toBe("A01");
    expect(tags.reclassified).toBe(false);
  });
});

describe("survey rules", () => {
  it("flags template-literal SQL (A03 survey-level)", () => {
    const src = "const r = await db.query(`SELECT * FROM users WHERE id = ${userId}`);";
    const findings = scanSurveyRules(src, "db.ts");
    const f = findings.find((x) => x.finding_type === "sql-template-literal-injection");
    expect(f).toBeTruthy();
    expect(f!.category).toBe("A03");
  });

  it("flags TLS verification disabled (A05) as High", () => {
    const findings = scanSurveyRules(`process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`, "config.ts");
    const f = findings.find((x) => x.finding_type === "tls-verification-disabled");
    expect(f!.severity).toBe("high");
    expect(f!.category).toBe("A05");
  });

  it("flags a CDN script without SRI (A08)", () => {
    const findings = scanSurveyRules(`<script src="https://cdn.example.com/x.js"></script>`, "page.html");
    expect(findings.some((x) => x.finding_type === "cdn-script-missing-sri")).toBe(true);
  });

  it("flags a silent catch (A09)", () => {
    const findings = scanSurveyRules(`try { risky(); } catch (e) {}`, "a.ts");
    expect(findings.some((x) => x.finding_type === "silent-catch")).toBe(true);
  });
});

describe("shallow SSRF", () => {
  it("flags a fetch built from request input with no allowlist", () => {
    const src = `export async function GET(req) { return fetch(req.query.url); }`;
    const findings = scanSsrf(src, "proxy.ts");
    expect(findings[0]!.finding_type).toBe("shallow-ssrf-user-controlled-url");
  });

  it("does NOT flag a fetch to a string literal", () => {
    const findings = scanSsrf(`fetch("https://api.stripe.com/v1/charges")`, "pay.ts");
    expect(findings.length).toBe(0);
  });

  it("does NOT flag when an allowlist check is nearby", () => {
    const src = `
      export async function GET(req) {
        const url = req.query.url;
        if (!allowedHosts.includes(new URL(url).hostname)) throw new Error();
        return fetch(url);
      }
    `;
    expect(scanSsrf(src, "proxy.ts").length).toBe(0);
  });
});

describe("dynamic-code-execution sinks", () => {
  it("flags the string-eval primitive", () => {
    const findings = scanDynamicCodeSinks(`const r = ev` + `al(userInput);`, "run.ts");
    expect(findings.some((x) => x.sinkKind === "string-eval")).toBe(true);
  });

  it("flags document-write", () => {
    const findings = scanDynamicCodeSinks(`document.write(payload);`, "dom.ts");
    expect(findings.some((x) => x.sinkKind === "document-write")).toBe(true);
  });

  it("routes dynamic-code sinks to Inline (review-required-never-auto)", () => {
    const d = scanDynamicCodeSinks(`document.write(x);`, "dom.ts")[0]!;
    const finding = dynamicCodeToFinding(d, "public-facing");
    expect(finding.fix_class).toBe("inline");
  });
});

describe("every finding carries both OWASP tags", () => {
  it("surveyToFinding sets owasp_2021 + owasp_2025", () => {
    const tagged = tagFinding({
      finding_type: "tls-verification-disabled",
      category: "A05",
      severity: "high",
      confidence: 0.9,
      file: "c.ts",
      line: 1,
      detail: "x",
    });
    const f = surveyToFinding(tagged, "public-facing");
    expect(f.owasp_2021).toBe("A05");
    expect(f.owasp_2025).toBe("A02"); // misconfig rose to A02 in 2025
  });

  it("ssrfToFinding annotates A10-2021 as A01-2025", () => {
    const s = scanSsrf(`export async function GET(req){ return fetch(req.query.url); }`, "p.ts")[0]!;
    const f = ssrfToFinding(s, "public-facing");
    expect(f.owasp_2021).toBe("A10");
    expect(f.owasp_2025).toBe("A01");
  });
});

describe("primary-concern assignment (ownership matrix)", () => {
  it("assigns A05 findings primary=config-posture, survey secondary", () => {
    const tagged = tagFinding({
      finding_type: "tls-verification-disabled",
      category: "A05",
      severity: "high",
      confidence: 0.9,
      file: "c.ts",
      line: 1,
      detail: "x",
    });
    expect(tagged.primary_concern).toBe("config-posture");
    expect(tagged.secondary_concerns).toContain("owasp-survey");
  });

  it("keeps A03 injection survey-owned in v0.2", () => {
    const tagged = tagFinding({
      finding_type: "sql-template-literal-injection",
      category: "A03",
      severity: "high",
      confidence: 0.7,
      file: "db.ts",
      line: 1,
      detail: "x",
    });
    expect(tagged.primary_concern).toBe("owasp-survey");
  });
});

describe("orchestrator + Semgrep deferral signal", () => {
  it("survey baseline always runs; semgrepAvailable false when absent", () => {
    write("db.ts", "const r = await db.query(`SELECT * FROM t WHERE id=${id}`);");
    const result = scanOwaspSurvey(tmp, semgrepAbsent);
    expect(result.semgrepAvailable).toBe(false);
    expect(result.survey.length).toBeGreaterThan(0);
    expect(result.survey.every((f) => f.tags.owasp_2021 && f.tags.owasp_2025)).toBe(true);
  });

  it("credits Semgrep when present (A03 deep deferred to it)", () => {
    write("db.ts", "const r = await db.query(`SELECT * FROM t WHERE id=${id}`);");
    const result = scanOwaspSurvey(tmp, semgrepPresent);
    expect(result.semgrepAvailable).toBe(true);
    // survey-level A03 still runs in-house regardless.
    expect(result.survey.some((f) => f.category === "A03")).toBe(true);
  });
});
