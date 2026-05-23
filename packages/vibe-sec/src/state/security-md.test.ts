// SECURITY.md generator tests (checklist 4.3 verify bullet).
//
// Proves: SECURITY.md is generated with an ASVS citation, the tier graduating
// guidance is present, honeytokens appear as a RECOMMENDATION (not generated),
// and emitSecurityMd writes to docs/SECURITY.md.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { generateSecurityMd, emitSecurityMd } from "./security-md.js";
import { securityMdPath } from "./paths.js";
import { makeFinding, type Finding } from "./findings.js";

describe("4.3 SECURITY.md — ASVS citation (the load-bearing claim)", () => {
  it("cites ASVS for the tier explicitly", () => {
    const md = generateSecurityMd({ tier: "public-facing", appName: "test-app" });
    expect(md).toContain("OWASP ASVS L2");
    expect(md).toContain("OWASP Application Security Verification Standard");
    // The standards-floor citation line.
    expect(md).toContain("OWASP ASVS Level 2 (L2)");
  });

  it("cites the Regulated floor as ASVS L3 + NIST SSDF + SBOM", () => {
    const md = generateSecurityMd({ tier: "regulated", appName: "test-app" });
    expect(md).toContain("ASVS L3 + NIST SSDF + SBOM");
    expect(md).toContain("NIST SSDF practices (PO, PS, PW, RV)");
  });

  it("includes the pass-bar percentage for the tier", () => {
    const md = generateSecurityMd({ tier: "customer-facing-saas" });
    expect(md).toContain("weighted score ≥ 80%");
  });
});

describe("4.3 SECURITY.md — graduating guidance", () => {
  it("names the next tier and its ASVS floor", () => {
    const md = generateSecurityMd({ tier: "internal", appName: "test-app" });
    expect(md).toContain("## Graduating guidance");
    expect(md).toContain("Public-facing");
    expect(md).toContain("OWASP ASVS L2");
  });

  it("at Regulated, says it's the highest tier with no next-tier story", () => {
    const md = generateSecurityMd({ tier: "regulated" });
    expect(md).toContain("This is the highest tier");
  });
});

describe("4.3 SECURITY.md — honeytokens are a recommendation, not generated", () => {
  it("surfaces honeytokens in the complements section framed as guidance", () => {
    const md = generateSecurityMd({ tier: "public-facing" });
    expect(md).toContain("Honeytokens / canaries");
    expect(md).toContain("a recommendation, not a generated artifact");
    // It must NOT emit any actual token value.
    expect(md).not.toMatch(/canarytoken[:=]\s*\S+/i);
  });
});

describe("4.3 SECURITY.md — posture summary from findings", () => {
  it("summarizes finding counts by severity when findings are supplied", () => {
    const findings: Finding[] = [
      makeFinding({
        id: "f1",
        primary_concern: "secret-detection",
        severity_base: "critical",
        severity_tier_adjusted: "critical",
        confidence: 0.9,
        finding_type: "x",
        title: "x",
        tier: "public-facing",
        fix_class: "inline",
        tool_of_record: "in-house",
      }),
    ];
    const md = generateSecurityMd({ tier: "public-facing", findings });
    expect(md).toContain("**1** finding(s)");
    expect(md).toContain("1 critical");
  });

  it("notes 'run audit' when no findings recorded", () => {
    const md = generateSecurityMd({ tier: "internal", findings: [] });
    expect(md).toContain("Run `/vibe-sec:audit`");
  });
});

describe("4.3 SECURITY.md — emit to docs/SECURITY.md", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-secmd-"));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("writes the file to docs/SECURITY.md and returns the path", () => {
    const written = emitSecurityMd(tmp, { tier: "public-facing", appName: "fixture-app" });
    expect(written).toBe(securityMdPath(tmp));
    expect(fs.existsSync(written)).toBe(true);
    const content = fs.readFileSync(written, "utf8");
    expect(content).toContain("# Security policy");
    expect(content).toContain("OWASP ASVS L2");
  });
});
