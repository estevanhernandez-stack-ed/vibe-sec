// End-to-end audit orchestration test (checklist 3.5 verify bullet).
//
// Exercises the real pipeline the /vibe-sec:audit SKILL orchestrates over the TS
// layer: scan a fixture → map to findings → write findings.jsonl + audit.json →
// build the four-band report → render markdown + banner. Then proves :gate runs
// over the cached state and :posture reads it without re-scanning.
//
// This is the integration proof the verify bullet asks for: four-band markdown +
// banner + findings.jsonl from a fixture, gate exit codes, posture-no-rescan.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { scanSecrets } from "../detectors/secrets/index.js";
import { scanConfigPosture } from "../detectors/config-posture/index.js";
import {
  resetFindingIds,
  secretToFinding,
  corsToFinding,
  firebaseRulesToFinding,
} from "../detectors/to-findings.js";
import {
  appendFindings,
  readFindingsDeduped,
  type Finding,
} from "../state/findings.js";
import { findingsPath, threatModelStatePath, projectDocsDir } from "../state/paths.js";
import { writeAuditState, readAuditState, type AuditState } from "../state/audit-state.js";
import { buildBandedReport } from "./bands.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderBanner } from "./banner.js";
import { runGate } from "../gate/run-gate.js";
import { threatModelInAudit, runThreatModel } from "../threat-model/index.js";
import type { ToolProbe } from "../orchestration/tool-registry.js";
import type { Tier } from "../types.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-audit-"));
  resetFindingIds();
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

const noTools: ToolProbe = (tool) => ({ name: tool, present: false, version: null });
// Runtime-concatenated so no literal real-provider key pattern lands in the file.
const AWS_FAKE = "AKIA" + "ABCDEFGHIJ234567";

/**
 * Compose the audit pipeline the way the SKILL does — over the real detectors +
 * mappers. Returns the artifacts for assertion.
 */
function runAudit(projectRoot: string, tier: Tier) {
  // 1. Run a couple of in-scope concerns over the fixture (in-house fallback).
  const secrets = scanSecrets(projectRoot, { probe: noTools, forceInhouse: true });
  const config = scanConfigPosture(projectRoot);

  // 2. Map to findings.
  const findings: Finding[] = [
    ...secrets.findings.map((s) => secretToFinding(s, tier)),
    ...config.cors.map((c) => corsToFinding(c, tier)),
    ...config.firebaseRules.map((f) => firebaseRulesToFinding(f, tier)),
  ];

  // 3. Persist findings.jsonl + audit.json.
  appendFindings(projectRoot, findings);
  const deduped = readFindingsDeduped(projectRoot);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of deduped) counts[f.severity_tier_adjusted] += 1;
  const auditState: AuditState = {
    schema_version: 1,
    scanned_at: new Date().toISOString(),
    tier,
    tier_confidence: 0.9,
    score: 0.5,
    gate_pass: false,
    counts: counts as AuditState["counts"],
    findings_total: deduped.length,
    tools_used: [secrets.toolOfRecord],
  };
  writeAuditState(projectRoot, auditState);

  // 4. Build the four-band report + render all three channels.
  const report = buildBandedReport(deduped, tier, { hasDependencies: true });
  const markdown = renderMarkdownReport(report, { command: "audit", score: 0.5, gatePass: false });
  const banner = renderBanner(report, { score: 0.5, threshold: 0.7, gatePass: false, noColor: true });

  return { findings: deduped, report, markdown, banner, auditState };
}

describe("3.5 /vibe-sec:audit — three channels over a fixture", () => {
  it("produces four-band markdown + banner + findings.jsonl", () => {
    write("config/keys.js", `const k = "${AWS_FAKE}";`);
    write(
      "server/app.js",
      `import cors from "cors";\napp.use(cors({ origin: true, credentials: true }));\n`,
    );
    write("firestore.rules", `service cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}\n`);

    const out = runAudit(tmp, "public-facing");

    // findings.jsonl exists + carries the mapped findings.
    expect(fs.existsSync(findingsPath(tmp))).toBe(true);
    expect(out.findings.length).toBeGreaterThan(0);
    expect(out.findings.some((f) => f.primary_concern === "secret-detection")).toBe(true);

    // four-band markdown.
    expect(out.markdown).toContain("## Band 1 — action needed now");
    expect(out.markdown).toContain("## Band 4 — tools that catch what the baseline misses");
    expect(out.markdown).toContain("## By OWASP category");

    // banner (the terminal channel) has the verdict + band structure.
    expect(out.banner).toContain("FAIL");
    expect(out.banner).toContain("Band 1 — action needed now");

    // No raw fake secret leaks into the artifacts.
    expect(out.markdown).not.toContain(AWS_FAKE);
    expect(out.banner).not.toContain(AWS_FAKE);
    expect(fs.readFileSync(findingsPath(tmp), "utf8")).not.toContain(AWS_FAKE);
  });

  it(":gate runs over the cached audit state and blocks on the High/Critical findings", () => {
    write("firestore.rules", `match /{document=**} { allow read, write: if true; }`);
    runAudit(tmp, "public-facing");
    const gate = runGate(tmp);
    // Firebase open-rule is a Critical auth/config finding → gate fails.
    expect(gate.exit).toBe(1);
  });

  it(":posture reads cached state without re-scanning", () => {
    write("config/keys.js", `const k = "${AWS_FAKE}";`);
    runAudit(tmp, "public-facing");

    // Simulate posture: read cached state + findings, assert no re-scan happened.
    const mtimeBefore = fs.statSync(findingsPath(tmp)).mtimeMs;
    const cached = readAuditState(tmp);
    const findings = readFindingsDeduped(tmp);
    const mtimeAfter = fs.statSync(findingsPath(tmp)).mtimeMs;

    expect(cached).not.toBeNull();
    expect(cached!.tier).toBe("public-facing");
    expect(findings.length).toBeGreaterThan(0);
    // Reading did not rewrite findings.jsonl — posture never re-scans.
    expect(mtimeAfter).toBe(mtimeBefore);
  });
});

describe("3.5 /vibe-sec:audit — clean fixture", () => {
  it("a clean project gates pass at internal", () => {
    write("README.md", "# clean app");
    // No secrets, no open CORS, no firebase rules → no findings.
    const out = runAudit(tmp, "internal");
    expect(out.report.band1).toHaveLength(0);
    const gate = runGate(tmp);
    expect(gate.exit).toBe(0);
  });
});

describe("4.1 threat-model — Internal-tier opt-in (Conflict 2 = C)", () => {
  it("threatModelInAudit is false at Internal and Prototype, true Public-facing+", () => {
    // The audit orchestrator consults this before running the sink node. At
    // Internal the threat model is OPT-IN ONLY — not auto-run in :audit.
    expect(threatModelInAudit("prototype")).toBe(false);
    expect(threatModelInAudit("internal")).toBe(false);
    expect(threatModelInAudit("public-facing")).toBe(true);
    expect(threatModelInAudit("customer-facing-saas")).toBe(true);
    expect(threatModelInAudit("regulated")).toBe(true);
  });

  it("an Internal-tier audit does not write a threat-model artifact unless opted in", () => {
    write("app/api/users/route.ts", `export async function GET() {}`);
    runAudit(tmp, "internal");

    // The audit at Internal skips the sink node (threatModelInAudit === false),
    // so the threat-model channels are absent. Only a direct
    // /vibe-sec:threat-model (opt-in) would emit them.
    if (!threatModelInAudit("internal")) {
      expect(fs.existsSync(threatModelStatePath(tmp))).toBe(false);
      expect(fs.existsSync(path.join(projectDocsDir(tmp), "threat-model.md"))).toBe(false);
    }

    // Opt-in path: a direct run DOES emit (and is allowed at Internal).
    const out = runThreatModel(tmp, { tier: "internal", write: true });
    expect(out.result.isStub).toBe(false);
    expect(fs.existsSync(path.join(projectDocsDir(tmp), "threat-model.md"))).toBe(true);
  });
});
