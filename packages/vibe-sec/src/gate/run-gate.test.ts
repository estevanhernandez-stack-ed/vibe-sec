import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runGate, foldConcernResults, buildAnnotations } from "./run-gate.js";
import { appendFindings, makeFinding, type Finding } from "../state/findings.js";
import { writeAuditState, type AuditState } from "../state/audit-state.js";
import { evaluateGate } from "../scoring/weighted-score.js";
import type { Concern, Severity, Tier } from "../types.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-gate-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function mk(concern: Concern, sev: Severity, tier: Tier = "public-facing"): Finding {
  return makeFinding({
    id: `${concern}-${sev}-${Math.random()}`,
    primary_concern: concern,
    severity_base: sev,
    severity_tier_adjusted: sev,
    confidence: 0.9,
    finding_type: "x",
    title: `${concern} ${sev}`,
    description: "d",
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    file: "src/x.ts",
    line: 4,
  });
}

function seedAudit(tier: Tier, gatePass = false): void {
  const state: AuditState = {
    schema_version: 1,
    scanned_at: new Date().toISOString(),
    tier,
    tier_confidence: 0.9,
    score: 0.5,
    gate_pass: gatePass,
    counts: { critical: 0, high: 0, medium: 0, low: 0 },
    findings_total: 0,
    tools_used: ["in-house"],
  };
  writeAuditState(tmp, state);
}

describe("3.5 gate — exit codes", () => {
  it("exits 1 on a High in a mandatory concern (public-facing: auth-model)", () => {
    seedAudit("public-facing");
    appendFindings(tmp, [mk("auth-model", "high")]);
    const res = runGate(tmp);
    expect(res.exit).toBe(1);
    expect(res.pass).toBe(false);
    expect(res.blockingConcerns).toContain("auth-model");
  });

  it("exits 1 on a Critical in a mandatory concern", () => {
    seedAudit("public-facing");
    appendFindings(tmp, [mk("config-posture", "critical")]);
    const res = runGate(tmp);
    expect(res.exit).toBe(1);
    expect(res.blockingConcerns).toContain("config-posture");
  });

  it("exits 0 when clean (no findings, score meets the bar)", () => {
    seedAudit("internal");
    // No findings → every in-scope concern passes at 1.0 → score 1.0 ≥ 0.55.
    const res = runGate(tmp);
    expect(res.exit).toBe(0);
    expect(res.pass).toBe(true);
  });

  it("exits 0 when only Low/Medium findings keep the score above the bar", () => {
    seedAudit("internal");
    appendFindings(tmp, [mk("config-posture", "low"), mk("supply-chain", "low")]);
    const res = runGate(tmp);
    // Low findings don't trip the amplifier; internal bar is 55%.
    expect(res.exit).toBe(0);
  });

  it("exits 2 on error — no cached audit and no pinned tier", () => {
    const res = runGate(tmp);
    expect(res.exit).toBe(2);
    expect(res.reasons[0]).toContain("no cached audit");
  });

  it("a pinned tier override lets the gate run without a cached audit", () => {
    appendFindings(tmp, [mk("auth-model", "high")]);
    const res = runGate(tmp, { tier: "public-facing" });
    expect(res.exit).toBe(1); // ran, and blocked on the High
  });
});

describe("3.5 gate — GitHub Actions annotations", () => {
  it("emits ::error:: annotations for blocking findings + the verdict when GITHUB_ACTIONS", () => {
    seedAudit("public-facing");
    appendFindings(tmp, [mk("auth-model", "critical")]);
    const res = runGate(tmp, { githubActions: true });
    expect(res.annotations.some((a) => a.startsWith("::error"))).toBe(true);
    expect(res.annotations.some((a) => a.includes("file=src/x.ts") && a.includes("line=4"))).toBe(true);
    expect(res.annotations.some((a) => a.includes("gate FAIL"))).toBe(true);
  });

  it("emits a ::notice:: pass annotation when clean", () => {
    seedAudit("internal");
    const res = runGate(tmp, { githubActions: true });
    expect(res.annotations.some((a) => a.startsWith("::notice::") && a.includes("PASS"))).toBe(true);
  });

  it("emits no annotations when githubActions is false", () => {
    seedAudit("public-facing");
    appendFindings(tmp, [mk("auth-model", "high")]);
    expect(runGate(tmp).annotations).toHaveLength(0);
  });
});

describe("3.5 gate — concern fold + Regulated 'no High anywhere'", () => {
  it("folds findings to in-scope concern results only", () => {
    const results = foldConcernResults([mk("auth-model", "high")], "public-facing");
    expect(results.every((r) => r.concern !== "tier-thresholds")).toBe(true);
    expect(results.find((r) => r.concern === "auth-model")?.severities).toContain("high");
  });

  it("Regulated fails on a High in any detector concern (Conflict 3 = C)", () => {
    // supply-chain isn't 'mandatory' below Regulated, but Regulated = no High anywhere.
    const results = foldConcernResults([mk("supply-chain", "high", "regulated")], "regulated");
    const gate = evaluateGate("regulated", results);
    expect(gate.pass).toBe(false);
    expect(gate.blockingConcerns).toContain("supply-chain");
  });
});

describe("3.5 buildAnnotations — direct", () => {
  it("notice-only on pass", () => {
    const gate = { exit: 0 as const, pass: true, score: 0.9, threshold: 0.7, blockingConcerns: [], reasons: [] };
    const out = buildAnnotations(gate, [], "public-facing");
    expect(out).toHaveLength(1);
    expect(out[0]).toContain("PASS");
  });
});
