import { describe, it, expect } from "vitest";
import {
  weightedScore,
  evaluateGate,
  isInScope,
  mandatoryConcerns,
  TIER_THRESHOLDS,
  TIER_ASVS_LABEL,
  type ConcernResult,
} from "./weighted-score.js";

describe("weighted score — denominator scoping", () => {
  it("excludes skipped concerns from the denominator", () => {
    // At Prototype, owasp-survey/crypto-pii/config-posture/etc. are skip.
    // Two in-scope concerns at 1.0 and 0.0 should average to 0.5, not be
    // diluted by skipped concerns sitting at 0.
    const results: ConcernResult[] = [
      { concern: "secret-detection", rawPassFraction: 1.0, severities: [] },
      { concern: "auth-model", rawPassFraction: 0.0, severities: [] },
      // These are skip at prototype — must NOT enter the denominator:
      { concern: "owasp-survey", rawPassFraction: 0.0, severities: [] },
      { concern: "config-posture", rawPassFraction: 0.0, severities: [] },
    ];
    const r = weightedScore("prototype", results);
    expect(r.inScopeConcerns.sort()).toEqual(["auth-model", "secret-detection"]);
    expect(r.score).toBeCloseTo(0.5, 5);
  });

  it("isInScope reflects the scope grid", () => {
    expect(isInScope("owasp-survey", "prototype")).toBe(false);
    expect(isInScope("owasp-survey", "public-facing")).toBe(true);
    expect(isInScope("secret-detection", "prototype")).toBe(true);
    // tier-thresholds owns no detectors → never in scope.
    expect(isInScope("tier-thresholds", "regulated")).toBe(false);
  });

  it("applies the severity amplifier per concern before summation", () => {
    // One concern 0.97-clean with a Critical → capped 0.5; one fully clean 1.0.
    const results: ConcernResult[] = [
      { concern: "secret-detection", rawPassFraction: 0.97, severities: ["critical"] },
      { concern: "auth-model", rawPassFraction: 1.0, severities: [] },
    ];
    const r = weightedScore("prototype", results);
    expect(r.score).toBeCloseTo((0.5 + 1.0) / 2, 5);
  });
});

describe("tier curve maps to ASVS", () => {
  it("uses the 30/55/70/80/90 thresholds", () => {
    expect(TIER_THRESHOLDS.prototype).toBe(0.3);
    expect(TIER_THRESHOLDS.internal).toBe(0.55);
    expect(TIER_THRESHOLDS["public-facing"]).toBe(0.7);
    expect(TIER_THRESHOLDS["customer-facing-saas"]).toBe(0.8);
    expect(TIER_THRESHOLDS.regulated).toBe(0.9);
  });

  it("labels each tier with its ASVS floor", () => {
    expect(TIER_ASVS_LABEL.internal).toContain("L1");
    expect(TIER_ASVS_LABEL["public-facing"]).toContain("L2");
    expect(TIER_ASVS_LABEL["customer-facing-saas"]).toContain("L3");
    expect(TIER_ASVS_LABEL.regulated).toContain("SSDF");
  });
});

describe("gate decision rules", () => {
  it("Public-facing gate fails on High in a mandatory concern even at ≥70%", () => {
    // Make the score high (≥70%) but plant a High in mandatory concern auth-model.
    const results: ConcernResult[] = [
      { concern: "owasp-survey", rawPassFraction: 1.0, severities: [] },
      { concern: "config-posture", rawPassFraction: 1.0, severities: [] },
      { concern: "rate-limiting", rawPassFraction: 1.0, severities: [] },
      // auth-model is mandatory at public-facing; one High → amplifier caps 0.8,
      // overall score still well above 0.7, but the hard rule must fail it.
      { concern: "auth-model", rawPassFraction: 1.0, severities: ["high"] },
      { concern: "secret-detection", rawPassFraction: 1.0, severities: [] },
      { concern: "dependency-cve", rawPassFraction: 1.0, severities: [] },
      { concern: "crypto-pii", rawPassFraction: 1.0, severities: [] },
      { concern: "supply-chain", rawPassFraction: 1.0, severities: [] },
    ];
    const gate = evaluateGate("public-facing", results);
    expect(gate.score).toBeGreaterThanOrEqual(0.7);
    expect(gate.pass).toBe(false);
    expect(gate.exit).toBe(1);
    expect(gate.blockingConcerns).toContain("auth-model");
  });

  it("Public-facing gate passes when clean and above threshold", () => {
    const results: ConcernResult[] = [
      { concern: "owasp-survey", rawPassFraction: 1.0, severities: [] },
      { concern: "config-posture", rawPassFraction: 1.0, severities: [] },
      { concern: "rate-limiting", rawPassFraction: 1.0, severities: [] },
      { concern: "auth-model", rawPassFraction: 1.0, severities: [] },
      { concern: "secret-detection", rawPassFraction: 1.0, severities: [] },
      { concern: "dependency-cve", rawPassFraction: 1.0, severities: [] },
      { concern: "crypto-pii", rawPassFraction: 1.0, severities: [] },
      { concern: "supply-chain", rawPassFraction: 1.0, severities: [] },
    ];
    const gate = evaluateGate("public-facing", results);
    expect(gate.pass).toBe(true);
    expect(gate.exit).toBe(0);
  });

  it("Prototype fails on a Critical in secret-detection regardless of score", () => {
    const results: ConcernResult[] = [
      { concern: "secret-detection", rawPassFraction: 1.0, severities: ["critical"] },
      { concern: "auth-model", rawPassFraction: 1.0, severities: [] },
    ];
    const gate = evaluateGate("prototype", results);
    expect(gate.pass).toBe(false);
    expect(gate.blockingConcerns).toContain("secret-detection");
  });

  it("Regulated treats every detector concern as mandatory (no High anywhere)", () => {
    const mand = mandatoryConcerns("regulated");
    expect(mand).toContain("secret-detection");
    expect(mand).toContain("supply-chain");
    expect(mand).not.toContain("threat-model");
  });

  it("fails on score below threshold even when clean", () => {
    const results: ConcernResult[] = [
      { concern: "secret-detection", rawPassFraction: 0.2, severities: [] },
      { concern: "auth-model", rawPassFraction: 0.2, severities: [] },
    ];
    const gate = evaluateGate("prototype", results);
    expect(gate.score).toBeLessThan(0.3);
    expect(gate.pass).toBe(false);
  });
});
