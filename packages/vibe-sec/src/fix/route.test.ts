import { describe, it, expect } from "vitest";
import { routeFix, destructiveKindOf, isDestructive, AUTO_CONFIDENCE, STAGE_CONFIDENCE } from "./route.js";
import { makeFinding, type Finding } from "../state/findings.js";
import type { Concern } from "../types.js";

function f(partial: Partial<Finding> & { primary_concern: Concern; finding_type: string; confidence: number }): Finding {
  return makeFinding({
    id: "test-1",
    severity_base: "high",
    severity_tier_adjusted: "high",
    tier: "public-facing",
    title: partial.finding_type,
    fix_class: "auto",
    tool_of_record: "in-house",
    ...partial,
  });
}

describe("3.5 fix-router — confidence-tier routing", () => {
  it("≥0.90 confidence → auto (when non-destructive)", () => {
    const d = routeFix(f({ primary_concern: "config-posture", finding_type: "missing-security-header", confidence: 0.95 }));
    expect(d.fixClass).toBe("auto");
    expect(d.override).toBeNull();
  });

  it("0.70-0.89 confidence → stage (when non-destructive)", () => {
    const d = routeFix(f({ primary_concern: "supply-chain", finding_type: "floating-version-pin", confidence: 0.8 }));
    expect(d.fixClass).toBe("stage");
    expect(d.override).toBeNull();
  });

  it("<0.70 confidence → inline (when non-destructive)", () => {
    const d = routeFix(f({ primary_concern: "supply-chain", finding_type: "floating-version-pin", confidence: 0.5 }));
    expect(d.fixClass).toBe("inline");
    expect(d.override).toBeNull();
  });

  it("threshold boundaries are inclusive on the high side", () => {
    expect(routeFix(f({ primary_concern: "config-posture", finding_type: "x", confidence: AUTO_CONFIDENCE })).fixClass).toBe("auto");
    expect(routeFix(f({ primary_concern: "config-posture", finding_type: "x", confidence: STAGE_CONFIDENCE })).fixClass).toBe("stage");
    expect(routeFix(f({ primary_concern: "config-posture", finding_type: "x", confidence: STAGE_CONFIDENCE - 0.01 })).fixClass).toBe("inline");
  });

  it("advisory / inform-only findings pass through unrouted", () => {
    const adv = routeFix(f({ primary_concern: "rate-limiting", finding_type: "no-abuse-monitoring", confidence: 0.95, fix_class: "advisory" }));
    expect(adv.fixClass).toBe("advisory");
  });
});

describe("3.5 fix-router — destructive-action overrides NEVER auto", () => {
  it("secret rotation never auto, even at 0.99 confidence", () => {
    const d = routeFix(f({ primary_concern: "secret-detection", finding_type: "aws-access-key", confidence: 0.99 }));
    expect(d.fixClass).not.toBe("auto");
    expect(d.fixClass).toBe("inline");
    expect(d.override?.kind).toBe("secret-rotation");
  });

  it("auth-logic changes never auto", () => {
    const d = routeFix(f({ primary_concern: "auth-model", finding_type: "idor-direct-object-ref", confidence: 0.95 }));
    expect(d.fixClass).not.toBe("auto");
    expect(d.override).not.toBeNull();
  });

  it("auth-middleware adds stage minimum, never auto", () => {
    const d = routeFix(f({ primary_concern: "auth-model", finding_type: "admin-route-no-auth", confidence: 0.99 }));
    expect(d.fixClass).toBe("stage");
    expect(d.override?.kind).toBe("auth-middleware-add");
  });

  it("JWT/session-secret regen never auto", () => {
    const d = routeFix(f({ primary_concern: "crypto-pii", finding_type: "jwt-weak-secret", confidence: 0.95 }));
    expect(d.fixClass).not.toBe("auto");
    expect(d.override?.kind).toBe("jwt-session-secret-regen");
  });

  it("RLS / Firestore-rules / policy changes stage, never auto", () => {
    const d = routeFix(f({ primary_concern: "config-posture", finding_type: "firestore-permissive-rule", confidence: 0.99 }));
    expect(d.fixClass).not.toBe("auto");
    expect(d.override?.kind).toBe("rls-policy-change");
  });

  it("password-hash migration never auto", () => {
    const d = routeFix(f({ primary_concern: "crypto-pii", finding_type: "weak-password-hash", confidence: 0.95 }));
    expect(d.fixClass).toBe("inline");
    expect(d.override?.kind).toBe("password-hash-migration");
  });

  it("git-history rewrite is inline-runbook-only", () => {
    const d = routeFix(f({ primary_concern: "secret-detection", finding_type: "history-secret-rewrite", confidence: 0.99 }));
    // secret-detection short-circuits to rotation first; assert it's never auto.
    expect(d.fixClass).not.toBe("auto");
    expect(d.override).not.toBeNull();
  });

  it("the full destructive set is recognized + none route to auto at max confidence", () => {
    const cases: Array<{ concern: Concern; ft: string }> = [
      { concern: "secret-detection", ft: "stripe-secret-key" },
      { concern: "auth-model", ft: "tenant-isolation-gap" },
      { concern: "auth-model", ft: "admin-route-no-role" },
      { concern: "crypto-pii", ft: "jwt-alg-none" },
      { concern: "config-posture", ft: "supabase-rls-policy-true" },
      { concern: "crypto-pii", ft: "plaintext-password-compare" },
    ];
    for (const c of cases) {
      const finding = f({ primary_concern: c.concern, finding_type: c.ft, confidence: 1 });
      expect(isDestructive(finding), `${c.ft} should be destructive`).toBe(true);
      expect(routeFix(finding).fixClass, `${c.ft} must not auto`).not.toBe("auto");
    }
  });

  it("non-destructive config + supply findings stay auto-eligible", () => {
    expect(isDestructive(f({ primary_concern: "config-posture", finding_type: "missing-security-header", confidence: 0.95 }))).toBe(false);
    expect(isDestructive(f({ primary_concern: "supply-chain", finding_type: "floating-version-pin", confidence: 0.95 }))).toBe(false);
  });
});

describe("3.5 destructiveKindOf — mapping", () => {
  it("maps secret-detection findings to secret-rotation", () => {
    expect(destructiveKindOf(f({ primary_concern: "secret-detection", finding_type: "anything", confidence: 0.9 }))).toBe("secret-rotation");
  });
  it("returns null for plain config-header findings", () => {
    expect(destructiveKindOf(f({ primary_concern: "config-posture", finding_type: "missing-hsts", confidence: 0.9 }))).toBeNull();
  });
});
