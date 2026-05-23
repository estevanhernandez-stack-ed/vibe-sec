import { describe, it, expect } from "vitest";
import { classifyTier, type RepoSignal } from "./classify-tier.js";

const deploySignal: RepoSignal = {
  name: "vercel.json present",
  weight: "strong",
  promotes: "public-facing",
};
const stripeSignal: RepoSignal = {
  name: "stripe + STRIPE_SECRET_KEY",
  weight: "strong",
  promotes: "customer-facing-saas",
};

describe("tier classifier", () => {
  it("inherits Vibe Test tier when present and no higher promotion", () => {
    const r = classifyTier({
      inheritedTier: "public-facing",
      inheritedModifiers: ["has-auth"],
      signals: [],
    });
    expect(r.tier).toBe("public-facing");
    expect(r.source).toBe("inherited");
    expect(r.modifiers).toContain("has-auth");
    expect(r.tierDriftNote).toBeNull();
  });

  it("promotes above the inherited tier when a security signal fires, logging drift", () => {
    const r = classifyTier({
      inheritedTier: "public-facing",
      signals: [stripeSignal],
    });
    expect(r.tier).toBe("customer-facing-saas");
    expect(r.source).toBe("promoted");
    expect(r.tierDriftNote).not.toBeNull();
    expect(r.tierDriftNote?.tier_promoted_from).toBe("public-facing");
    expect(r.tierDriftNote?.tier_promoted_to).toBe("customer-facing-saas");
    expect(r.tierDriftNote?.promoted_by).toContain("stripe");
  });

  it("self-scans to public-facing on one strong deploy signal when no inheritance", () => {
    const r = classifyTier({ inheritedTier: null, signals: [deploySignal] });
    expect(r.tier).toBe("public-facing");
    expect(r.source).toBe("self-scan");
  });

  it("requires 2 medium signals to promote (1 medium does not)", () => {
    const oneMedium: RepoSignal = {
      name: "fly.toml",
      weight: "medium",
      promotes: "public-facing",
    };
    const single = classifyTier({ inheritedTier: null, signals: [oneMedium] });
    expect(single.tier).toBe("prototype");

    const twoMedium = classifyTier({
      inheritedTier: null,
      signals: [oneMedium, { ...oneMedium, name: "firebase prod alias" }],
    });
    expect(twoMedium.tier).toBe("public-facing");
  });

  it("respects an explicit builder override above all signals", () => {
    const r = classifyTier({
      inheritedTier: null,
      signals: [stripeSignal],
      override: "prototype",
    });
    expect(r.tier).toBe("prototype");
    expect(r.source).toBe("override");
    expect(r.confidence).toBe(1);
  });

  it("prototype-floor hints cap a weak self-scan at prototype", () => {
    const weak: RepoSignal = {
      name: "NEXT_PUBLIC_ var",
      weight: "weak",
      promotes: "public-facing",
    };
    const r = classifyTier({
      inheritedTier: null,
      signals: [weak],
      prototypeFloorHints: 3,
    });
    expect(r.tier).toBe("prototype");
  });

  it("never throws on empty input — degrades to prototype", () => {
    const r = classifyTier({ inheritedTier: null, signals: [] });
    expect(r.tier).toBe("prototype");
    expect(r.source).toBe("self-scan");
  });
});
