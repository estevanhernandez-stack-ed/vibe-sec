import { describe, it, expect } from "vitest";
import { classifyTier, type RepoSignal } from "./classify-tier.js";

const deploySignal: RepoSignal = {
  name: "vercel.json present",
  weight: "strong",
  promotes: "public-facing",
  dimension: "deploy",
};
const stripeSignal: RepoSignal = {
  name: "stripe + STRIPE_SECRET_KEY",
  weight: "strong",
  promotes: "customer-facing-saas",
};

// The three legs of the compound customer-facing-saas rule (spec §2.3).
const userDataSignal: RepoSignal = {
  name: "firebase-admin (server-side user data)",
  weight: "medium",
  promotes: "public-facing",
  dimension: "persistent-user-data",
};
const adminRoleSignal: RepoSignal = {
  name: "admin-role surface (role-gated administration)",
  weight: "medium",
  promotes: "public-facing",
  dimension: "admin-role",
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
    // deploy → public-facing is the base classification, NOT a security drift.
    expect(r.tierDriftNote).toBeNull();
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

  // ── Compound customer-facing-saas promotion (spec §2.3) ──────────────────
  // The WSYATM dogfood gap: a deployed app that stores real user PII AND has an
  // admin surface is customer-facing-saas, even when no single signal is strong
  // enough to count-promote it. The fix is the distinct-dimension compound rule.
  describe("data-sensitivity compound promotion", () => {
    it("promotes a deployed app with persisted user PII + admin roles to customer-facing-saas (the WSYATM shape)", () => {
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, userDataSignal, adminRoleSignal],
      });
      expect(r.tier).toBe("customer-facing-saas");
      // The lift above deploy-detection is a logged, builder-visible promotion.
      expect(r.source).toBe("promoted");
      expect(r.tierDriftNote).not.toBeNull();
      expect(r.tierDriftNote?.tier_promoted_from).toBe("public-facing");
      expect(r.tierDriftNote?.tier_promoted_to).toBe("customer-facing-saas");
      // The drift note names the user-data + admin signals that drove it.
      expect(r.tierDriftNote?.promoted_by).toContain("user data");
      expect(r.tierDriftNote?.promoted_by).toContain("admin-role");
    });

    it("a multi-tenant signal substitutes for the admin-role leg (confirmatory)", () => {
      const tenantSignal: RepoSignal = {
        name: "tenant_id FK on user tables + RLS",
        weight: "medium",
        promotes: "public-facing",
        dimension: "multi-tenant",
      };
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, userDataSignal, tenantSignal],
      });
      expect(r.tier).toBe("customer-facing-saas");
      expect(r.tierDriftNote).not.toBeNull();
    });

    // ── Over-promotion guards. Precision is the whole game. ────────────────

    it("does NOT promote a bare prototype with no auth + no persistence", () => {
      // A scratch app: nothing deployed, no user data, no admin surface.
      const r = classifyTier({
        inheritedTier: null,
        signals: [
          {
            name: "NEXT_PUBLIC_ var",
            weight: "weak",
            promotes: "public-facing",
          },
        ],
      });
      expect(r.tier).toBe("prototype");
      expect(r.tierDriftNote).toBeNull();
    });

    it("does NOT promote an internal tool (deploy + user data but no admin/tenant surface)", () => {
      // An internal CRUD tool: ships + stores data, but no role-gated admin
      // surface. Two of three legs is not enough — stays public-facing.
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, userDataSignal],
      });
      expect(r.tier).toBe("public-facing");
      expect(r.tierDriftNote).toBeNull();
    });

    it("does NOT promote a public marketing site (deploy + admin CMS but no persisted user data)", () => {
      // A deployed marketing site with a CMS admin login, but no user PII at
      // rest. Missing the persistent-user-data leg → stays public-facing.
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, adminRoleSignal],
      });
      expect(r.tier).toBe("public-facing");
      expect(r.tierDriftNote).toBeNull();
    });

    it("does NOT promote on two medium signals in the SAME dimension (guards count-only over-promotion)", () => {
      // Two persistent-user-data signals, deployed — but no admin/tenant leg.
      // The generic ≥2-medium rule would lift to public-facing (correct), but
      // the compound rule must NOT see this as customer-facing-saas.
      const secondUserData: RepoSignal = {
        name: "Firestore/Storage security rules",
        weight: "medium",
        promotes: "public-facing",
        dimension: "persistent-user-data",
      };
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, userDataSignal, secondUserData],
      });
      expect(r.tier).toBe("public-facing");
      expect(r.tierDriftNote).toBeNull();
    });

    it("does NOT promote without a deploy signal (undeployed app with user data + admin stays internal/prototype)", () => {
      // Local-only app: user data + admin surface but no deploy config. Missing
      // the deploy leg → the compound rule must not fire. The two mediums still
      // count-promote to public-facing, but never to customer-facing-saas.
      const r = classifyTier({
        inheritedTier: null,
        signals: [userDataSignal, adminRoleSignal],
      });
      expect(r.tier).toBe("public-facing");
      expect(r.tierDriftNote).toBeNull();
    });

    it("a builder override still hard-caps below the compound promotion", () => {
      const r = classifyTier({
        inheritedTier: null,
        signals: [deploySignal, userDataSignal, adminRoleSignal],
        override: "internal",
      });
      expect(r.tier).toBe("internal");
      expect(r.source).toBe("override");
    });
  });
});
