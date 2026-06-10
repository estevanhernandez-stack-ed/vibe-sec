// Tier classifier (spec §2.3, synthesis §Detection; research:
// security-tier-thresholds.md). Inherit-first, scan-second.
//
//   1. If a fresh handshake supplies a tier, inherit it, then allow a
//      security-specific PROMOTION (explicit, logged via tier_drift_note).
//      REALITY CHECK (GAP-07, 2026-06-09): Vibe Test's artifact schema v1
//      carries NO classification block, so inheritedTier is always null
//      today — every run takes the self-scan path, and the audit banner
//      says so. The inherit path below stays live so it activates
//      unmodified when the core-owned v2 contract adds a tier
//      (vibe-plugins docs/spec-bank/plugin-core-phase2.md).
//   2. Otherwise self-scan the repo signals and fuse them into a tier.
//
// This file owns the signal-fusion math. The Vibe Test read lives in
// composition/vibe-test.ts; this module accepts an already-parsed handshake so
// it stays pure + testable.

import { type Tier, ALL_TIERS } from "../types.js";

export type SignalWeight = "strong" | "medium" | "weak";

/**
 * The data-sensitivity dimension a signal evidences (spec §2.3, research
 * "payment/PII integration → Customer-facing SaaS"). The customer-facing
 * promotion is precision-gated on the *combination* of distinct dimensions —
 * real user-data-at-stake — not on a raw count of medium signals. A bare
 * "has a database" app does not promote; it must show persisted user data AND
 * an admin-role surface AND a deploy/public signal.
 */
export type DataSensitivityDimension =
  | "deploy" // ships somewhere public-facing (deploy/hosting config)
  | "persistent-user-data" // stores real user PII / accounts (Firestore users, auth-backed records, payment)
  | "admin-role" // has an admin / role-gated surface (other people's data is administered)
  | "multi-tenant"; // tenant/org scoping (confirmatory)

/** A repo signal the self-scan can detect (research signal tables). */
export interface RepoSignal {
  name: string;
  weight: SignalWeight;
  /** Which tier ceiling this signal pushes toward. */
  promotes: Tier;
  /**
   * Optional data-sensitivity dimension this signal evidences. Used by the
   * compound customer-facing-saas promotion rule (spec §2.3). Signals without a
   * dimension only participate in the generic count-based promotion.
   */
  dimension?: DataSensitivityDimension;
}

/** Inputs to the classifier — already gathered by the caller. */
export interface ClassifyInput {
  /** Inherited tier from Vibe Test, when present + fresh. null = self-scan. */
  inheritedTier: Tier | null;
  /** Inherited context modifiers, passed through. */
  inheritedModifiers?: string[];
  /** Detected repo signals for the self-scan / promotion path. */
  signals: RepoSignal[];
  /** Explicit builder override (profile.json shared.deployment_context). */
  override?: Tier | null;
  /** Prototype-floor hints (no README, no tests, no deploy config, young repo). */
  prototypeFloorHints?: number;
}

export interface ClassifyResult {
  tier: Tier;
  confidence: number;
  modifiers: string[];
  /** How the tier was reached — inherit / self-scan / promoted / override. */
  source: "inherited" | "self-scan" | "promoted" | "override";
  /** Populated only when a security promotion fired above the inherited tier. */
  tierDriftNote: TierDriftNote | null;
  /** Human-readable signal list for the "why this tier?" banner. */
  rationale: string[];
}

export interface TierDriftNote {
  tier_promoted_from: Tier;
  tier_promoted_to: Tier;
  promoted_by: string;
}

const TIER_RANK: Record<Tier, number> = {
  prototype: 0,
  internal: 1,
  "public-facing": 2,
  "customer-facing-saas": 3,
  regulated: 4,
};

function rankToTier(rank: number): Tier {
  const clamped = Math.max(0, Math.min(ALL_TIERS.length - 1, rank));
  return ALL_TIERS[clamped]!;
}

function higher(a: Tier, b: Tier): Tier {
  return TIER_RANK[a] >= TIER_RANK[b] ? a : b;
}

/**
 * The compound customer-facing-saas promotion (spec §2.3, research
 * "payment/PII integration → Customer-facing SaaS"). Precision is the whole
 * game: promotion fires only when the repo evidences real user-data-at-stake
 * across THREE distinct dimensions —
 *
 *   (a) deploy / public-facing signal           AND
 *   (b) persistent user data (PII / accounts / payment) AND
 *   (c) an admin-role surface.
 *
 * This is deliberately stricter than the generic "≥2 medium" count: two medium
 * signals in the SAME dimension (e.g. a deployed app with two deploy configs,
 * or a database app with no admin surface) must NOT promote. The guard is the
 * distinct-dimension requirement — a bare prototype, an internal tool, and a
 * public marketing site each fail it because they lack one of the three legs.
 *
 * `multi-tenant` is confirmatory only (research): it can substitute for the
 * admin-role leg when persistent-user-data + deploy are both present, since a
 * tenant-scoped app administers other people's data by construction.
 */
function compoundCustomerFacing(signals: readonly RepoSignal[]): {
  fires: boolean;
  by: string[];
} {
  const inDim = (d: DataSensitivityDimension) =>
    signals.filter((s) => s.dimension === d);
  const deploy = inDim("deploy");
  const userData = inDim("persistent-user-data");
  const adminRole = inDim("admin-role");
  const multiTenant = inDim("multi-tenant");

  const hasDeploy = deploy.length > 0;
  const hasUserData = userData.length > 0;
  // Admin surface OR a multi-tenant signal (which implies administered data).
  const hasAdminSurface = adminRole.length > 0 || multiTenant.length > 0;

  const fires = hasDeploy && hasUserData && hasAdminSurface;
  if (!fires) return { fires: false, by: [] };

  const by = [
    ...deploy,
    ...userData,
    ...(adminRole.length > 0 ? adminRole : multiTenant),
  ].map((s) => s.name);
  return { fires: true, by };
}

/**
 * Promotion rule (research): ≥1 Strong OR ≥2 Medium signals toward a tier
 * promote the ceiling to at least that tier. Weak signals only nudge
 * confidence, never promote alone. On top of that count-based rule, the
 * compound customer-facing-saas rule (spec §2.3) promotes on the combination
 * of deploy + persistent-user-data + admin-role dimensions.
 */
function ceilingFromSignals(signals: readonly RepoSignal[]): {
  ceiling: Tier;
  rationale: string[];
} {
  let ceiling: Tier = "prototype";
  const rationale: string[] = [];

  // Group signals by the tier they promote.
  const byTier = new Map<Tier, RepoSignal[]>();
  for (const s of signals) {
    const arr = byTier.get(s.promotes) ?? [];
    arr.push(s);
    byTier.set(s.promotes, arr);
  }

  for (const [tier, group] of byTier) {
    const strong = group.filter((s) => s.weight === "strong").length;
    const medium = group.filter((s) => s.weight === "medium").length;
    if (strong >= 1 || medium >= 2) {
      ceiling = higher(ceiling, tier);
      rationale.push(
        `${tier}: ${strong} strong + ${medium} medium signal(s) (${group
          .map((s) => s.name)
          .join(", ")})`,
      );
    } else if (group.length > 0) {
      rationale.push(
        `${tier}: signals present but below promotion threshold (${group
          .map((s) => s.name)
          .join(", ")})`,
      );
    }
  }

  // Compound customer-facing-saas rule — real user-data-at-stake across three
  // distinct dimensions. Stricter than count-based; guards over-promotion.
  const compound = compoundCustomerFacing(signals);
  if (compound.fires) {
    ceiling = higher(ceiling, "customer-facing-saas");
    rationale.push(
      `customer-facing-saas: deploy + persistent-user-data + admin-role (${compound.by.join(
        ", ",
      )})`,
    );
  }

  return { ceiling, rationale };
}

/**
 * The pre-compound baseline tier — the ceiling the count-based promotion rule
 * alone would yield, BEFORE the compound customer-facing-saas (data-sensitivity)
 * rule is applied. Used as the `from` tier in the self-scan tier_drift_note so
 * exactly the security promotion above the deploy-detected tier is logged +
 * builder-visible (spec §2.3 — "promote above the deploy-detected tier"). The
 * normal deploy → public-facing classification is NOT drift; only the lift the
 * data-sensitivity signals add on top of it is.
 */
function countBasedCeiling(signals: readonly RepoSignal[]): Tier {
  let ceiling: Tier = "prototype";
  const byTier = new Map<Tier, RepoSignal[]>();
  for (const s of signals) {
    const arr = byTier.get(s.promotes) ?? [];
    arr.push(s);
    byTier.set(s.promotes, arr);
  }
  for (const [tier, group] of byTier) {
    const strong = group.filter((s) => s.weight === "strong").length;
    const medium = group.filter((s) => s.weight === "medium").length;
    if (strong >= 1 || medium >= 2) ceiling = higher(ceiling, tier);
  }
  return ceiling;
}

/**
 * Attribute a promotion: which signals (by name) drove the lift above `from`.
 * Counts both the count-based promoters (strong/medium toward a higher tier)
 * AND the compound customer-facing-saas dimensions, so a Firebase-shaped app
 * whose customer-facing lift comes from the compound rule still names the
 * deploy + user-data + admin-role signals that caused it.
 */
function attributePromotion(signals: readonly RepoSignal[], from: Tier): string {
  const names = new Set<string>();
  for (const s of signals) {
    if (
      TIER_RANK[s.promotes] > TIER_RANK[from] &&
      (s.weight === "strong" || s.weight === "medium")
    ) {
      names.add(s.name);
    }
  }
  const compound = compoundCustomerFacing(signals);
  if (compound.fires && TIER_RANK["customer-facing-saas"] > TIER_RANK[from]) {
    for (const n of compound.by) names.add(n);
  }
  return Array.from(names).join(" + ") || "security-signal";
}

/**
 * Confidence model: high when a tier is well-supported by ≥1 strong signal or
 * inherited from a fresh sibling; lower when only weak signals or a default.
 */
function confidenceFor(
  source: ClassifyResult["source"],
  signals: readonly RepoSignal[],
  prototypeFloorHints: number,
): number {
  if (source === "override") return 1;
  if (source === "inherited") return 0.95;
  const strong = signals.filter((s) => s.weight === "strong").length;
  const medium = signals.filter((s) => s.weight === "medium").length;
  let c = 0.5 + strong * 0.2 + medium * 0.1;
  // Prototype-floor hints lower confidence in any promotion.
  c -= prototypeFloorHints * 0.05;
  return Math.max(0.1, Math.min(1, c));
}

/**
 * Classify the project tier. Pure: all I/O happens in the caller.
 *
 * Inherit-first: if a fresh Vibe Test tier is supplied, it's the baseline; a
 * security signal that promotes ABOVE it produces a tier_drift_note. When no
 * inherited tier, self-scan the signals. An explicit override always wins.
 */
export function classifyTier(input: ClassifyInput): ClassifyResult {
  const modifiers = [...(input.inheritedModifiers ?? [])];
  const prototypeFloorHints = input.prototypeFloorHints ?? 0;

  // 1. Explicit builder override hard-caps the tier (research mitigation).
  if (input.override) {
    return {
      tier: input.override,
      confidence: 1,
      modifiers,
      source: "override",
      tierDriftNote: null,
      rationale: [`builder override → ${input.override}`],
    };
  }

  const { ceiling, rationale } = ceilingFromSignals(input.signals);

  // 2. Inherit-first path.
  if (input.inheritedTier) {
    // Security promotion only if the signal ceiling is strictly higher.
    if (TIER_RANK[ceiling] > TIER_RANK[input.inheritedTier]) {
      const promotedBy = attributePromotion(input.signals, input.inheritedTier);
      return {
        tier: ceiling,
        confidence: confidenceFor("self-scan", input.signals, prototypeFloorHints),
        modifiers,
        source: "promoted",
        tierDriftNote: {
          tier_promoted_from: input.inheritedTier,
          tier_promoted_to: ceiling,
          promoted_by: promotedBy || "security-signal",
        },
        rationale: [
          `inherited ${input.inheritedTier} from Vibe Test`,
          `promoted to ${ceiling}`,
          ...rationale,
        ],
      };
    }
    return {
      tier: input.inheritedTier,
      confidence: confidenceFor("inherited", input.signals, prototypeFloorHints),
      modifiers,
      source: "inherited",
      tierDriftNote: null,
      rationale: [`inherited ${input.inheritedTier} from Vibe Test`, ...rationale],
    };
  }

  // 3. Self-scan path. Prototype-floor hints can demote a weak ceiling.
  let tier = ceiling;
  if (prototypeFloorHints >= 2 && TIER_RANK[tier] <= TIER_RANK["internal"]) {
    tier = "prototype";
    rationale.push(
      `prototype-floor hints (${prototypeFloorHints}) cap tier at prototype`,
    );
  }

  // Self-scan tier_drift_note: when the data-sensitivity (compound) promotion
  // lifts the tier ABOVE what the count-based deploy-detection alone would
  // yield, log it so the promotion is builder-visible, not silent (spec §2.3).
  // The normal deploy → public-facing classification is NOT drift; only the
  // extra lift the user-data-at-stake signals add on top of it is. The drift
  // note is the beacon the SKILL surfaces ("you deployed a public app, but it
  // stores user PII + has an admin surface — that's customer-facing-saas").
  const baseline = countBasedCeiling(input.signals);
  let tierDriftNote: TierDriftNote | null = null;
  if (TIER_RANK[tier] > TIER_RANK[baseline]) {
    tierDriftNote = {
      tier_promoted_from: baseline,
      tier_promoted_to: tier,
      promoted_by: attributePromotion(input.signals, baseline),
    };
  }

  return {
    tier,
    confidence: confidenceFor("self-scan", input.signals, prototypeFloorHints),
    modifiers,
    source: tierDriftNote ? "promoted" : "self-scan",
    tierDriftNote,
    rationale: rationale.length ? rationale : ["no promotion signals → prototype"],
  };
}

/** Map a numeric ASVS-style rank back to a tier (helper for callers). */
export { rankToTier, TIER_RANK };
