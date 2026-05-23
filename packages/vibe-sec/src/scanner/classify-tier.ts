// Tier classifier (spec §2.3, synthesis §Detection; research:
// security-tier-thresholds.md). Inherit-first, scan-second.
//
//   1. If Vibe Test's covered-surfaces.json is present + fresh (≤24h), inherit
//      classification.tier + modifiers, then allow a security-specific
//      PROMOTION (explicit, logged via tier_drift_note).
//   2. Otherwise self-scan the repo signals and fuse them into a tier.
//
// This file owns the signal-fusion math. The Vibe Test read lives in
// composition/vibe-test.ts; this module accepts an already-parsed handshake so
// it stays pure + testable.

import { type Tier, ALL_TIERS } from "../types.js";

export type SignalWeight = "strong" | "medium" | "weak";

/** A repo signal the self-scan can detect (research signal tables). */
export interface RepoSignal {
  name: string;
  weight: SignalWeight;
  /** Which tier ceiling this signal pushes toward. */
  promotes: Tier;
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
 * Promotion rule (research): ≥1 Strong OR ≥2 Medium signals toward a tier
 * promote the ceiling to at least that tier. Weak signals only nudge
 * confidence, never promote alone.
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

  return { ceiling, rationale };
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
      const promotedBy = input.signals
        .filter(
          (s) =>
            TIER_RANK[s.promotes] > TIER_RANK[input.inheritedTier!] &&
            (s.weight === "strong" || s.weight === "medium"),
        )
        .map((s) => s.name)
        .join(" + ");
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

  return {
    tier,
    confidence: confidenceFor("self-scan", input.signals, prototypeFloorHints),
    modifiers,
    source: "self-scan",
    tierDriftNote: null,
    rationale: rationale.length ? rationale : ["no promotion signals → prototype"],
  };
}

/** Map a numeric ASVS-style rank back to a tier (helper for callers). */
export { rankToTier, TIER_RANK };
