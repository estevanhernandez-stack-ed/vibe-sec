// Weighted-score calculator + gate decision (spec §2.2, §2.4; synthesis §6).
//
// The math substrate. Shared implementation consumed by classifier, audit,
// gate, and posture. Two responsibilities:
//   1. weightedScore() — Σ(concern_pass_fraction × concern_weight) over
//      IN-SCOPE concerns at the current tier. `skip` concerns are excluded
//      from the denominator (tier is a scope gate, not just a severity dial).
//      The severity amplifier (Critical → 0.5 cap, High → 0.8) is applied
//      per concern before summation.
//   2. evaluateGate() — pass/fail vs the tier threshold, including the
//      "no High/Critical in mandatory concerns" hard rules.

import {
  type Concern,
  type ConcernScope,
  type Severity,
  type Tier,
  ALL_CONCERNS,
  SEVERITY_ORDER,
} from "../types.js";
import { amplify } from "./severity-amplifier.js";

// ─── tier curve (spec §2.1 — the 30/55/70/80/90 ASVS-mapped thresholds) ──────
export const TIER_THRESHOLDS: Record<Tier, number> = {
  prototype: 0.3,
  internal: 0.55,
  "public-facing": 0.7,
  "customer-facing-saas": 0.8,
  regulated: 0.9,
};

export const TIER_ASVS_LABEL: Record<Tier, string> = {
  prototype: "no formal verification target",
  internal: "OWASP ASVS L1",
  "public-facing": "OWASP ASVS L2",
  "customer-facing-saas": "OWASP ASVS L3",
  regulated: "OWASP ASVS L3 + NIST SSDF + SBOM",
};

// ─── per-tier per-concern scope grid (synthesis §6) ──────────────────────────
// Each cell is one of skip | lightweight | full | mandatory.
// `skip` removes the concern from the score denominator entirely.
export const SCOPE_GRID: Record<Concern, Record<Tier, ConcernScope>> = {
  "dependency-cve": {
    prototype: "lightweight",
    internal: "full",
    "public-facing": "full",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "secret-detection": {
    prototype: "full",
    internal: "full",
    "public-facing": "full",
    "customer-facing-saas": "full",
    regulated: "mandatory",
  },
  "owasp-survey": {
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "mandatory",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "crypto-pii": {
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "full",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "config-posture": {
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "full",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "supply-chain": {
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "full",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "rate-limiting": {
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "mandatory",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "auth-model": {
    prototype: "lightweight",
    internal: "full",
    "public-facing": "mandatory",
    "customer-facing-saas": "mandatory",
    regulated: "mandatory",
  },
  "threat-model": {
    // Advisory at every tier — never gate-blocking, never in the denominator.
    prototype: "skip",
    internal: "lightweight",
    "public-facing": "full",
    "customer-facing-saas": "full",
    regulated: "full",
  },
  "tier-thresholds": {
    // The meta-concern. Owns no detectors → never contributes a pass_fraction.
    prototype: "skip",
    internal: "skip",
    "public-facing": "skip",
    "customer-facing-saas": "skip",
    regulated: "skip",
  },
  "license-compliance": {
    // GAP-26. Prototype/internal: out of scope entirely (out of the score
    // denominator — license obligations attach to distribution, not tinkering).
    // Public-facing runs it advisory-weight (lightweight); Customer-facing-SaaS
    // and Regulated run it at full weight. Never gate-mandatory (see
    // mandatoryConcerns) — remediation is a business decision, not a code fix.
    prototype: "skip",
    internal: "skip",
    "public-facing": "lightweight",
    "customer-facing-saas": "full",
    regulated: "full",
  },
};

/**
 * Default per-concern weights. The corpus locks the tier curve and the
 * scope-grid denominator but does not assign distinct numeric concern weights
 * for v0.2, so the substrate defaults to equal weight (1.0) per concern.
 * Callers can override per concern; the scope grid still governs membership.
 */
export const DEFAULT_CONCERN_WEIGHT = 1.0;

export interface ConcernResult {
  concern: Concern;
  /** Detector-computed clean fraction in [0,1], before the amplifier. */
  rawPassFraction: number;
  /** Tier-adjusted severities of findings in this concern (drives amplifier). */
  severities: Severity[];
  /** Optional weight override; defaults to DEFAULT_CONCERN_WEIGHT. */
  weight?: number;
}

export interface WeightedScoreResult {
  /** Final weighted score in [0,1]. */
  score: number;
  /** Concerns that counted toward the denominator (non-skip at this tier). */
  inScopeConcerns: Concern[];
  /** Per-concern amplified pass fractions, for report rendering. */
  perConcern: Record<string, number>;
  tier: Tier;
}

/**
 * Whether a concern is in scope (counts toward the denominator) at a tier.
 * `skip` is the only scope that excludes it.
 */
export function isInScope(concern: Concern, tier: Tier): boolean {
  return SCOPE_GRID[concern][tier] !== "skip";
}

/**
 * The concerns whose High/Critical findings hard-fail the gate at a tier
 * (spec §2.4). Threat-model (#9) is always advisory, never gate-blocking.
 *
 * This is the explicit spec §2.4 table, NOT a projection of the SCOPE_GRID —
 * the grid's "full" vs "mandatory" cell labels are about denominator scope +
 * detection depth, which is a separate axis from gate-blocking. Public-facing's
 * mandatory set (concerns 3,5,7,8) includes config-posture (5), which the grid
 * marks "full"; deriving mandatory from the grid silently dropped it. Encoding
 * §2.4 directly keeps the gate honest to the spec.
 */
const MANDATORY_BY_TIER: Record<Tier, Concern[]> = {
  // No concern individually mandatory; Critical-in-1/2/7 handled separately.
  prototype: [],
  internal: [],
  // §2.4: concerns 3, 5, 7, 8.
  "public-facing": ["owasp-survey", "config-posture", "rate-limiting", "auth-model"],
  // §2.4: concerns 1, 3, 4, 5, 6, 7, 8.
  "customer-facing-saas": [
    "dependency-cve",
    "owasp-survey",
    "crypto-pii",
    "config-posture",
    "supply-chain",
    "rate-limiting",
    "auth-model",
  ],
  // §2.4: "no High anywhere except #9" — every detector concern is mandatory.
  regulated: [],
};

export function mandatoryConcerns(tier: Tier): Concern[] {
  if (tier === "regulated") {
    // Every detector concern except the advisory threat-model, the meta
    // tier-thresholds, and license-compliance (GAP-26: license findings route
    // to business decisions — purchase / swap / open the source / document the
    // position — so they weigh in the score but never hard-block the gate).
    return ALL_CONCERNS.filter(
      (c) =>
        c !== "threat-model" &&
        c !== "tier-thresholds" &&
        c !== "license-compliance",
    );
  }
  return [...MANDATORY_BY_TIER[tier]];
}

/**
 * Compute the weighted score for a tier from per-concern results.
 * skip concerns are dropped from both numerator and denominator.
 */
export function weightedScore(
  tier: Tier,
  results: readonly ConcernResult[],
): WeightedScoreResult {
  let numerator = 0;
  let denominator = 0;
  const inScopeConcerns: Concern[] = [];
  const perConcern: Record<string, number> = {};

  for (const r of results) {
    if (!isInScope(r.concern, tier)) continue;
    const weight = r.weight ?? DEFAULT_CONCERN_WEIGHT;
    const amplified = amplify(r.rawPassFraction, r.severities);
    numerator += amplified * weight;
    denominator += weight;
    inScopeConcerns.push(r.concern);
    perConcern[r.concern] = amplified;
  }

  const score = denominator === 0 ? 1 : numerator / denominator;
  return { score, inScopeConcerns, perConcern, tier };
}

export type GateExit = 0 | 1 | 2;

export interface GateResult {
  /** Exit code: 0 pass / 1 fail / 2 scanner error. */
  exit: GateExit;
  pass: boolean;
  score: number;
  threshold: number;
  /** Mandatory concerns that carry a blocking High/Critical finding. */
  blockingConcerns: Concern[];
  reasons: string[];
}

/**
 * The maximum severity present in a concern's findings, or null if clean.
 */
function maxSeverity(severities: readonly Severity[]): Severity | null {
  let max: Severity | null = null;
  for (const s of severities) {
    if (max === null || SEVERITY_ORDER[s] > SEVERITY_ORDER[max]) max = s;
  }
  return max;
}

/**
 * Gate decision (spec §2.4). Returns exit 0/1, plus the blocking reasons.
 * Scanner-error (exit 2) is the caller's responsibility — this is the clean
 * pass/fail path given valid results.
 */
export function evaluateGate(
  tier: Tier,
  results: readonly ConcernResult[],
): GateResult {
  const { score } = weightedScore(tier, results);
  const threshold = TIER_THRESHOLDS[tier];
  const reasons: string[] = [];

  // Threshold check.
  const meetsThreshold = score >= threshold - 1e-9;
  if (!meetsThreshold) {
    reasons.push(
      `weighted score ${(score * 100).toFixed(0)}% below the ${(threshold * 100).toFixed(0)}% ${tier} bar`,
    );
  }

  // Mandatory-concern hard rule: no High/Critical in mandatory concerns.
  const mandatory = new Set(mandatoryConcerns(tier));
  const blockingConcerns: Concern[] = [];
  for (const r of results) {
    if (!mandatory.has(r.concern)) continue;
    const max = maxSeverity(r.severities);
    if (max === "critical" || max === "high") {
      blockingConcerns.push(r.concern);
      reasons.push(`${max} finding in mandatory concern "${r.concern}"`);
    }
  }

  // The unauthenticated-LLM-burn override and the prototype Critical-in-1/2/7
  // rule are encoded by the caller marking the relevant findings Critical in
  // a mandatory concern; at Prototype, concerns 1/2/7 fail-on-Critical even
  // though the tier has no "mandatory" cells — handle that explicitly.
  if (tier === "prototype") {
    const protoFailConcerns: Concern[] = [
      "dependency-cve",
      "secret-detection",
      "rate-limiting",
    ];
    for (const r of results) {
      if (!protoFailConcerns.includes(r.concern)) continue;
      if (maxSeverity(r.severities) === "critical" && !blockingConcerns.includes(r.concern)) {
        blockingConcerns.push(r.concern);
        reasons.push(`critical finding in "${r.concern}" fails even at Prototype`);
      }
    }
  }

  const pass = meetsThreshold && blockingConcerns.length === 0;
  return {
    exit: pass ? 0 : 1,
    pass,
    score,
    threshold,
    blockingConcerns,
    reasons,
  };
}
