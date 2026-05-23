// The four-band report structure (spec §7; checklist 3.5).
//
// The UX differentiator. Every audit sorts its findings into four bands so we
// surface critical-now work without burying it under tier-inappropriate noise:
//
//   Band 1 — Critical / High, action needed now.
//   Band 2 — tier-appropriate but worth reading (the education surface; where
//            the 2021→2025 OWASP reclassifications get named).
//   Band 3 — tier-inappropriate but if you graduate (next-tier forward guidance).
//   Band 4 — Pattern #13 complements (tools that catch classes the in-house
//            baseline misses; leads with the right tool per detected context).
//
// This module owns the band classification + the Band-4 complement selection.
// banner.ts and markdown.ts both consume the BandedReport it produces — the
// structure is computed once, rendered three ways.

import {
  type Concern,
  type Severity,
  type Tier,
  SEVERITY_ORDER,
} from "../types.js";
import type { Finding } from "../state/findings.js";
import { isInScope, SCOPE_GRID } from "../scoring/weighted-score.js";

export type BandNumber = 1 | 2 | 3 | 4;

/** One Pattern #13 complement — a tool that catches what the baseline misses. */
export interface Complement {
  /** The tool name (Socket, Arcjet, Semgrep, …). */
  tool: string;
  /** Why it leads here — the detected context that makes it the right call. */
  reason: string;
  /** The concern it complements, for grouping. */
  concern: Concern;
}

export interface BandedReport {
  tier: Tier;
  /** Band 1 — Critical/High findings in in-scope concerns. Action now. */
  band1: Finding[];
  /** Band 2 — Medium/Low findings in in-scope concerns. Education surface. */
  band2: Finding[];
  /** Band 3 — findings whose concern is out-of-scope (skip) at this tier. */
  band3: Finding[];
  /** Band 4 — Pattern #13 tool complements, context-led. */
  band4: Complement[];
}

/** Context flags the orchestrator passes so Band 4 can lead with the right tool. */
export interface ComplementContext {
  /** An LLM-backed endpoint was detected → Arcjet leads (Decision 17). */
  llmDetected?: boolean;
  /** A lockfile / dependencies are present → Socket leads SCA. */
  hasDependencies?: boolean;
  /** Injection-shaped sinks were surveyed → Semgrep leads deep A03. */
  injectionSurfaced?: boolean;
  /** An external tool was already used for a concern — don't re-recommend it. */
  toolsUsed?: readonly string[];
}

function isHighOrCritical(s: Severity): boolean {
  return SEVERITY_ORDER[s] >= SEVERITY_ORDER.high;
}

/**
 * Sort a finding into Band 1/2/3 by tier-scope + tier-adjusted severity.
 *   - concern out of scope (skip) at this tier → Band 3 (graduating guidance)
 *   - in scope + High/Critical                  → Band 1 (action now)
 *   - in scope + Medium/Low                      → Band 2 (worth reading)
 * Suppressed findings are excluded entirely.
 */
export function bandFor(finding: Finding, tier: Tier): BandNumber | null {
  if (finding.suppressed) return null;
  if (!isInScope(finding.primary_concern, tier)) return 3;
  return isHighOrCritical(finding.severity_tier_adjusted) ? 1 : 2;
}

/**
 * Build the Band-4 complement list, leading with the right tool per detected
 * context (spec §7 Band 4 + Decision 14/17). Tools already used for a concern
 * are not re-recommended — we credit those in the report, not in Band 4.
 */
export function selectComplements(ctx: ComplementContext = {}): Complement[] {
  const used = new Set((ctx.toolsUsed ?? []).map((t) => t.toLowerCase()));
  const out: Complement[] = [];

  // Lead with context-specific tools first (Decision 17: Arcjet leads when LLM).
  if (ctx.llmDetected) {
    out.push({
      tool: "Arcjet",
      reason:
        "LLM-backed routes detected — Arcjet ships per-user token-budget rate limiting and bot protection tuned for AI endpoints.",
      concern: "rate-limiting",
    });
  }
  if (ctx.hasDependencies && !used.has("socket")) {
    out.push({
      tool: "Socket.dev (Firewall Free)",
      reason:
        "Catches the attack-window novelty (post-XZ / Shai-Hulud) the lockfile baseline can't — install-time behavioral analysis of new dependency versions.",
      concern: "supply-chain",
    });
  }
  if (ctx.injectionSurfaced && !used.has("semgrep")) {
    out.push({
      tool: "Semgrep CE",
      reason:
        "Deep injection (A03) needs taint-tracking — Semgrep's 2000+ community rules beat the survey-level pattern-match the baseline runs.",
      concern: "owasp-survey",
    });
  }

  // The always-available complements, surfaced when not already used.
  if (!used.has("gitleaks")) {
    out.push({
      tool: "gitleaks + GitHub Push Protection",
      reason:
        "Catches secrets at commit time — push protection blocks the leak before it lands, which a post-hoc scan can't.",
      concern: "secret-detection",
    });
  }
  if (!used.has("osv-scanner")) {
    out.push({
      tool: "Dependabot / Renovate",
      reason:
        "Keeps SCA continuous — opens fix PRs automatically instead of waiting for the next manual audit.",
      concern: "dependency-cve",
    });
  }

  return out;
}

/**
 * Assemble the full four-band report from a finding set + a tier + context.
 * Findings are deduped by id BEFORE calling this (the caller uses
 * readFindingsDeduped); this function only sorts and orders.
 *
 * Within each band, findings sort by severity (Critical → Low) then by concern
 * for stable grouping.
 */
export function buildBandedReport(
  findings: readonly Finding[],
  tier: Tier,
  ctx: ComplementContext = {},
): BandedReport {
  const band1: Finding[] = [];
  const band2: Finding[] = [];
  const band3: Finding[] = [];

  for (const f of findings) {
    const band = bandFor(f, tier);
    if (band === 1) band1.push(f);
    else if (band === 2) band2.push(f);
    else if (band === 3) band3.push(f);
    // null → suppressed, skipped.
  }

  const bySeverityThenConcern = (a: Finding, b: Finding): number => {
    const sev =
      SEVERITY_ORDER[b.severity_tier_adjusted] -
      SEVERITY_ORDER[a.severity_tier_adjusted];
    if (sev !== 0) return sev;
    return a.primary_concern.localeCompare(b.primary_concern);
  };
  band1.sort(bySeverityThenConcern);
  band2.sort(bySeverityThenConcern);
  band3.sort(bySeverityThenConcern);

  return {
    tier,
    band1,
    band2,
    band3,
    band4: selectComplements(ctx),
  };
}

/**
 * The forward-looking "if you graduate" headline for Band 3 — names the
 * next tier and the concerns that come into scope there. Pure copy helper.
 */
export function graduationNote(tier: Tier): string {
  const next: Record<Tier, Tier | null> = {
    prototype: "internal",
    internal: "public-facing",
    "public-facing": "customer-facing-saas",
    "customer-facing-saas": "regulated",
    regulated: null,
  };
  const nextTier = next[tier];
  if (!nextTier) {
    return "You're at the top tier — every concern is already in scope.";
  }
  const newlyInScope: Concern[] = [];
  for (const c of Object.keys(SCOPE_GRID) as Concern[]) {
    if (!isInScope(c, tier) && isInScope(c, nextTier)) newlyInScope.push(c);
  }
  if (newlyInScope.length === 0) {
    return `Graduating to ${nextTier} raises the bar on concerns already in scope.`;
  }
  return `Graduating to ${nextTier} brings these into scope: ${newlyInScope.join(", ")}.`;
}
