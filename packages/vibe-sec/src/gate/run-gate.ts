// Gate runner — CI pass/fail over cached findings (spec §2.4; checklist 3.5).
//
// Deterministic + headless. Reads the cached findings.jsonl (deduped by id),
// folds them into per-concern results, runs evaluateGate() from the scoring
// substrate, and returns the exit code + GitHub Actions annotations. No scanning
// here — the gate consumes what :audit already wrote, so CI runs are fast and
// reproducible.
//
// Exit codes (spec §2.4): 0 pass / 1 fail / 2 error (no cached state, bad tier).
//
// The per-concern fold:
//   - rawPassFraction is approximated from the finding density per concern; the
//     amplifier (Critical → 0.5 cap, High → 0.8) does the gate-relevant work, so
//     the exact clean-fraction matters less than the severities. A concern with
//     zero findings passes at 1.0; any finding lowers it, and a High/Critical
//     caps it via the amplifier inside weightedScore().

import {
  type Concern,
  type Severity,
  type Tier,
  ALL_CONCERNS,
} from "../types.js";
import type { Finding } from "../state/findings.js";
import { readFindingsDeduped } from "../state/findings.js";
import { readAuditState } from "../state/audit-state.js";
import {
  type ConcernResult,
  type GateResult,
  evaluateGate,
  isInScope,
} from "../scoring/weighted-score.js";

/**
 * Fold deduped findings into one ConcernResult per concern. Suppressed findings
 * are excluded. The rawPassFraction is a simple density proxy: 1.0 when clean,
 * decaying with finding count — the amplifier (driven by `severities`) is what
 * actually gates, so this proxy only needs to be monotonic + bounded.
 *
 * `notApplicable` (GAP-09): concerns whose applicability gate reported
 * not-applicable this audit (e.g. data-posture with no persistence layer).
 * They are dropped from the fold — and therefore from the score denominator —
 * because a concern with nothing to evaluate must not count as a 1.0 pass.
 */
export function foldConcernResults(
  findings: readonly Finding[],
  tier: Tier,
  notApplicable: readonly Concern[] = [],
): ConcernResult[] {
  const na = new Set(notApplicable);
  const byConcern = new Map<Concern, Finding[]>();
  for (const f of findings) {
    if (f.suppressed) continue;
    const arr = byConcern.get(f.primary_concern) ?? [];
    arr.push(f);
    byConcern.set(f.primary_concern, arr);
  }

  const out: ConcernResult[] = [];
  for (const concern of ALL_CONCERNS) {
    if (!isInScope(concern, tier)) continue; // skip concerns never reach the gate
    if (na.has(concern)) continue; // not-applicable: out of the denominator
    const fs_ = byConcern.get(concern) ?? [];
    const severities: Severity[] = fs_.map((f) => f.severity_tier_adjusted);
    // Density proxy: clean → 1.0; each finding shaves toward a 0.5 floor so the
    // weighted score still moves on Medium/Low-only concerns. The amplifier does
    // the hard capping for High/Critical.
    const rawPassFraction = fs_.length === 0 ? 1 : Math.max(0.5, 1 - fs_.length * 0.1);
    out.push({ concern, rawPassFraction, severities });
  }
  return out;
}

export interface GateRunResult extends GateResult {
  tier: Tier;
  /** GitHub Actions annotation lines (emitted when GITHUB_ACTIONS=true). */
  annotations: string[];
}

/**
 * Run the gate against cached state. Returns exit 2 when no audit has been run
 * (the gate has nothing to evaluate) — that's a scanner error, not a pass.
 *
 * @param projectRoot the repo root
 * @param opts.tier   override the cached tier (e.g. a CI-pinned tier)
 * @param opts.githubActions emit GH Actions annotation strings
 * @param opts.notApplicable override the cached not-applicable concern list
 */
export function runGate(
  projectRoot: string,
  opts: {
    tier?: Tier;
    githubActions?: boolean;
    app?: string;
    notApplicable?: readonly Concern[];
  } = {},
): GateRunResult {
  const audit = readAuditState(projectRoot, opts.app);
  const tier = opts.tier ?? audit?.tier;

  // Exit 2 — no cached audit + no pinned tier → nothing to gate.
  if (!tier) {
    return {
      exit: 2,
      pass: false,
      score: 0,
      threshold: 0,
      blockingConcerns: [],
      reasons: ["no cached audit found — run /vibe-sec:audit first, or pin a tier"],
      tier: "prototype",
      annotations: opts.githubActions
        ? ["::error::vibe-sec gate: no cached audit found — run /vibe-sec:audit first"]
        : [],
    };
  }

  const findings = readFindingsDeduped(projectRoot, opts.app);
  // Not-applicable concerns (GAP-09): explicit override wins, else the cached
  // audit's record — so headless CI runs honor the applicability gate too.
  const notApplicable = opts.notApplicable ?? audit?.not_applicable_concerns ?? [];
  const results = foldConcernResults(findings, tier, notApplicable);
  const gate = evaluateGate(tier, results);

  const annotations = opts.githubActions ? buildAnnotations(gate, findings, tier) : [];

  return { ...gate, tier, annotations };
}

/**
 * Build GitHub Actions workflow-command annotations. `::error::` for blocking
 * findings + the gate verdict, `::warning::` for the score gap. File/line are
 * included when present so annotations land on the right lines in the PR diff.
 */
export function buildAnnotations(
  gate: GateResult,
  findings: readonly Finding[],
  tier: Tier,
): string[] {
  const out: string[] = [];

  if (gate.pass) {
    out.push(`::notice::vibe-sec gate PASS — ${(gate.score * 100).toFixed(0)}% meets the ${tier} bar`);
    return out;
  }

  // The blocking findings (High/Critical in mandatory concerns) get error
  // annotations on their source lines.
  const blocking = new Set(gate.blockingConcerns);
  for (const f of findings) {
    if (f.suppressed) continue;
    if (!blocking.has(f.primary_concern)) continue;
    if (f.severity_tier_adjusted !== "high" && f.severity_tier_adjusted !== "critical") continue;
    const loc = f.file
      ? ` file=${f.file}${f.line ? `,line=${f.line}` : ""}`
      : "";
    out.push(`::error${loc}::[${f.severity_tier_adjusted}] ${f.title} (${f.primary_concern})`);
  }

  // The verdict line.
  out.push(
    `::error::vibe-sec gate FAIL — ${gate.reasons.join("; ")}`,
  );
  return out;
}
