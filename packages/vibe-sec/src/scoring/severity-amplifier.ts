// Severity amplifier (spec §2.2, synthesis Decision 2).
//
// The hard rule that forces "97% clean but one committed AWS key still fails":
//   - any Critical finding in a concern caps that concern's pass_fraction at 0.5
//   - any High finding caps it at 0.8
// Applies across all twelve concerns. Lower (Medium/Low) findings don't amplify —
// they only move the raw pass_fraction the detector computes.

import type { Severity } from "../types.js";

export const CRITICAL_CAP = 0.5;
export const HIGH_CAP = 0.8;

/**
 * Apply the severity amplifier to a concern's raw pass fraction.
 *
 * @param rawPassFraction the detector-computed clean fraction in [0,1]
 * @param severities      the tier-adjusted severities of findings in this concern
 * @returns the capped pass fraction (never raises the value, only caps it)
 */
export function amplify(
  rawPassFraction: number,
  severities: readonly Severity[],
): number {
  const clamped = clamp01(rawPassFraction);
  let cap = 1;
  for (const sev of severities) {
    if (sev === "critical") {
      cap = Math.min(cap, CRITICAL_CAP);
    } else if (sev === "high") {
      cap = Math.min(cap, HIGH_CAP);
    }
  }
  return Math.min(clamped, cap);
}

/**
 * The cap a single severity imposes — exposed for callers that want to reason
 * about a finding in isolation. Returns 1 for Medium/Low (no amplification).
 */
export function capForSeverity(severity: Severity): number {
  if (severity === "critical") return CRITICAL_CAP;
  if (severity === "high") return HIGH_CAP;
  return 1;
}

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}
