// Shared types for Vibe Sec v0.2 — the math substrate + handoff spine.
// Kept in one place so scoring, state, composition, and detectors agree on
// the vocabulary without circular imports.

/** The five security tiers. Maps to the 30/55/70/80/90 ASVS curve (spec §2.1). */
export type Tier =
  | "prototype"
  | "internal"
  | "public-facing"
  | "customer-facing-saas"
  | "regulated";

/** ASVS / standards floor per tier (spec §2.1). */
export type AsvsLevel = "none" | "ASVS-L1" | "ASVS-L2" | "ASVS-L3" | "ASVS-L3+SSDF";

/** Vibe-Sec-native 4-level severity. CVE findings carry CVSS passthrough separately. */
export type Severity = "critical" | "high" | "medium" | "low";

/**
 * The eleven concerns. `primary_concern` is exactly one of these (spec §6).
 * #11 license-compliance landed via GAP-26 (the GPL-engine-in-a-commercial-app
 * incident) — static license posture of the installed dependency tree.
 */
export type Concern =
  | "dependency-cve"
  | "secret-detection"
  | "owasp-survey"
  | "crypto-pii"
  | "config-posture"
  | "supply-chain"
  | "rate-limiting"
  | "auth-model"
  | "threat-model"
  | "tier-thresholds"
  | "license-compliance";

/** Per-tier per-concern scope. `skip` excludes a concern from the score denominator. */
export type ConcernScope = "skip" | "lightweight" | "full" | "mandatory";

/** Confidence-tier fix routing classes (spec §8). */
export type FixClass = "auto" | "stage" | "inline" | "advisory" | "inform-only";

/** Which detector produced the raw finding — credit + FP-comparison (spec §6). */
export type ToolOfRecord =
  | "in-house"
  | "gitleaks"
  | "trufflehog"
  | "osv-scanner"
  | "npm-audit"
  | "semgrep"
  | "codeql"
  | "syft"
  | "trivy";

export const ALL_TIERS: readonly Tier[] = [
  "prototype",
  "internal",
  "public-facing",
  "customer-facing-saas",
  "regulated",
] as const;

export const ALL_CONCERNS: readonly Concern[] = [
  "dependency-cve",
  "secret-detection",
  "owasp-survey",
  "crypto-pii",
  "config-posture",
  "supply-chain",
  "rate-limiting",
  "auth-model",
  "threat-model",
  "tier-thresholds",
  "license-compliance",
] as const;

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};
