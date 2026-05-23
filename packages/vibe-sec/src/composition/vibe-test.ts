// Vibe Test composition handshake (spec §9, synthesis §4.2).
//
// Reads .vibe-test/state/covered-surfaces.json when present + fresh (≤24h),
// extracts the fields Vibe Sec consumes, and never throws — absent/stale/
// corrupt all degrade to a self-classify signal. The writer direction is the
// findings.jsonl writer from state/findings.ts (Vibe Test reads that at
// generate time); this module owns only the read.

import fs from "node:fs";
import { type Tier } from "../types.js";
import { vibeTestCoveredSurfacesPath } from "../state/paths.js";

const FRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

/** The subset of covered-surfaces.json Vibe Sec reads (spec §9.1). */
export interface CoveredSurfaces {
  classification?: {
    tier?: string;
    modifiers?: string[];
    generated_at?: string;
  };
  covered_surfaces?: {
    endpoints_with_behavioral_tests?: string[];
    endpoints_with_edge_case_tests?: string[];
  };
  uncovered_surfaces?: {
    endpoints?: string[];
  };
  detected_stack?: {
    frontend?: string[];
    backend?: string[];
    auth?: string[];
    integrations?: string[];
  };
  /** Top-level timestamp fallback when classification.generated_at is absent. */
  generated_at?: string;
}

/** What the classifier + audit consume from a successful, fresh read. */
export interface HandshakeResult {
  /** True only when present, fresh, and parseable. */
  present: boolean;
  /** Why the handshake degraded, when present === false. */
  reason: "ok" | "absent" | "stale" | "corrupt";
  /** Inherited tier, when a valid tier was read. null → self-classify. */
  inheritedTier: Tier | null;
  modifiers: string[];
  /** Surfaces with behavioral tests → de-prioritize re-audit. */
  endpointsWithBehavioralTests: string[];
  /** Surfaces with edge-case tests → stronger de-prioritization. */
  endpointsWithEdgeCaseTests: string[];
  /** Uncovered endpoints → ELEVATE admin-endpoint + IDOR scanning. */
  uncoveredEndpoints: string[];
  /** Detected stack → picks CVE feeds / auth libs / framework rules. */
  detectedStack: {
    frontend: string[];
    backend: string[];
    auth: string[];
    integrations: string[];
  };
}

const VALID_TIERS = new Set<string>([
  "prototype",
  "internal",
  "public-facing",
  "customer-facing-saas",
  "regulated",
]);

function emptyResult(reason: HandshakeResult["reason"]): HandshakeResult {
  return {
    present: false,
    reason,
    inheritedTier: null,
    modifiers: [],
    endpointsWithBehavioralTests: [],
    endpointsWithEdgeCaseTests: [],
    uncoveredEndpoints: [],
    detectedStack: { frontend: [], backend: [], auth: [], integrations: [] },
  };
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/**
 * Read the Vibe Test handshake. Pure-ish: takes the project root and a clock,
 * does the file read internally, and never throws. Any failure path returns a
 * `present: false` result with a reason — the caller falls back to self-classify.
 */
export function readVibeTestHandshake(
  projectRoot: string,
  now: number = Date.now(),
): HandshakeResult {
  const file = vibeTestCoveredSurfacesPath(projectRoot);

  let raw: string;
  try {
    if (!fs.existsSync(file)) return emptyResult("absent");
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return emptyResult("absent");
  }

  let parsed: CoveredSurfaces;
  try {
    parsed = JSON.parse(raw) as CoveredSurfaces;
  } catch {
    return emptyResult("corrupt");
  }
  if (typeof parsed !== "object" || parsed === null) {
    return emptyResult("corrupt");
  }

  // Freshness gate (≤24h). Use classification.generated_at, then top-level.
  const stamp =
    parsed.classification?.generated_at ?? parsed.generated_at ?? null;
  if (stamp) {
    const ts = Date.parse(stamp);
    if (!Number.isNaN(ts) && now - ts > FRESH_WINDOW_MS) {
      return emptyResult("stale");
    }
  }
  // No timestamp at all → treat as stale (can't prove freshness). Fail-safe to
  // self-classify rather than trust an undated handshake.
  if (!stamp) {
    return emptyResult("stale");
  }

  const tierRaw = parsed.classification?.tier;
  const inheritedTier =
    typeof tierRaw === "string" && VALID_TIERS.has(tierRaw)
      ? (tierRaw as Tier)
      : null;

  return {
    present: true,
    reason: "ok",
    inheritedTier,
    modifiers: asStringArray(parsed.classification?.modifiers),
    endpointsWithBehavioralTests: asStringArray(
      parsed.covered_surfaces?.endpoints_with_behavioral_tests,
    ),
    endpointsWithEdgeCaseTests: asStringArray(
      parsed.covered_surfaces?.endpoints_with_edge_case_tests,
    ),
    uncoveredEndpoints: asStringArray(parsed.uncovered_surfaces?.endpoints),
    detectedStack: {
      frontend: asStringArray(parsed.detected_stack?.frontend),
      backend: asStringArray(parsed.detected_stack?.backend),
      auth: asStringArray(parsed.detected_stack?.auth),
      integrations: asStringArray(parsed.detected_stack?.integrations),
    },
  };
}

/** True when uncovered endpoints exist and should elevate audit priority. */
export function shouldElevateForUncovered(h: HandshakeResult): boolean {
  return h.present && h.uncoveredEndpoints.length > 0;
}

export { FRESH_WINDOW_MS as VIBE_TEST_FRESH_WINDOW_MS };
