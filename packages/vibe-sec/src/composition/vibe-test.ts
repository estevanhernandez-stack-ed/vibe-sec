// Vibe Test composition handshake (spec §9, synthesis §4.2) — artifact schema v1.
//
// Reads .vibe-test/state/covered-surfaces.json when present + fresh (≤24h).
// The artifact's contract is Vibe Test's published schema (vibe-test repo:
// skills/guide/schemas/covered-surfaces.schema.json — schema_version const 1,
// additionalProperties false):
//
//   { schema_version: 1, plugin_version?, generated_at, project?,
//     surfaces: [{ kind: route|component|model|middleware|integration,
//                  identifier, file_path?, coverage_level:
//                  none|smoke|behavioral|edge|integration|performance,
//                  test_files?, last_verified_at? }],
//     summary? }
//
// HISTORY (GAP-07, 2026-06-09 quality-net gap analysis): v0.7.0 and earlier
// read a shape Vibe Test never emitted (classification.tier,
// covered_surfaces.endpoints_*, detected_stack) — the reader parsed a real
// artifact, reported reason "ok", and extracted nothing. A false-green
// handshake by construction. This rewrite consumes what schema v1 actually
// carries and names what it cannot:
//
//   - TIER: schema v1 has no classification block, so tier inheritance is
//     structurally impossible today. inheritedTier is always null; the
//     classifier self-scans and the audit banner says so out loud.
//     Inheritance activates only when the core-owned v2 contract adds a
//     classification block (vibe-plugins docs/spec-bank/plugin-core-phase2.md).
//   - MODIFIERS / DETECTED STACK: also absent from v1 — always empty, named
//     in `unavailable` so callers can render the degraded-fields line.
//   - COVERAGE: the live signal. Routes with coverage_level "none" elevate
//     admin-endpoint + IDOR scanning; behavioral/edge-tested routes
//     de-prioritize re-audit. (The v0.2 emitter only assigns none|smoke, so
//     behavioral/edge lists populate from Vibe Test v0.3+ — the enum is
//     already in schema v1, the mapping is forward-compatible.)
//
// Never throws — absent/stale/corrupt/unsupported-schema all degrade to a
// self-classify signal, and every degradation carries a reason the SKILL must
// surface. Silent fallback is a defect, not a feature.

import fs from "node:fs";
import { type Tier } from "../types.js";
import { vibeTestCoveredSurfacesPath } from "../state/paths.js";

const FRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

/** One surface entry as Vibe Test emits it (schema v1, surfaces[]). */
export interface CoveredSurfaceV1 {
  kind?: string;
  identifier?: string;
  file_path?: string;
  coverage_level?: string;
  test_files?: string[];
  last_verified_at?: string;
}

/** The artifact as Vibe Test emits it (schema v1). */
export interface CoveredSurfacesDocV1 {
  schema_version?: number;
  plugin_version?: string;
  generated_at?: string;
  project?: {
    repo_root?: string;
    commit_hash?: string | null;
  };
  surfaces?: CoveredSurfaceV1[];
  summary?: {
    total_surfaces?: number;
    covered_surfaces?: number;
    coverage_by_kind?: Record<string, { total?: number; covered?: number }>;
  };
}

/** What the classifier + audit consume from a successful, fresh read. */
export interface HandshakeResult {
  /** True only when present, fresh, parseable, and schema_version === 1. */
  present: boolean;
  /** Why the handshake degraded, when present === false. */
  reason: "ok" | "absent" | "stale" | "corrupt" | "unsupported-schema";
  /** schema_version read from the artifact (null when unreadable). */
  schemaVersion: number | null;
  /**
   * Inherited tier. ALWAYS null under artifact v1 — the schema carries no
   * classification block. Kept in the interface so the classifier's
   * inherit-first path activates unmodified when the v2 contract ships.
   */
  inheritedTier: Tier | null;
  /** Inherited context modifiers. Always [] under artifact v1. */
  modifiers: string[];
  /** Route surfaces with behavioral-or-better tests → de-prioritize re-audit. */
  endpointsWithBehavioralTests: string[];
  /** Route surfaces with edge-case tests → stronger de-prioritization. */
  endpointsWithEdgeCaseTests: string[];
  /** Route surfaces with NO tests → ELEVATE admin-endpoint + IDOR scanning. */
  uncoveredEndpoints: string[];
  /** Detected stack. Always empty under artifact v1 (not in the schema). */
  detectedStack: {
    frontend: string[];
    backend: string[];
    auth: string[];
    integrations: string[];
  };
  /** Surface totals for the audit banner's handshake status line. */
  surfaceTotals: {
    total: number;
    routes: number;
    uncoveredRoutes: number;
  };
  /**
   * Fields the audit wanted but artifact v1 cannot supply. The SKILL renders
   * these in the handshake status line so the degradation is visible, never
   * silent.
   */
  unavailable: string[];
}

/** Fields artifact v1 structurally cannot carry (see module header). */
const V1_UNAVAILABLE = ["tier", "modifiers", "detected_stack"] as const;

/** coverage_level values that count as behavioral-or-better on a route. */
const BEHAVIORAL_LEVELS = new Set(["behavioral", "edge"]);

function emptyResult(
  reason: HandshakeResult["reason"],
  schemaVersion: number | null = null,
): HandshakeResult {
  return {
    present: false,
    reason,
    schemaVersion,
    inheritedTier: null,
    modifiers: [],
    endpointsWithBehavioralTests: [],
    endpointsWithEdgeCaseTests: [],
    uncoveredEndpoints: [],
    detectedStack: { frontend: [], backend: [], auth: [], integrations: [] },
    surfaceTotals: { total: 0, routes: 0, uncoveredRoutes: 0 },
    unavailable: [],
  };
}

/**
 * Read the Vibe Test handshake. Pure-ish: takes the project root and a clock,
 * does the file read internally, and never throws. Any failure path returns a
 * `present: false` result with a reason — the caller falls back to
 * self-classify AND surfaces the reason (silent fallback is a defect).
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

  let parsed: CoveredSurfacesDocV1;
  try {
    parsed = JSON.parse(raw) as CoveredSurfacesDocV1;
  } catch {
    return emptyResult("corrupt");
  }
  if (typeof parsed !== "object" || parsed === null) {
    return emptyResult("corrupt");
  }

  // Schema gate. schema_version is required-const-1 in Vibe Test's schema.
  // A missing schema_version is exactly the pre-rewrite imaginary shape (or a
  // hand-rolled file) — reject loudly instead of green-lighting it; that
  // false-green is the defect this rewrite exists to kill.
  if (parsed.schema_version !== 1) {
    return emptyResult(
      "unsupported-schema",
      typeof parsed.schema_version === "number" ? parsed.schema_version : null,
    );
  }

  // Freshness gate (≤24h) on the required top-level generated_at.
  const stamp = parsed.generated_at ?? null;
  if (!stamp) {
    // No timestamp → can't prove freshness. Fail-safe to self-classify
    // rather than trust an undated handshake.
    return emptyResult("stale", 1);
  }
  const ts = Date.parse(stamp);
  if (Number.isNaN(ts) || now - ts > FRESH_WINDOW_MS) {
    return emptyResult("stale", 1);
  }

  const surfaces = Array.isArray(parsed.surfaces) ? parsed.surfaces : [];

  const behavioral: string[] = [];
  const edge: string[] = [];
  const uncovered: string[] = [];
  let routeCount = 0;

  for (const s of surfaces) {
    if (s?.kind !== "route" || typeof s.identifier !== "string") continue;
    routeCount += 1;
    const level = typeof s.coverage_level === "string" ? s.coverage_level : "none";
    if (level === "none") uncovered.push(s.identifier);
    if (BEHAVIORAL_LEVELS.has(level)) behavioral.push(s.identifier);
    if (level === "edge") edge.push(s.identifier);
  }

  return {
    present: true,
    reason: "ok",
    schemaVersion: 1,
    inheritedTier: null, // structurally absent from artifact v1 — see header
    modifiers: [],
    endpointsWithBehavioralTests: behavioral,
    endpointsWithEdgeCaseTests: edge,
    uncoveredEndpoints: uncovered,
    detectedStack: { frontend: [], backend: [], auth: [], integrations: [] },
    surfaceTotals: {
      total: surfaces.length,
      routes: routeCount,
      uncoveredRoutes: uncovered.length,
    },
    unavailable: [...V1_UNAVAILABLE],
  };
}

/** True when uncovered endpoints exist and should elevate audit priority. */
export function shouldElevateForUncovered(h: HandshakeResult): boolean {
  return h.present && h.uncoveredEndpoints.length > 0;
}

/**
 * The one-line handshake status the audit banner MUST print on every run —
 * ok or degraded, never silent. Centralized here so the SKILL, the audit,
 * and the threat-model all render the same truth.
 */
export function handshakeStatusLine(h: HandshakeResult): string {
  if (h.present) {
    return (
      `vibe-test handshake: ok (schema v${h.schemaVersion}) — ` +
      `${h.surfaceTotals.total} surfaces read, ` +
      `${h.surfaceTotals.uncoveredRoutes}/${h.surfaceTotals.routes} routes uncovered ` +
      `(elevates admin/IDOR scanning); ` +
      `not in artifact v1: ${h.unavailable.join(", ")} → tier self-classified`
    );
  }
  return `vibe-test handshake: degraded (${h.reason}) — self-classifying tier, no coverage signal`;
}

export { FRESH_WINDOW_MS as VIBE_TEST_FRESH_WINDOW_MS };
