// Rate-limiting orchestrator (concern #7; spec §4.7, synthesis §3.7;
// checklist 3.4).
//
// Always in-house (synthesis §3.7) — platform-native surfaces (Vercel Firewall /
// Cloudflare / API Gateway), Arcjet, and Upstash are recommended in Band 4, not
// shelled out. Four passes:
//   - middleware: rate-limit library presence + store shape + custom INCR
//   - llm-endpoint: the LLM-burn override (Decision 5) — unauthenticated LLM
//     endpoint is Critical at every tier
//   - platform-config: deploy-platform detection + recommendation order
//   - abuse-monitoring: 429-without-monitoring (gated on a limiter existing)
//
// Integrates with auth-model's route inventory (checklist 3.4 dep): reuses
// scanRoutes to know whether the app exposes routes at all, so the
// library-absence signal only fires for apps with a route surface.

import { walkSource } from "../source-walk.js";
import { scanMiddleware, hasRateLimitLibrary, type MiddlewareFinding } from "./middleware.js";
import { scanLlmEndpoint, detectLlmSdk, type LlmEndpointFinding } from "./llm-endpoint.js";
import {
  detectPlatformConfig,
  recommendationOrder,
  type PlatformConfig,
  type RecommendationOrder,
} from "./platform-config.js";
import { scanAbuseMonitoring, type AbuseMonitoringFinding } from "./abuse-monitoring.js";
import { scanRoutes } from "../auth-model/route-inventory.js";
import { readDeclaredDeps } from "../supply-chain/lockfile.js";
import type { Tier } from "../../types.js";

export interface RateLimitScanResult {
  /** Per-file middleware shape findings. */
  middleware: MiddlewareFinding[];
  /** Project-level: no rate-limit library at all (when routes exist). */
  libraryAbsent: boolean;
  llmEndpoints: LlmEndpointFinding[];
  platform: PlatformConfig;
  recommendation: RecommendationOrder;
  abuseMonitoring: AbuseMonitoringFinding[];
  /** Whether any LLM-backed route was detected (drives Arcjet Band-4 lead). */
  llmRoutesDetected: boolean;
  /** Whether the app exposes any route surface at all. */
  hasRoutes: boolean;
}

export interface RateLimitScanOptions {
  /** Tier drives the recommendation order (Decision 16). Default public-facing. */
  tier?: Tier;
}

/** Run the full rate-limiting pass over a project. */
export function scanRateLimiting(
  projectRoot: string,
  opts: RateLimitScanOptions = {},
): RateLimitScanResult {
  const tier: Tier = opts.tier ?? "public-facing";

  const middleware: MiddlewareFinding[] = [];
  const llmEndpoints: LlmEndpointFinding[] = [];
  const abuseMonitoring: AbuseMonitoringFinding[] = [];
  let hasRoutes = false;
  let anyLimiterCallSite = false;

  walkSource(projectRoot, [
    (text, rel) => {
      if (scanRoutes(text, rel).length > 0) hasRoutes = true;
      const mw = scanMiddleware(text, rel);
      if (mw.length > 0) anyLimiterCallSite = true;
      middleware.push(...mw);
      llmEndpoints.push(...scanLlmEndpoint(text, rel));
      abuseMonitoring.push(...scanAbuseMonitoring(text, rel));
      if (detectLlmSdk(text)) {
        /* LLM SDK present — llmRoutesDetected computed below from llmEndpoints */
      }
      return [];
    },
  ]);

  const declaredDeps = readDeclaredDeps(projectRoot).map((d) => d.name);
  const hasLib = hasRateLimitLibrary(declaredDeps) || anyLimiterCallSite;
  const libraryAbsent = hasRoutes && !hasLib;

  const llmRoutesDetected = llmEndpoints.length > 0;

  const platform = detectPlatformConfig(projectRoot);
  const recommendation = recommendationOrder(platform.platform, tier, llmRoutesDetected);

  // Abuse-monitoring only matters once a limiter exists.
  const monitoring = hasLib ? abuseMonitoring : [];

  return {
    middleware,
    libraryAbsent,
    llmEndpoints,
    platform,
    recommendation,
    abuseMonitoring: monitoring,
    llmRoutesDetected,
    hasRoutes,
  };
}

export {
  scanMiddleware,
  hasRateLimitLibrary,
  scanLlmEndpoint,
  detectLlmSdk,
  detectPlatformConfig,
  recommendationOrder,
  scanAbuseMonitoring,
};
export type { MiddlewareFinding };
export type { LlmEndpointFinding };
export type { AbuseMonitoringFinding };
export type { PlatformConfig, RecommendationOrder, DeployPlatform } from "./platform-config.js";
