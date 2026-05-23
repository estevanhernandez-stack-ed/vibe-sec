// Platform rate-limit config detection + recommendation order (Decision 16/17;
// spec §4.7, synthesis §3.7).
//
// Detect the deploy platform and whether a platform-native rate-limit surface is
// configured (Vercel Firewall, Cloudflare Rulesets, AWS API Gateway throttling).
// The recommendation ORDER is tier-aware (Decision 16):
//   - Public-facing+  → recommend platform-native FIRST (one less moving part,
//     lower latency, defense-in-depth when paired with app middleware), then the
//     framework-generic complement (@upstash/ratelimit).
//   - Prototype/Internal → recommend framework-generic first (portable, no
//     account setup).
// And the Band-4 lead (Decision 17): when LLM routes are detected, Arcjet leads
// (AI-native per-user token budgets); otherwise Upstash Ratelimit leads.

import fs from "node:fs";
import path from "node:path";
import type { Tier } from "../../types.js";

export type DeployPlatform = "vercel" | "cloudflare" | "aws-api-gateway" | "netlify" | "fly" | "railway" | "render" | "unknown";

export interface PlatformConfig {
  platform: DeployPlatform;
  /** True when a platform-native rate-limit/WAF config is present. */
  nativeRateLimitConfigured: boolean;
  signals: string[];
}

function readIfExists(projectRoot: string, rel: string): string | null {
  try {
    return fs.readFileSync(path.join(projectRoot, rel), "utf8");
  } catch {
    return null;
  }
}

function fileExists(projectRoot: string, rel: string): boolean {
  try {
    fs.accessSync(path.join(projectRoot, rel));
    return true;
  } catch {
    return false;
  }
}

/** Detect the deploy platform + whether native rate limiting is configured. */
export function detectPlatformConfig(projectRoot: string): PlatformConfig {
  const signals: string[] = [];

  const vercelJson = readIfExists(projectRoot, "vercel.json");
  if (vercelJson || fileExists(projectRoot, ".vercel")) {
    signals.push("vercel");
    // Vercel Firewall rules live under config; a `firewall`/`rules` key is the signal.
    const configured = Boolean(vercelJson && /"(?:firewall|rateLimit|rules)"/.test(vercelJson));
    return { platform: "vercel", nativeRateLimitConfigured: configured, signals };
  }

  if (fileExists(projectRoot, "wrangler.toml") || readIfExists(projectRoot, "wrangler.toml")) {
    const wrangler = readIfExists(projectRoot, "wrangler.toml") ?? "";
    signals.push("cloudflare");
    return {
      platform: "cloudflare",
      nativeRateLimitConfigured: /\b(?:rate_limit|ruleset|waf)\b/i.test(wrangler),
      signals,
    };
  }

  const netlify = readIfExists(projectRoot, "netlify.toml");
  if (netlify) {
    signals.push("netlify");
    return { platform: "netlify", nativeRateLimitConfigured: false, signals };
  }

  if (fileExists(projectRoot, "fly.toml")) {
    signals.push("fly");
    return { platform: "fly", nativeRateLimitConfigured: false, signals };
  }

  // AWS API Gateway via serverless / SAM / CDK.
  const serverless = readIfExists(projectRoot, "serverless.yml") ?? readIfExists(projectRoot, "template.yaml");
  if (serverless) {
    signals.push("aws-api-gateway");
    return {
      platform: "aws-api-gateway",
      nativeRateLimitConfigured: /\b(?:throttl|UsagePlan|burstLimit|rateLimit)\b/i.test(serverless),
      signals,
    };
  }

  return { platform: "unknown", nativeRateLimitConfigured: false, signals };
}

export interface RecommendationOrder {
  /** Ordered list of recommended rate-limit surfaces for this tier. */
  recommended: string[];
  /** The Band-4 lead recommendation. */
  band4Lead: "arcjet" | "upstash-ratelimit";
}

const PUBLIC_FACING_PLUS = new Set<Tier>(["public-facing", "customer-facing-saas", "regulated"]);

/**
 * Compute the recommendation order (Decision 16) + Band-4 lead (Decision 17).
 * `llmRoutesDetected` flips the Band-4 lead to Arcjet.
 */
export function recommendationOrder(
  platform: DeployPlatform,
  tier: Tier,
  llmRoutesDetected: boolean,
): RecommendationOrder {
  const platformNative: Record<DeployPlatform, string> = {
    vercel: "Vercel Firewall (platform-native)",
    cloudflare: "Cloudflare Rulesets (platform-native)",
    "aws-api-gateway": "API Gateway throttling (platform-native)",
    netlify: "Netlify edge rate limiting",
    fly: "Fly.io edge / app-level limiter",
    railway: "app-level limiter (no native rate limit)",
    render: "app-level limiter (no native rate limit)",
    unknown: "@upstash/ratelimit (framework-generic)",
  };
  const generic = "@upstash/ratelimit + @upstash/redis (framework-generic)";
  const native = platformNative[platform];

  const recommended =
    PUBLIC_FACING_PLUS.has(tier) && platform !== "unknown"
      ? [native, generic]
      : [generic, native];

  return {
    recommended,
    band4Lead: llmRoutesDetected ? "arcjet" : "upstash-ratelimit",
  };
}
