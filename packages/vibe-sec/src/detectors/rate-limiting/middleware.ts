// Rate-limit middleware-registration inspection (spec §4.7, synthesis §3.7).
//
// Per-framework, is a rate limiter registered at all, and is it backed by a
// shared store (Redis/Upstash) vs in-memory (which doesn't survive multiple
// instances)? Frameworks: Express (express-rate-limit), Fastify
// (@fastify/rate-limit), Next.js (middleware.ts), NestJS (ThrottlerModule),
// Hono, tRPC. A custom Redis-INCR pattern surfaces as "detected, not verified"
// (synthesis §3.7) — informational, not a blocker.
//
// The library-presence check is project-level (the orchestrator passes the
// package.json deps + whether any limiter call site was seen); the per-file scan
// here classifies the limiter shape it finds.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface MiddlewareFinding {
  finding_type:
    | "no-rate-limit-library"
    | "in-memory-rate-limit-store"
    | "custom-rate-limit-detected-not-verified";
  severity: Severity;
  file: string | null;
  line: number | null;
  detail: string;
}

// Known rate-limit libraries (package names + call sites).
export const RATE_LIMIT_LIBS = [
  "express-rate-limit",
  "@fastify/rate-limit",
  "rate-limiter-flexible",
  "@upstash/ratelimit",
  "@nestjs/throttler",
  "hono-rate-limiter",
  "@arcjet/next",
  "arcjet",
] as const;

const LIB_CALL_RE =
  /\b(?:rateLimit|rateLimiter|RateLimiterMemory|RateLimiterRedis|Ratelimit|ThrottlerModule|rateLimiterMiddleware|arcjet)\s*\(/;
// A shared store config (Redis/Upstash) vs the default in-memory store.
const SHARED_STORE_RE = /\b(?:redis|upstash|RateLimiterRedis|new Redis|ioredis|MemcachedStore|store\s*:)\b/i;
// Custom Redis-INCR rate limiting — detected, not verified.
const CUSTOM_INCR_RE = /\b(?:redis|client)\s*\.\s*incr\s*\(/i;

/**
 * Classify a rate-limiter call site found in a file. Returns the shape finding(s)
 * for this file — the "no library at all" finding is emitted at project level by
 * the orchestrator (it needs the whole-project view).
 */
export function scanMiddleware(text: string, filePath: string): MiddlewareFinding[] {
  const findings: MiddlewareFinding[] = [];

  const hasLibCall = LIB_CALL_RE.test(text);
  if (hasLibCall && !SHARED_STORE_RE.test(text)) {
    const idx = text.search(LIB_CALL_RE);
    findings.push({
      finding_type: "in-memory-rate-limit-store",
      severity: "low",
      file: filePath,
      line: lineOf(text, Math.max(0, idx)),
      detail:
        "A rate limiter is registered but uses the default in-memory store. Across multiple instances each holds its own counter, so the effective limit multiplies by instance count. Back it with Redis/Upstash for a shared counter.",
    });
  }

  if (CUSTOM_INCR_RE.test(text) && !hasLibCall) {
    const idx = text.search(CUSTOM_INCR_RE);
    findings.push({
      finding_type: "custom-rate-limit-detected-not-verified",
      severity: "low",
      file: filePath,
      line: lineOf(text, Math.max(0, idx)),
      detail:
        "A custom Redis-INCR rate-limit pattern is present. Detected, not verified — confirm it sets an expiry on the counter and handles the race between INCR and EXPIRE. A library (Upstash Ratelimit) handles these correctly.",
    });
  }

  return findings;
}

/**
 * Project-level: does the project depend on any rate-limit library? The
 * orchestrator passes the declared deps. When none and the app exposes routes,
 * surface the library-absence signal (severity is tier-gated by the mapper).
 */
export function hasRateLimitLibrary(declaredDepNames: readonly string[]): boolean {
  return declaredDepNames.some((d) => (RATE_LIMIT_LIBS as readonly string[]).includes(d));
}
