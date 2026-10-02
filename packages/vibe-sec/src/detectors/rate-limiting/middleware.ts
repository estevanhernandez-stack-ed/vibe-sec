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
// Project-local guard helpers: an identifier that CONTAINS a rate-limit /
// budget / throttle stem and is CALLED (`enforceRateLimit(`, `checkDailyBudget(`,
// `throttleUser(`). LIB_CALL_RE anchors on a word boundary, so a repo's own
// `enforceRateLimit` never matched and the whole project read as having no
// limiter at all (WSYATM, 2026-10-02). A definition (`function enforceRateLimit(`)
// is not a call site — the orchestrator needs to see the helper USED by a route.
const LOCAL_GUARD_CALL_RE =
  /(?<!function\s)(?<![.\w])(\w*(?:rateLimit|ratelimit|rate_limit|dailyBudget|daily_budget|throttle)\w*)\s*\(/gi;

/** First call-site index of a project-local guard helper, or -1. */
function findLocalGuardCall(text: string): number {
  LOCAL_GUARD_CALL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LOCAL_GUARD_CALL_RE.exec(text)) !== null) {
    const name = m[1] ?? "";
    // `function enforceRateLimit(` / `async function enforceRateLimit(` define, not call.
    const before = text.slice(Math.max(0, m.index - 24), m.index);
    if (/\bfunction\s+$/.test(before)) continue;
    // Bare library names are LIB_CALL_RE's job.
    if (/^(?:rateLimit|rateLimiter|Ratelimit)$/.test(name)) continue;
    return m.index;
  }
  return -1;
}

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
    return findings;
  }

  if (!hasLibCall) {
    const idx = findLocalGuardCall(text);
    if (idx >= 0) {
      findings.push({
        finding_type: "custom-rate-limit-detected-not-verified",
        severity: "low",
        file: filePath,
        line: lineOf(text, idx),
        detail:
          "A project-local (in-house) rate-limit or budget guard is called here. Detected, not verified — confirm the counter lives in a shared store (not process memory), expires, and fails closed for the public tier. Verification is a human read of the helper, not a scan.",
      });
    }
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
