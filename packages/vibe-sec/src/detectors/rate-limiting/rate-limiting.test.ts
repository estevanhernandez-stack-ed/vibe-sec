import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanLlmEndpoint, detectLlmSdk } from "./llm-endpoint.js";
import { scanMiddleware, hasRateLimitLibrary } from "./middleware.js";
import { detectPlatformConfig, recommendationOrder } from "./platform-config.js";
import { scanAbuseMonitoring } from "./abuse-monitoring.js";
import { scanRateLimiting } from "./index.js";
import { llmEndpointToFinding, rateLimitAbsentToFinding } from "../to-findings.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-rate-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

// ─── LLM endpoint — the one tier-override (Decision 5) ─────────────────────
describe("LLM endpoint detection", () => {
  const unauthOpenai = `
    import OpenAI from "openai";
    const client = new OpenAI();
    export async function POST(req) {
      const { prompt } = await req.json();
      return Response.json(await client.chat.completions.create({ messages: [{ role: "user", content: prompt }] }));
    }
  `;

  it("detects an unauthenticated openai route", () => {
    const findings = scanLlmEndpoint(unauthOpenai, "app/api/chat/route.ts");
    expect(findings[0]!.finding_type).toBe("llm-endpoint-unauthenticated");
    expect(findings[0]!.sdk).toBe("openai");
  });

  it("unauthenticated LLM endpoint maps to Critical even at Prototype", () => {
    const f = scanLlmEndpoint(unauthOpenai, "app/api/chat/route.ts")[0]!;
    expect(llmEndpointToFinding(f, "prototype").severity_tier_adjusted).toBe("critical");
    expect(llmEndpointToFinding(f, "internal").severity_tier_adjusted).toBe("critical");
    expect(llmEndpointToFinding(f, "public-facing").severity_tier_adjusted).toBe("critical");
  });

  it("authenticated-but-unbounded LLM endpoint is tier-gated", () => {
    const authUnbounded = `
      import Anthropic from "@anthropic-ai/sdk";
      export async function POST(req) {
        const session = await getServerSession();
        return Response.json(await client.messages.create({}));
      }
    `;
    const f = scanLlmEndpoint(authUnbounded, "app/api/chat/route.ts")[0]!;
    expect(f.finding_type).toBe("llm-endpoint-unbounded");
    expect(llmEndpointToFinding(f, "prototype").severity_tier_adjusted).toBe("low");
    expect(llmEndpointToFinding(f, "public-facing").severity_tier_adjusted).toBe("high");
    expect(llmEndpointToFinding(f, "customer-facing-saas").severity_tier_adjusted).toBe("critical");
  });

  it("does NOT flag an authenticated + budgeted LLM endpoint", () => {
    const safe = `
      import OpenAI from "openai";
      export async function POST(req) {
        const session = await getServerSession();
        const { success } = await ratelimit.limit(session.user.id);
        return client.chat.completions.create({ max_tokens: 500 });
      }
    `;
    expect(scanLlmEndpoint(safe, "route.ts").length).toBe(0);
  });

  it("does NOT flag a bare openai import with no handler", () => {
    expect(scanLlmEndpoint(`import OpenAI from "openai";`, "lib/ai.ts").length).toBe(0);
  });

  it("detects multiple SDKs", () => {
    expect(detectLlmSdk(`import { Anthropic } from "@anthropic-ai/sdk";`)).toBe("@anthropic-ai/sdk");
    expect(detectLlmSdk(`const r = require("groq-sdk");`)).toBe("groq-sdk");
  });
});

// ─── middleware inspection ─────────────────────────────────────────────────
describe("middleware inspection", () => {
  it("flags an in-memory rate-limit store", () => {
    const src = `import rateLimit from "express-rate-limit"; app.use(rateLimit({ windowMs: 60000, max: 100 }));`;
    const findings = scanMiddleware(src, "server.ts");
    expect(findings.some((f) => f.finding_type === "in-memory-rate-limit-store")).toBe(true);
  });

  it("does NOT flag a Redis-backed limiter", () => {
    const src = `const l = new RateLimiterRedis({ storeClient: redis });`;
    const findings = scanMiddleware(src, "server.ts");
    expect(findings.some((f) => f.finding_type === "in-memory-rate-limit-store")).toBe(false);
  });

  it("surfaces a custom Redis-INCR as detected-not-verified", () => {
    const findings = scanMiddleware(`await redis.incr(key);`, "limit.ts");
    expect(findings.some((f) => f.finding_type === "custom-rate-limit-detected-not-verified")).toBe(true);
  });

  it("hasRateLimitLibrary detects a known dep", () => {
    expect(hasRateLimitLibrary(["express", "@upstash/ratelimit"])).toBe(true);
    expect(hasRateLimitLibrary(["express", "react"])).toBe(false);
  });
});

// ─── platform config + recommendation order (Decisions 16/17) ──────────────
describe("platform config + recommendation order", () => {
  it("detects Vercel and recommends platform-native first at Public-facing+", () => {
    write("vercel.json", JSON.stringify({ version: 2 }));
    const cfg = detectPlatformConfig(tmp);
    expect(cfg.platform).toBe("vercel");
    const rec = recommendationOrder("vercel", "public-facing", false);
    expect(rec.recommended[0]).toMatch(/platform-native/);
  });

  it("recommends framework-generic first at Prototype", () => {
    const rec = recommendationOrder("vercel", "prototype", false);
    expect(rec.recommended[0]).toMatch(/framework-generic/);
  });

  it("Arcjet leads Band 4 when LLM routes detected, Upstash otherwise", () => {
    expect(recommendationOrder("vercel", "public-facing", true).band4Lead).toBe("arcjet");
    expect(recommendationOrder("vercel", "public-facing", false).band4Lead).toBe("upstash-ratelimit");
  });
});

// ─── abuse monitoring ──────────────────────────────────────────────────────
describe("abuse monitoring", () => {
  it("flags a 429 with no monitoring nearby", () => {
    const findings = scanAbuseMonitoring(`if (tooMany) return res.status(429).send("slow down");`, "h.ts");
    expect(findings[0]!.finding_type).toBe("rate-limit-without-monitoring");
  });

  it("does NOT flag a 429 with a log nearby", () => {
    const src = `if (tooMany) { logger.warn("throttled", { ip }); return res.status(429).end(); }`;
    expect(scanAbuseMonitoring(src, "h.ts").length).toBe(0);
  });
});

// ─── library-absence tier gate ─────────────────────────────────────────────
describe("library-absence finding", () => {
  it("is null at Prototype, High at Public-facing", () => {
    expect(rateLimitAbsentToFinding("prototype")).toBeNull();
    expect(rateLimitAbsentToFinding("public-facing")!.severity_tier_adjusted).toBe("high");
  });
});

// ─── orchestrator integration ──────────────────────────────────────────────
describe("rate-limiting orchestrator", () => {
  it("flags an unauthenticated openai route + reports library absent", () => {
    write("package.json", JSON.stringify({ dependencies: { openai: "4.0.0", next: "15.0.0" } }));
    write(
      "app/api/chat/route.ts",
      `import OpenAI from "openai";
       const c = new OpenAI();
       export async function POST(req) { return Response.json(await c.chat.completions.create({})); }`,
    );
    const result = scanRateLimiting(tmp, { tier: "prototype" });
    expect(result.llmRoutesDetected).toBe(true);
    expect(result.llmEndpoints[0]!.finding_type).toBe("llm-endpoint-unauthenticated");
    expect(result.libraryAbsent).toBe(true);
    expect(result.recommendation.band4Lead).toBe("arcjet"); // LLM detected
  });
});
