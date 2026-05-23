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

  // ─── Regression: handler-scoped auth (WSYATM quiz.js vs leaderboards.js) ──
  // The load-bearing fix. A Firebase functions file imports verifyAuthToken at
  // the top and uses it in SOME handlers but not others. Whole-file auth checks
  // would (a) falsely mark the unauthed generateQuiz handler as authed (killing
  // the real catch), or (b) inflate the auth-gated generateBadgeIcon to
  // unauthenticated-critical. Auth must be scoped to the handler the model call
  // sits inside.
  describe("handler-scoped auth (regression)", () => {
    // Mirrors WSYATM functions/src/games/quiz.js: imports verifyAuthToken, used
    // in OTHER handlers, but generateQuiz (the Gemini handler) has NO auth.
    const quizFile = `
const {onRequest} = require("firebase-functions/v2/https");
const {GoogleGenerativeAI} = require("@google/generative-ai");
const { db, geminiApiKey, verifyAuthToken, checkAdminRole } = require("../utils/helpers");

const generateQuiz = onRequest(
    {cors: true, timeoutSeconds: 120},
    async (req, res) => {
      if (req.method !== "POST") {
        return res.status(405).json({error: "Method not allowed"});
      }
      const {movieTitle} = req.body;
      const genAI = new GoogleGenerativeAI(geminiApiKey.value());
      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
      const result = await model.generateContent(prompt);
      return res.json(result.response.text());
    });

const getMyQuizHistory = onRequest({cors: true}, async (req, res) => {
  const decodedToken = await verifyAuthToken(req);
  const uid = decodedToken.uid;
  return res.json({ history: [] });
});

module.exports = { generateQuiz, getMyQuizHistory };
`;

    it("KEEPS flagging the unauthenticated Gemini handler even though the file imports verifyAuthToken", () => {
      const findings = scanLlmEndpoint(quizFile, "functions/src/games/quiz.js");
      expect(findings.length).toBe(1);
      expect(findings[0]!.finding_type).toBe("llm-endpoint-unauthenticated");
      expect(findings[0]!.hasAuth).toBe(false);
    });

    // Mirrors WSYATM functions/src/social/leaderboards.js generateBadgeIcon:
    // auth + admin-gated in the SAME handler, but no per-user budget (the rate
    // limiting is commented out). Should be unbounded (tier-gated), NOT
    // unauthenticated-critical.
    const badgeFile = `
const {onRequest} = require("firebase-functions/v2/https");
const {GoogleGenerativeAI} = require("@google/generative-ai");
const { geminiApiKey, verifyAuthToken, checkAdminRole } = require("../utils/helpers");

const generateBadgeIcon = onRequest(
    {cors: true, memory: "1GiB"},
    async (req, res) => {
      const decodedToken = await verifyAuthToken(req);
      const uid = decodedToken.uid;
      await checkAdminRole(uid);
      const {badgeId, prompt} = req.body;
      // SERVER-SIDE RATE LIMITING - DISABLED FOR TESTING
      const genAI = new GoogleGenerativeAI(geminiApiKey.value());
      const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-image" });
      const generatePromise = model.generateContent({ contents: [] });
      return res.json({ ok: true });
    });

module.exports = { generateBadgeIcon };
`;

    it("downgrades the auth+admin-gated badge handler to unbounded, NOT unauthenticated", () => {
      const findings = scanLlmEndpoint(badgeFile, "functions/src/social/leaderboards.js");
      expect(findings.length).toBe(1);
      expect(findings[0]!.finding_type).toBe("llm-endpoint-unbounded");
      expect(findings[0]!.hasAuth).toBe(true);
      // public-facing: unbounded → high (not the every-tier critical).
      expect(llmEndpointToFinding(findings[0]!, "public-facing").severity_tier_adjusted).toBe("high");
    });
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
