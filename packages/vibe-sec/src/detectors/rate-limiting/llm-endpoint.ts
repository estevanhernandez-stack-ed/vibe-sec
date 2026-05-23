// LLM-endpoint detection (Decision 5, the one tier-override; spec §4.7,
// synthesis §3.7).
//
// The new primitive: a route handler that imports an LLM SDK and forwards to it.
// Detection is SDK-import + handler-proximity + auth-check + per-user-budget:
//   - SDK import: openai / @anthropic-ai/sdk / @google/generative-ai /
//     @aws-sdk/client-bedrock-runtime / cohere-ai / replicate / groq-sdk / @mistralai.
//   - handler proximity: the SDK call lives in (or is reachable from) a route
//     handler in the same file.
//   - auth check: an auth marker in the handler (else the route is unauthenticated).
//   - per-user budget: a token-budget / max_tokens-per-user / rate-limit marker.
//
// The severity rule (the one override):
//   - UNAUTHENTICATED LLM-backed endpoint  → Critical at EVERY tier, incl.
//     Prototype. Adversary profile = "anyone who wants free inference" = the
//     whole internet; financial blast radius is concrete and attacker cost zero.
//   - AUTHENTICATED but unbounded (no per-user budget) → tier-gated: Critical at
//     Customer-facing+, High at Public-facing, informational below (Conflict 1 = A).
// The detector reports the facts (hasAuth, hasBudget); the mapper applies the
// tier rule.

import { lineOf } from "../source-walk.js";

export interface LlmEndpointFinding {
  finding_type: "llm-endpoint-unauthenticated" | "llm-endpoint-unbounded";
  /** The SDK detected (for Band-4 Arcjet recommendation). */
  sdk: string;
  hasAuth: boolean;
  hasPerUserBudget: boolean;
  file: string;
  line: number;
  detail: string;
}

// LLM SDK imports → friendly name.
const LLM_SDKS: { re: RegExp; name: string }[] = [
  { re: /\bfrom\s+["']openai["']|require\(\s*["']openai["']/, name: "openai" },
  { re: /@anthropic-ai\/sdk/, name: "@anthropic-ai/sdk" },
  { re: /@google\/generative-ai/, name: "@google/generative-ai" },
  { re: /@aws-sdk\/client-bedrock-runtime/, name: "@aws-sdk/client-bedrock-runtime" },
  { re: /\bcohere-ai\b/, name: "cohere-ai" },
  { re: /\breplicate\b/, name: "replicate" },
  { re: /\bgroq-sdk\b/, name: "groq-sdk" },
  { re: /@mistralai\//, name: "@mistralai" },
];

// An actual call into the model (not just the import) — strengthens the signal.
const LLM_CALL_RE =
  /\.(?:chat\.completions\.create|messages\.create|generateContent|invoke|generate|run)\s*\(/;
// A route-handler shape present in the file.
const HANDLER_RE =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(|\bonRequest\s*\(|export\s+default\s+(?:async\s+)?function/;
// Auth marker in the handler/file.
const AUTH_RE =
  /\b(?:auth\s*\(|getServerSession\s*\(|getUser\s*\(|requireAuth|currentUser\s*\(|session\.user|req\.user|ctx\.user|verifyToken|getToken\s*\()/;
// Per-user budget / rate-limit / token-cap markers.
const BUDGET_RE =
  /\b(?:rateLimit|ratelimit|@upstash\/ratelimit|arcjet|tokenBudget|max_tokens_per_user|perUserLimit|quota|creditsRemaining|usageLimit|max_tokens\s*:)\b/i;

/** Detect the LLM SDK referenced in a file, if any. */
export function detectLlmSdk(text: string): string | null {
  for (const s of LLM_SDKS) if (s.re.test(text)) return s.name;
  return null;
}

/** Scan one source file for LLM-backed endpoints. */
export function scanLlmEndpoint(text: string, filePath: string): LlmEndpointFinding[] {
  const sdk = detectLlmSdk(text);
  if (!sdk) return [];
  // Require an actual model call OR a route handler in the same file — an import
  // alone (e.g. a types-only import) isn't an endpoint.
  if (!LLM_CALL_RE.test(text) && !HANDLER_RE.test(text)) return [];
  if (!HANDLER_RE.test(text)) return []; // must be wired into a route surface

  const hasAuth = AUTH_RE.test(text);
  const hasPerUserBudget = BUDGET_RE.test(text);

  // Find a representative line: the model call, else the SDK import.
  const callIdx = text.search(LLM_CALL_RE);
  const idx = callIdx >= 0 ? callIdx : 0;

  const finding_type = hasAuth ? "llm-endpoint-unbounded" : "llm-endpoint-unauthenticated";

  // An authenticated + budgeted endpoint is fine — emit nothing.
  if (hasAuth && hasPerUserBudget) return [];

  return [
    {
      finding_type,
      sdk,
      hasAuth,
      hasPerUserBudget,
      file: filePath,
      line: lineOf(text, idx),
      detail: hasAuth
        ? `This route forwards to ${sdk} for authenticated users but has no per-user token budget. A single account can run up a large bill. Add a per-user token budget (Arcjet's AI budget primitive, or an Upstash rate limit keyed on user id).`
        : `This route forwards to ${sdk} with no authentication and no per-user budget. Anyone on the internet can exhaust your monthly LLM spend in an afternoon. Require auth AND add a per-user token budget. This is Critical at every tier.`,
    },
  ];
}
