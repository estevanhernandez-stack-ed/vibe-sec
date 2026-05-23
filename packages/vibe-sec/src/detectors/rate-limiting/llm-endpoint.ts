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
  /\.(?:chat\.completions\.create|messages\.create|generateContent|invoke|generate|run)\s*\(/g;
// A route-handler shape present in the file.
const HANDLER_RE =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(|\bonRequest\s*\(|export\s+default\s+(?:async\s+)?function/;
// Handler-block boundary markers — used to scope the auth/budget check to the
// handler that contains the model call rather than the whole file (a file can
// export many handlers; one calls the model with no auth, others auth-gate).
const HANDLER_BOUNDARY_RE =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|\b(?:const|let|var)\s+\w+\s*=\s*onRequest\s*\(|\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(|\bonRequest\s*\(|\bonCall\s*\(|export\s+default\s+(?:async\s+)?function/g;
// Auth marker in the handler/file. Includes Firebase's canonical patterns
// (verifyAuthToken / verifyIdToken / checkAdminRole / getAuth().verifyIdToken)
// and inline Express Bearer extraction — but these are tested against the SCOPED
// handler block (see scanLlmEndpoint), never the whole file, so an import of
// verifyAuthToken used by a *sibling* handler doesn't mask an unauthed one.
const AUTH_RE =
  /\bauth\s*\(|\bgetServerSession\s*\(|\bgetUser\s*\(|\brequireAuth\b|\bcurrentUser\s*\(|\bsession\.user\b|\breq\.user\b|\bctx\.user\b|\bverifyToken\b|\bverifyAuthToken\b|\bverifyIdToken\b|\bcheckAdminRole\b|\bcheckManagerRole\b|\bverifyFirebaseToken\b|\bgetAuth\s*\(|\badmin\.auth\s*\(|\bgetToken\s*\(|\bauthHeader\b|\bauthorization\b|\bBearer\s/;
// Per-user budget / rate-limit / token-cap markers.
const BUDGET_RE =
  /\b(?:rateLimit|ratelimit|@upstash\/ratelimit|arcjet|tokenBudget|max_tokens_per_user|perUserLimit|quota|creditsRemaining|usageLimit|max_tokens\s*:)\b/i;

/**
 * Given the full file text and the index of a model call, return the slice of
 * text that bounds the handler the call sits inside (and its start offset): from
 * the nearest preceding handler-declaration to the next handler-declaration (or
 * end-of-file). This scopes the auth/budget check to the right handler in a
 * multi-handler file.
 */
function handlerBlockAround(text: string, callIndex: number): { start: number; block: string } {
  HANDLER_BOUNDARY_RE.lastIndex = 0;
  let blockStart = 0;
  let blockEnd = text.length;
  for (const m of text.matchAll(HANDLER_BOUNDARY_RE)) {
    const idx = m.index ?? 0;
    if (idx <= callIndex) {
      blockStart = idx; // nearest handler decl at or before the call
    } else {
      blockEnd = idx; // first handler decl after the call bounds the block
      break;
    }
  }
  return { start: blockStart, block: text.slice(blockStart, blockEnd) };
}

/** Detect the LLM SDK referenced in a file, if any. */
export function detectLlmSdk(text: string): string | null {
  for (const s of LLM_SDKS) if (s.re.test(text)) return s.name;
  return null;
}

/** Scan one source file for LLM-backed endpoints. */
export function scanLlmEndpoint(text: string, filePath: string): LlmEndpointFinding[] {
  const sdk = detectLlmSdk(text);
  if (!sdk) return [];
  if (!HANDLER_RE.test(text)) return []; // must be wired into a route surface

  // Find every model-call site. Each is attributed to the handler block it sits
  // inside, and auth/budget are tested against THAT block — not the whole file —
  // so a file with a sibling authed handler can't mask an unauthed model call,
  // and an imported-but-unused `verifyAuthToken` doesn't fake authentication.
  LLM_CALL_RE.lastIndex = 0;
  const callMatches = [...text.matchAll(LLM_CALL_RE)];

  const findings: LlmEndpointFinding[] = [];
  // Dedup per handler block so one handler with two model calls yields one finding.
  const seenBlocks = new Set<number>();

  // If the SDK + handler are present but no concrete model call was matched, fall
  // back to a single whole-file representative (preserves prior behavior for the
  // import+handler-without-recognized-call shape).
  const callSites = callMatches.length > 0 ? callMatches.map((m) => m.index ?? 0) : [0];

  for (const callIdx of callSites) {
    const { start: blockStart, block } = handlerBlockAround(text, callIdx);
    // Dedup multiple model calls that live in the same handler block.
    if (seenBlocks.has(blockStart)) continue;
    seenBlocks.add(blockStart);

    const hasAuth = AUTH_RE.test(block);
    const hasPerUserBudget = BUDGET_RE.test(block);

    // An authenticated + budgeted endpoint is fine — emit nothing for this block.
    if (hasAuth && hasPerUserBudget) continue;

    const finding_type = hasAuth ? "llm-endpoint-unbounded" : "llm-endpoint-unauthenticated";

    findings.push({
      finding_type,
      sdk,
      hasAuth,
      hasPerUserBudget,
      file: filePath,
      line: lineOf(text, callIdx),
      detail: hasAuth
        ? `This route forwards to ${sdk} for authenticated users but has no per-user token budget. A single account can run up a large bill. Add a per-user token budget (Arcjet's AI budget primitive, or an Upstash rate limit keyed on user id).`
        : `This route forwards to ${sdk} with no authentication and no per-user budget. Anyone on the internet can exhaust your monthly LLM spend in an afternoon. Require auth AND add a per-user token budget. This is Critical at every tier.`,
    });
  }

  return findings;
}
