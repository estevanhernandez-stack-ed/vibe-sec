// Shallow SSRF pattern-match (A10-2021 / A01-2025; spec §4.3, synthesis §3.3).
//
// Deep SSRF needs CodeQL-grade flow analysis (deferred to v0.3 per spec §14).
// The shallow pass catches the high-signal vibe-coded shape: an outbound fetch /
// axios / got / http.request whose URL is built from request input (req.query,
// req.body, req.params, or a user-controlled variable) with no allowlist /
// hostname validation nearby. That's the classic "proxy whatever URL the user
// sends" SSRF — the one that reaches cloud metadata endpoints.
//
// Precision guard: a fetch to a string literal, or one with an allowlist /
// new URL().hostname check in the same handler, is not flagged. This stays
// review-grade (confidence ~0.6), not a hard blocker.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface SsrfFinding {
  finding_type: "shallow-ssrf-user-controlled-url";
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  detail: string;
}

// Outbound request sinks. URL is the first arg.
const FETCH_SINK_RE =
  /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|superagent\.\w+|http\.request|https\.request|request)\s*\(\s*([^,)]+)/g;
// Request-input markers that, when present in the URL expression, signal taint.
const TAINTED_URL_RE =
  /\b(?:req\.(?:query|body|params)|request\.(?:query|body|nextUrl)|searchParams\.get|ctx\.query|url\s*\+|`[^`]*\$\{[^}]*(?:url|host|target|endpoint|redirect)[^}]*\}`)/i;
// Allowlist / validation in the surrounding handler defeats the finding.
const VALIDATION_RE =
  /\b(?:allowlist|allowedHosts|allowedOrigins|new URL\([^)]*\)\.hostname|isAllowed|validateUrl|whitelist|\.startsWith\(\s*["'`]https?:\/\/)/i;

function surroundingHandler(text: string, idx: number): string {
  const start = Math.max(0, idx - 400);
  const end = Math.min(text.length, idx + 200);
  return text.slice(start, end);
}

/** Scan one source file for shallow SSRF patterns. */
export function scanSsrf(text: string, filePath: string): SsrfFinding[] {
  const findings: SsrfFinding[] = [];
  FETCH_SINK_RE.lastIndex = 0;
  for (const m of text.matchAll(FETCH_SINK_RE)) {
    const urlArg = m[1] ?? "";
    const idx = m.index ?? 0;
    // String-literal URL is never SSRF.
    if (/^\s*["'`][^"'`]*["'`]\s*$/.test(urlArg)) continue;
    if (!TAINTED_URL_RE.test(urlArg)) continue;
    const ctx = surroundingHandler(text, idx);
    if (VALIDATION_RE.test(ctx)) continue;
    findings.push({
      finding_type: "shallow-ssrf-user-controlled-url",
      severity: "high",
      confidence: 0.6,
      file: filePath,
      line: lineOf(text, idx),
      detail:
        "An outbound request is built from request input with no host allowlist nearby. If an attacker controls the URL they can reach internal services and cloud metadata endpoints (SSRF). Validate the host against an allowlist before fetching. Shallow match — deep flow-analysis is deferred to Semgrep/CodeQL.",
    });
  }
  return findings;
}
