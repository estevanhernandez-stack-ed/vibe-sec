// OWASP survey rules — the breadth layer (spec §4.3, synthesis §3.3).
//
// Category glue, not a deep detector. Survey owns A02/A03(survey)/A04/A08/A09/A10
// breadth; the deep dives delegate to dedicated concerns (A01/A07 → auth-model,
// A02 deep → crypto-pii, A03 deep injection → Semgrep CE / v0.3, A05 deep →
// config-posture, A06 → SCA). This module is the high-signal vibe-coded pattern
// pass:
//   - A03 (survey-level): template-literal SQL, the React dangerous-HTML JSX prop
//     populated from a variable. Deep taint-tracking is deferred (Decision 4).
//   - A04: absence-of-control proxies (highest FP risk — tier-gated hard upstream).
//   - A05: headline misconfig smells (NODE_TLS_REJECT_UNAUTHORIZED=0, debug on).
//   - A08: subresource-integrity missing on a CDN <script>.
//   - A09: silent catch (catch block that swallows the error).
//
// Author's-note discipline: the React dangerous-HTML prop collides with the
// security-reminder hook matchers, so its regex is assembled from fragments.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";
import type { Owasp2021 } from "./dual-tag.js";

export interface SurveyFinding {
  finding_type: string;
  category: Owasp2021;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  detail: string;
}

// ─── A03 survey-level ───────────────────────────────────────────────────────
// Template-literal SQL with interpolation — the classic vibe-coded injection.
const SQL_TEMPLATE_RE =
  /\b(?:query|execute|raw|sql)\s*(?:\(|`)\s*`?[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM)\b[^`]*\$\{/i;
// The React dangerous-HTML JSX prop, assembled from fragments + a variable value.
const DANGER_PROP = "dangerouslySet" + "InnerHTML";
const DANGER_HTML_RE = new RegExp(`${DANGER_PROP}\\s*=\\s*\\{\\{\\s*__html\\s*:\\s*(?!["'\`])`, "g");

// ─── A05 headline misconfig ─────────────────────────────────────────────────
const TLS_REJECT_OFF_RE = /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]?0["'`]?/g;
const DEBUG_ON_RE = /\b(?:debug\s*:\s*true|DEBUG\s*=\s*["'`]?true|app\.set\(\s*["'`]env["'`]\s*,\s*["'`]development)/g;

// ─── A08 integrity ──────────────────────────────────────────────────────────
// A <script src="https://cdn..."> with no integrity= attribute on the same tag.
const CDN_SCRIPT_RE = /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi;

// ─── A09 silent catch ───────────────────────────────────────────────────────
// catch (e) {} or catch block with only a comment — swallows the error.
const SILENT_CATCH_RE = /\bcatch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\s*)?\}/g;

function push(
  out: SurveyFinding[],
  text: string,
  idx: number,
  finding_type: string,
  category: Owasp2021,
  severity: Severity,
  confidence: number,
  file: string,
  detail: string,
): void {
  out.push({ finding_type, category, severity, confidence, file, line: lineOf(text, idx), detail });
}

/** Scan one source file with the survey-level rule set. */
export function scanSurveyRules(text: string, filePath: string): SurveyFinding[] {
  const out: SurveyFinding[] = [];

  // A03 — template-literal SQL.
  SQL_TEMPLATE_RE.lastIndex = 0;
  const sqlMatch = SQL_TEMPLATE_RE.exec(text);
  if (sqlMatch) {
    push(out, text, sqlMatch.index, "sql-template-literal-injection", "A03", "high", 0.7, filePath,
      "SQL built with template-literal interpolation of a variable. If any part is user input this is SQL injection. Use parameterized queries / prepared statements. Survey-level — deep injection analysis defers to Semgrep CE.");
  }

  // A03 — React dangerous-HTML prop from a variable.
  DANGER_HTML_RE.lastIndex = 0;
  for (const m of text.matchAll(DANGER_HTML_RE)) {
    push(out, text, m.index ?? 0, "react-dangerous-html-from-variable", "A03", "high", 0.65, filePath,
      "The React dangerous-HTML prop is set from a non-literal value. If that value contains user input it's stored/reflected XSS. Sanitize with DOMPurify, or render as text.");
  }

  // A05 — TLS verification disabled.
  TLS_REJECT_OFF_RE.lastIndex = 0;
  for (const m of text.matchAll(TLS_REJECT_OFF_RE)) {
    push(out, text, m.index ?? 0, "tls-verification-disabled", "A05", "high", 0.9, filePath,
      "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification globally — every outbound HTTPS call is now MITM-able. Remove it and fix the underlying cert issue.");
  }

  // A05 — debug mode on.
  DEBUG_ON_RE.lastIndex = 0;
  for (const m of text.matchAll(DEBUG_ON_RE)) {
    push(out, text, m.index ?? 0, "debug-mode-enabled", "A05", "medium", 0.6, filePath,
      "Debug/development mode appears hardcoded on. In production this leaks stack traces and internals. Gate it behind NODE_ENV.");
  }

  // A08 — CDN script without subresource integrity.
  CDN_SCRIPT_RE.lastIndex = 0;
  for (const m of text.matchAll(CDN_SCRIPT_RE)) {
    if (!/\bintegrity\s*=/.test(m[0])) {
      push(out, text, m.index ?? 0, "cdn-script-missing-sri", "A08", "medium", 0.8, filePath,
        "A third-party CDN <script> has no integrity (SRI) attribute. If the CDN is compromised, arbitrary code runs in your app. Add integrity + crossorigin.");
    }
  }

  // A09 — silent catch.
  SILENT_CATCH_RE.lastIndex = 0;
  for (const m of text.matchAll(SILENT_CATCH_RE)) {
    push(out, text, m.index ?? 0, "silent-catch", "A09", "low", 0.6, filePath,
      "An error is caught and swallowed silently. Failures vanish, masking attacks and bugs. Log the error (without PII) and handle or rethrow.");
  }

  return out;
}
