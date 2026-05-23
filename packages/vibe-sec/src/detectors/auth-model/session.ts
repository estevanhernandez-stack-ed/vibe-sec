// Session-pattern classification (spec §4.8 probe 5, synthesis §3.8).
//
// Classify how the app manages sessions and flag the per-library correctness
// gaps. The high-signal vibe-coded patterns:
//   - JWT stored in localStorage / sessionStorage — XSS-readable; should be an
//     HttpOnly cookie. Architectural finding (High).
//   - Session cookie without maxAge — non-expiring session. Medium.
//   - next-auth / Clerk / Supabase Auth / Lucia / iron-session detection — used
//     to set the session library so the report can give per-library guidance.
//   - Missing CSRF protection on a cookie-session app (no csrf token + cookie
//     session) — advisory.
//
// This probe is classification-first: it returns the detected library and the
// concrete findings. Secret/rotation concerns (NEXTAUTH_SECRET) are delegated to
// crypto-pii / secret-detection — here we only classify session handling.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export type SessionLibrary =
  | "next-auth"
  | "clerk"
  | "supabase-auth"
  | "lucia"
  | "iron-session"
  | "express-session"
  | "custom-jwt"
  | "unknown";

export interface SessionFinding {
  finding_type:
    | "jwt-in-web-storage"
    | "session-cookie-no-maxage"
    | "missing-csrf-on-cookie-session";
  severity: Severity;
  file: string;
  line: number;
  detail: string;
}

const LIBRARY_SIGNALS: { lib: SessionLibrary; re: RegExp }[] = [
  { lib: "next-auth", re: /\b(?:next-auth|NextAuth|getServerSession|@auth\/core)\b/ },
  { lib: "clerk", re: /(?:@clerk\/|clerkClient|useAuth\(\)|currentUser\(\))/ },
  { lib: "supabase-auth", re: /\b(?:supabase\.auth|@supabase\/auth-helpers|getUser\(\))\b/ },
  { lib: "lucia", re: /\b(?:lucia|Lucia|validateSession)\b/ },
  { lib: "iron-session", re: /\biron-session|getIronSession\b/ },
  { lib: "express-session", re: /\bexpress-session|req\.session\b/ },
];

// JWT/token written to web storage (XSS-readable).
const WEB_STORAGE_TOKEN_RE =
  /\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["'`][^"'`]*(?:token|jwt|auth|session)[^"'`]*["'`]/gi;
// Cookie set without a maxAge / expires.
const COOKIE_SET_RE = /\b(?:res\.cookie|cookies\(\)\.set|setCookie|cookie\.set)\s*\(/g;
const MAXAGE_RE = /\b(?:maxAge|expires)\b/;

/** Classify the session library used in a file (best-effort, first match wins). */
export function classifySessionLibrary(text: string): SessionLibrary {
  for (const s of LIBRARY_SIGNALS) if (s.re.test(text)) return s.lib;
  if (/\bjwt\.(?:sign|verify)\b/.test(text)) return "custom-jwt";
  return "unknown";
}

function callArgSpan(text: string, openParenIdx: number): string {
  let depth = 0;
  let i = openParenIdx;
  for (; i < text.length && i < openParenIdx + 400; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) break;
    }
  }
  return text.slice(openParenIdx, i + 1);
}

/** Scan one source file for session-handling weaknesses. */
export function scanSession(text: string, filePath: string): SessionFinding[] {
  const findings: SessionFinding[] = [];

  WEB_STORAGE_TOKEN_RE.lastIndex = 0;
  for (const m of text.matchAll(WEB_STORAGE_TOKEN_RE)) {
    findings.push({
      finding_type: "jwt-in-web-storage",
      severity: "high",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "A session token is stored in localStorage/sessionStorage, which any XSS can read. Store it in an HttpOnly, Secure, SameSite cookie instead so JavaScript can't exfiltrate it.",
    });
  }

  COOKIE_SET_RE.lastIndex = 0;
  for (const m of text.matchAll(COOKIE_SET_RE)) {
    const idx = m.index ?? 0;
    const openParen = idx + m[0].length - 1;
    const args = callArgSpan(text, openParen);
    // Only flag session-ish cookies (skip preference/analytics cookies).
    if (/\b(?:session|sid|auth|jwt|token)\b/i.test(args) && !MAXAGE_RE.test(args)) {
      findings.push({
        finding_type: "session-cookie-no-maxage",
        severity: "medium",
        file: filePath,
        line: lineOf(text, idx),
        detail:
          "A session cookie is set without maxAge/expires — it becomes a session cookie that lingers per browser policy and can't be centrally expired. Set an explicit maxAge.",
      });
    }
  }

  return findings;
}
