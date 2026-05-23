// Cookie-flag inspection (synthesis §3.5, Decision 23).
//
// A cookie that carries a session needs HttpOnly (no JS access → XSS can't
// steal it), Secure (HTTPS-only), and SameSite (CSRF defense). We inspect
// cookie-setting call sites — res.cookie(), Set-Cookie headers, the cookies()
// API, NextAuth/express-session config — for missing flags.
//
// Ownership nuance (Decision 23): when the cookie is auth-related (session,
// token, jwt, refresh names), the finding is owned by the auth-model concern;
// config-posture owns the generic cookie-flag baseline. This module reports the
// raw finding + an `authRelated` flag so the orchestrator routes ownership.

export interface CookieFinding {
  finding_type: "cookie-missing-flags";
  file: string;
  line: number;
  cookieName: string;
  missingFlags: string[];
  /** True when the cookie name looks auth-related → auth-model owns it. */
  authRelated: boolean;
  severity: "high" | "medium" | "low";
  detail: string;
}

const AUTH_COOKIE_RE = /(session|sess|token|jwt|auth|refresh|sid|csrf)/i;

// res.cookie('name', value, { ...options })  — capture name + the options blob.
const RES_COOKIE_RE =
  /\.cookie\s*\(\s*["'`]([^"'`]+)["'`]\s*,[^,]*,\s*(\{[^}]*\})/g;
// Set-Cookie header string form.
const SET_COOKIE_HEADER_RE = /Set-Cookie["'`]?\s*[,:]\s*["'`]([^=]+)=([^"'`;]*);?([^"'`]*)["'`]/gi;

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

function missingFromOptions(opts: string): string[] {
  const missing: string[] = [];
  if (!/httpOnly\s*:\s*true/i.test(opts)) missing.push("HttpOnly");
  if (!/secure\s*:\s*true/i.test(opts)) missing.push("Secure");
  if (!/sameSite\s*:/i.test(opts)) missing.push("SameSite");
  return missing;
}

function missingFromHeaderAttrs(attrs: string): string[] {
  const missing: string[] = [];
  if (!/httponly/i.test(attrs)) missing.push("HttpOnly");
  if (!/secure/i.test(attrs)) missing.push("Secure");
  if (!/samesite/i.test(attrs)) missing.push("SameSite");
  return missing;
}

function severityFor(authRelated: boolean, missing: string[]): "high" | "medium" | "low" {
  if (authRelated && missing.includes("HttpOnly")) return "high";
  if (authRelated) return "medium";
  return "low";
}

/** Scan a source file for cookie-setting calls missing security flags. */
export function scanCookies(text: string, filePath: string): CookieFinding[] {
  const out: CookieFinding[] = [];

  RES_COOKIE_RE.lastIndex = 0;
  for (const m of text.matchAll(RES_COOKIE_RE)) {
    const name = m[1]!;
    const opts = m[2] ?? "";
    const missing = missingFromOptions(opts);
    if (missing.length === 0) continue;
    const authRelated = AUTH_COOKIE_RE.test(name);
    out.push({
      finding_type: "cookie-missing-flags",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      cookieName: name,
      missingFlags: missing,
      authRelated,
      severity: severityFor(authRelated, missing),
      detail: `Cookie "${name}" is set without ${missing.join(", ")}. ${
        authRelated ? "This is auth-related — " : ""
      }add the missing flags.`,
    });
  }

  SET_COOKIE_HEADER_RE.lastIndex = 0;
  for (const m of text.matchAll(SET_COOKIE_HEADER_RE)) {
    const name = m[1]!.trim();
    const attrs = m[3] ?? "";
    const missing = missingFromHeaderAttrs(attrs);
    if (missing.length === 0) continue;
    const authRelated = AUTH_COOKIE_RE.test(name);
    out.push({
      finding_type: "cookie-missing-flags",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      cookieName: name,
      missingFlags: missing,
      authRelated,
      severity: severityFor(authRelated, missing),
      detail: `Set-Cookie "${name}" missing ${missing.join(", ")}.`,
    });
  }

  return out;
}
