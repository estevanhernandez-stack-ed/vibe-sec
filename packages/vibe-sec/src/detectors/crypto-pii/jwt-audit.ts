// JWT algorithm audit (spec §4.4, synthesis §3.4).
//
// Three Critical JWT findings, all about who controls the verification algorithm:
//   1. `none` algorithm — `jwt.sign(payload, key, { algorithm: 'none' })` or a
//      verify that accepts `none`. An unsigned token is forgeable by anyone.
//   2. jwt.verify WITHOUT an `algorithms:` constraint — the classic algorithm-
//      confusion / downgrade vector. An attacker can flip RS256 → HS256 and sign
//      with the public key, or present a `none` token. Always pin algorithms.
//   3. A short HS256 secret (< 32 bytes) — brute-forceable. A hardcoded literal
//      secret short enough to count bytes, or an obvious `|| 'fallback'`.
//
// A `|| 'somesecret'` fallback on the signing secret is its own finding — it
// means the app silently signs with a known constant when the env var is unset.
//
// All JWT-secret literals in tests/fixtures must be obviously fake + short
// (push-protection rule): the detector reads byte length, not provider shape, so
// a 12-char "devsecret123" exercises the short-secret path without resembling a
// real key.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface JwtFinding {
  finding_type:
    | "jwt-none-algorithm"
    | "jwt-verify-missing-algorithms"
    | "jwt-short-secret"
    | "jwt-secret-fallback";
  severity: Severity;
  file: string;
  line: number;
  detail: string;
}

const HS256_MIN_SECRET_BYTES = 32;

// algorithm(s): 'none' anywhere in a jwt options object.
const NONE_ALGO_RE = /\balgorithms?\s*:\s*(?:\[\s*)?["'`]none["'`]/gi;
// jwt.verify(...) call — we then check whether the same call has an algorithms: key.
const JWT_VERIFY_RE = /\bjwt\s*\.\s*verify\s*\(/g;
// A literal signing secret: jwt.sign(payload, "literal", …) — second arg string.
const JWT_SIGN_LITERAL_RE = /\bjwt\s*\.\s*sign\s*\([^,]+,\s*["'`]([^"'`]+)["'`]/g;
// `process.env.JWT_SECRET || 'fallback'` — a constant fallback secret.
const SECRET_FALLBACK_RE =
  /process\.env\.\w*(?:JWT|SECRET|TOKEN|NEXTAUTH)\w*\s*(?:\?\?|\|\|)\s*["'`]([^"'`]+)["'`]/gi;

/**
 * Given the index of a `jwt.verify(` token, grab the call's argument span (a
 * shallow brace-balanced slice) so we can check for an `algorithms:` constraint.
 */
function callSpan(text: string, openParenIdx: number): string {
  let depth = 0;
  let i = openParenIdx;
  for (; i < text.length && i < openParenIdx + 600; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) break;
    }
  }
  return text.slice(openParenIdx, i + 1);
}

/** Scan one source file for JWT algorithm + secret weaknesses. */
export function scanJwt(text: string, filePath: string): JwtFinding[] {
  const findings: JwtFinding[] = [];

  // 1. `none` algorithm — Critical wherever it appears.
  NONE_ALGO_RE.lastIndex = 0;
  for (const m of text.matchAll(NONE_ALGO_RE)) {
    findings.push({
      finding_type: "jwt-none-algorithm",
      severity: "critical",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "JWT configured with the 'none' algorithm. An unsigned token is forgeable by anyone — drop 'none' and pin a real algorithm (e.g. HS256 or RS256).",
    });
  }

  // 2. jwt.verify without an algorithms: constraint — Critical.
  JWT_VERIFY_RE.lastIndex = 0;
  for (const m of text.matchAll(JWT_VERIFY_RE)) {
    const idx = m.index ?? 0;
    const openParen = idx + m[0].length - 1;
    const span = callSpan(text, openParen);
    if (!/\balgorithms\s*:/.test(span)) {
      findings.push({
        finding_type: "jwt-verify-missing-algorithms",
        severity: "critical",
        file: filePath,
        line: lineOf(text, idx),
        detail:
          "jwt.verify() has no `algorithms:` constraint. Without it, an attacker can downgrade the algorithm (RS256 → HS256 confusion) or present a 'none' token. Pin the expected algorithm(s): jwt.verify(token, key, { algorithms: ['HS256'] }).",
      });
    }
  }

  // 3a. Short literal signing secret — brute-forceable HS256 key.
  JWT_SIGN_LITERAL_RE.lastIndex = 0;
  for (const m of text.matchAll(JWT_SIGN_LITERAL_RE)) {
    const secret = m[1] ?? "";
    if (Buffer.byteLength(secret, "utf8") < HS256_MIN_SECRET_BYTES) {
      findings.push({
        finding_type: "jwt-short-secret",
        severity: "critical",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        detail: `JWT signed with a hardcoded ${Buffer.byteLength(secret, "utf8")}-byte secret (< ${HS256_MIN_SECRET_BYTES} bytes). Short HS256 secrets are brute-forceable. Use a 32+ byte random secret from the environment, and rotate this one.`,
      });
    }
  }

  // 3b. Constant fallback secret — silently signs with a known value.
  SECRET_FALLBACK_RE.lastIndex = 0;
  for (const m of text.matchAll(SECRET_FALLBACK_RE)) {
    const fallback = m[1] ?? "";
    const sev: Severity =
      Buffer.byteLength(fallback, "utf8") < HS256_MIN_SECRET_BYTES ? "critical" : "high";
    findings.push({
      finding_type: "jwt-secret-fallback",
      severity: sev,
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "JWT/session secret has a constant `|| fallback`. When the env var is unset the app signs with a known value anyone can forge against. Fail fast at boot instead — require the env var with no default.",
    });
  }

  return findings;
}
