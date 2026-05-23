// Security-headers posture (synthesis §3.5, Decision 15).
//
// The OWASP Secure Headers 2026 baseline: CSP, HSTS, X-Content-Type-Options
// nosniff, X-Frame-Options (or CSP frame-ancestors), Referrer-Policy,
// Permissions-Policy, COOP/COEP at Customer-facing+. We parse the headers a
// project declares across the stack — Next.js `headers()`, helmet registration,
// vercel.json, Netlify `_headers`, nginx `add_header` — and report which baseline
// headers are missing.
//
// Two routing nuances encoded here:
//   - X-XSS-Protection is deprecated — never recommend adding it (only flag a
//     stale present value as informational).
//   - CSP report-only is the auto-apply form (Decision 15); enforcing CSP is
//     always staged. So a missing CSP routes the recommendation to report-only.

export type SecurityHeader =
  | "content-security-policy"
  | "strict-transport-security"
  | "x-content-type-options"
  | "x-frame-options"
  | "referrer-policy"
  | "permissions-policy";

export interface HeaderPosture {
  /** Which baseline headers were found declared somewhere in the project. */
  present: Set<SecurityHeader>;
  /** Which baseline headers are missing. */
  missing: SecurityHeader[];
  /** True when a CSP exists in report-only mode (vs enforcing). */
  cspReportOnly: boolean;
  /** True when a deprecated X-XSS-Protection header is set (informational). */
  hasDeprecatedXssHeader: boolean;
}

const BASELINE: SecurityHeader[] = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

const HEADER_PATTERNS: Record<SecurityHeader, RegExp> = {
  "content-security-policy": /content-security-policy/i,
  "strict-transport-security": /strict-transport-security/i,
  "x-content-type-options": /x-content-type-options/i,
  "x-frame-options": /x-frame-options/i,
  "referrer-policy": /referrer-policy/i,
  "permissions-policy": /permissions-policy/i,
};

// helmet defaults set CSP, HSTS, nosniff, frameguard, referrer-policy when
// registered with no options — so a bare helmet() registration counts as
// declaring most of the baseline.
const HELMET_DEFAULT_HEADERS: SecurityHeader[] = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
];

/**
 * Analyze a concatenated blob of the project's header-declaring config + source.
 * The caller is responsible for gathering the relevant files (next.config,
 * vercel.json, _headers, nginx.conf, the middleware/helmet source) into `text`.
 */
export function analyzeHeaders(text: string): HeaderPosture {
  const present = new Set<SecurityHeader>();

  // Bare helmet() with no disabling options → most of the baseline.
  const helmetCall = /\bhelmet\s*\(/.test(text);
  if (helmetCall) {
    for (const h of HELMET_DEFAULT_HEADERS) present.add(h);
  }

  for (const h of BASELINE) {
    if (HEADER_PATTERNS[h].test(text)) present.add(h);
  }

  const cspReportOnly =
    /content-security-policy-report-only/i.test(text) &&
    !/\bcontent-security-policy\b(?!-report)/i.test(text);

  const missing = BASELINE.filter((h) => !present.has(h));
  const hasDeprecatedXssHeader = /x-xss-protection/i.test(text);

  return { present, missing, cspReportOnly, hasDeprecatedXssHeader };
}

export interface HeaderFinding {
  finding_type: "missing-security-header" | "deprecated-xss-header";
  header: string;
  /** Auto for additive missing headers (Decision 15); CSP recommends report-only. */
  fix_class: "auto" | "stage" | "advisory";
  detail: string;
}

/**
 * Turn a posture into findings. Missing additive headers route to Auto; a
 * missing CSP routes to Auto-as-report-only (enforcing CSP is always staged).
 * The deprecated X-XSS-Protection header is advisory-only.
 */
export function headerFindings(posture: HeaderPosture): HeaderFinding[] {
  const out: HeaderFinding[] = [];
  for (const h of posture.missing) {
    if (h === "content-security-policy") {
      out.push({
        finding_type: "missing-security-header",
        header: h,
        fix_class: "auto",
        detail:
          "No Content-Security-Policy. Add it in report-only mode first (auto-applicable) so you can watch for breakage before enforcing — enforcing CSP is always staged for review.",
      });
    } else {
      out.push({
        finding_type: "missing-security-header",
        header: h,
        fix_class: "auto",
        detail: `Missing ${h}. Additive — safe to auto-apply.`,
      });
    }
  }
  if (posture.hasDeprecatedXssHeader) {
    out.push({
      finding_type: "deprecated-xss-header",
      header: "x-xss-protection",
      fix_class: "advisory",
      detail:
        "X-XSS-Protection is deprecated and can introduce vulnerabilities. Remove it and rely on a Content-Security-Policy instead. Do not add it.",
    });
  }
  return out;
}
