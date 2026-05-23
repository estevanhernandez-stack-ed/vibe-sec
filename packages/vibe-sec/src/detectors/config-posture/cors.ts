// CORS posture (synthesis §3.5).
//
// The one CORS misconfiguration that's an unconditional Critical: reflecting
// the request origin AND allowing credentials. `origin: true, credentials: true`
// (or a callback that always returns the origin) means any site can make
// authenticated cross-origin requests with the victim's cookies — a CSRF
// bypass. The browser refuses `Access-Control-Allow-Origin: *` with credentials,
// so attackers use origin reflection instead; that's exactly this pattern.
//
// We detect the two common shapes in Express/Fastify `cors()` config and in
// hand-rolled header-setting. Wildcard origin WITHOUT credentials is a separate,
// lower-severity finding (overly permissive, but not a credential leak).

export interface CorsFinding {
  finding_type:
    | "cors-origin-reflection-with-credentials"
    | "cors-wildcard-origin"
    | "cors-credentials-with-dynamic-origin";
  severity: "critical" | "high" | "medium";
  file: string;
  line: number;
  detail: string;
}

// `origin: true` + `credentials: true` in a cors() options object.
const ORIGIN_TRUE_RE = /\borigin\s*:\s*true\b/;
// A callback that calls back with (null, true) — always-allow reflection.
const ORIGIN_CALLBACK_REFLECT_RE =
  /origin\s*:\s*(?:\(|function)[^)]*\)\s*=>?\s*\{?[^}]*\bcb?\s*\(\s*null\s*,\s*true\s*\)/s;
const CREDENTIALS_TRUE_RE = /\bcredentials\s*:\s*true\b/;
const ORIGIN_WILDCARD_RE = /\borigin\s*:\s*["']\*["']/;
// Reflecting req.headers.origin straight back.
const REFLECT_HEADER_RE =
  /Access-Control-Allow-Origin["']?\s*[,)]?\s*,?\s*(?:req\.headers\.origin|origin)\b/;
const ACAO_WILDCARD_HEADER_RE =
  /Access-Control-Allow-Origin["']\s*,\s*["']\*["']/;
const ACAC_TRUE_HEADER_RE =
  /Access-Control-Allow-Credentials["']\s*,\s*["']?true["']?/;

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

/** Scan a source file for CORS misconfigurations. */
export function scanCors(text: string, filePath: string): CorsFinding[] {
  const findings: CorsFinding[] = [];

  const hasCredentials = CREDENTIALS_TRUE_RE.test(text) || ACAC_TRUE_HEADER_RE.test(text);
  const reflectsOrigin =
    ORIGIN_TRUE_RE.test(text) ||
    ORIGIN_CALLBACK_REFLECT_RE.test(text) ||
    REFLECT_HEADER_RE.test(text);

  // Critical: origin reflection + credentials.
  if (hasCredentials && reflectsOrigin) {
    const idx = text.search(ORIGIN_TRUE_RE) >= 0 ? text.search(ORIGIN_TRUE_RE) : text.search(CREDENTIALS_TRUE_RE);
    findings.push({
      finding_type: "cors-origin-reflection-with-credentials",
      severity: "critical",
      file: filePath,
      line: lineOf(text, Math.max(0, idx)),
      detail:
        "CORS reflects the request origin AND allows credentials. Any site can make authenticated cross-origin requests with the user's cookies. Replace the reflected origin with an explicit allowlist.",
    });
    return findings; // the Critical subsumes the lower wildcard finding
  }

  // High: wildcard origin with credentials (browsers block it, but the intent
  // is the leak — and some setups special-case it).
  if (hasCredentials && (ORIGIN_WILDCARD_RE.test(text) || ACAO_WILDCARD_HEADER_RE.test(text))) {
    findings.push({
      finding_type: "cors-credentials-with-dynamic-origin",
      severity: "high",
      file: filePath,
      line: lineOf(text, text.search(ORIGIN_WILDCARD_RE)),
      detail:
        "Wildcard CORS origin combined with credentials. Browsers reject this combination, but the configuration intent leaks credentials — use an explicit allowlist.",
    });
    return findings;
  }

  // Medium: wildcard origin without credentials — overly permissive.
  if (ORIGIN_WILDCARD_RE.test(text) || ACAO_WILDCARD_HEADER_RE.test(text)) {
    findings.push({
      finding_type: "cors-wildcard-origin",
      severity: "medium",
      file: filePath,
      line: lineOf(text, text.search(ORIGIN_WILDCARD_RE)),
      detail:
        "CORS allows any origin (*). Acceptable for public read-only APIs; tighten to an allowlist if responses are user-specific.",
    });
  }

  return findings;
}
