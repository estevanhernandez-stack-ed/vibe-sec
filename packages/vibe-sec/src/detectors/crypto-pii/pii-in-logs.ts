// PII-in-logs call-site scan (spec §4.4, synthesis §3.4; A09 cross-tag).
//
// Logging PII is a quiet GDPR/CCPA problem: console.log(user.email),
// logger.info({ ssn }), Sentry.captureException(err, { user: { email } }). The
// finding scales with destination — a local console.log is Medium; piping PII to
// a third-party tracker (Sentry / Datadog / LogRocket / PostHog / Mixpanel) is a
// cross-border-transfer problem (GDPR Art. 44) and is Critical at Public-facing+
// (tier scaling happens in the mapper; the detector reports the base severity:
// High for third-party sinks, Medium for local logs).
//
// We detect a log/tracker call whose arguments reference a PII-shaped identifier
// (matching the same field-name library the inventory uses). This is shared
// schema with rate-limiting's safe-log-shape concern (synthesis §3.7 delegation).

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface PiiLogFinding {
  finding_type: "pii-in-local-log" | "pii-in-third-party-tracker";
  severity: Severity;
  sink: string;
  piiHint: string;
  file: string;
  line: number;
  detail: string;
}

// Local logging sinks.
const LOCAL_LOG_RE = /\b(?:console\.(?:log|info|warn|error|debug)|logger\.\w+|winston\.\w+|pino\(\)\.\w+|fastify\.log\.\w+)\s*\(/g;
// Third-party tracker sinks (cross-border transfer surface).
const TRACKER_RE =
  /\b(?:Sentry\.\w+|datadog\w*\.\w+|LogRocket\.\w+|posthog\.\w+|mixpanel\.\w+|amplitude\.\w+|analytics\.\w+|Bugsnag\.\w+|rollbar\.\w+)\s*\(/g;

// PII-shaped identifiers in the call arguments (reuses the inventory vocabulary).
const PII_ARG_RE =
  /\b(email|phone|ssn|password|passwd|creditCard|cardNumber|cvv|dateOfBirth|dob|passport|driverLicense|address|fullName|firstName|lastName|nationalId|taxId|medicalRecord|diagnosis|bloodType|ipAddress|geolocation)\b/i;

function argSpan(text: string, openParenIdx: number): string {
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

function scanSink(
  text: string,
  filePath: string,
  re: RegExp,
  finding_type: PiiLogFinding["finding_type"],
  severity: Severity,
): PiiLogFinding[] {
  const out: PiiLogFinding[] = [];
  re.lastIndex = 0;
  for (const m of text.matchAll(re)) {
    const idx = m.index ?? 0;
    const openParen = idx + m[0].length - 1;
    const args = argSpan(text, openParen);
    const piiMatch = args.match(PII_ARG_RE);
    if (piiMatch) {
      out.push({
        finding_type,
        severity,
        sink: m[0].replace(/\($/, "").trim(),
        piiHint: piiMatch[1] ?? piiMatch[0],
        file: filePath,
        line: lineOf(text, idx),
        detail:
          finding_type === "pii-in-third-party-tracker"
            ? `PII (${piiMatch[1] ?? piiMatch[0]}) sent to a third-party tracker. This is a cross-border personal-data transfer (GDPR Art. 44). Redact PII before it leaves your infrastructure, or scrub it in the tracker's beforeSend hook.`
            : `PII (${piiMatch[1] ?? piiMatch[0]}) written to logs. Logs are retained, replicated, and often shipped off-box. Redact or hash PII before logging it.`,
      });
    }
  }
  return out;
}

/** Scan one source file for PII flowing into log/tracker call sites. */
export function scanPiiInLogs(text: string, filePath: string): PiiLogFinding[] {
  return [
    ...scanSink(text, filePath, TRACKER_RE, "pii-in-third-party-tracker", "high"),
    ...scanSink(text, filePath, LOCAL_LOG_RE, "pii-in-local-log", "medium"),
  ];
}
