// Abuse-monitoring presence (spec §4.7, synthesis §3.7).
//
// Rate limiting without monitoring is half a control — you can't tell whether
// limits are firing under attack. This pass checks for the monitoring side:
//   - structured logging on a 429 (res.status(429) with a log/metric nearby),
//   - a metrics increment / alerting hook around the limiter.
// The absence is an advisory (low) signal, dual-tagged A04 (Insecure Design) +
// A09 (Logging Failures) by the mapper. It only matters once a limiter exists;
// the orchestrator gates it on "a limiter was detected."

import { lineOf } from "../source-walk.js";

export interface AbuseMonitoringFinding {
  finding_type: "rate-limit-without-monitoring";
  file: string | null;
  line: number | null;
  detail: string;
}

// A 429 response being sent.
const STATUS_429_RE = /\b(?:status\s*\(\s*429|statusCode\s*=\s*429|\.status\s*=\s*429|sendStatus\s*\(\s*429)/g;
// Monitoring around it: a log, metric, or alert call.
const MONITORING_RE =
  /\b(?:logger?\.\w+|console\.\w+|metrics?\.\w+|statsd|datadog|increment\s*\(|captureMessage|track\s*\(|alert\s*\()/i;

/**
 * Scan one file. When it sends a 429 but has no monitoring call nearby, surface
 * the gap. Returns the per-file findings; the orchestrator decides whether to
 * emit based on whether any limiter exists project-wide.
 */
export function scanAbuseMonitoring(text: string, filePath: string): AbuseMonitoringFinding[] {
  const findings: AbuseMonitoringFinding[] = [];
  STATUS_429_RE.lastIndex = 0;
  for (const m of text.matchAll(STATUS_429_RE)) {
    const idx = m.index ?? 0;
    const window = text.slice(Math.max(0, idx - 200), Math.min(text.length, idx + 200));
    if (!MONITORING_RE.test(window)) {
      findings.push({
        finding_type: "rate-limit-without-monitoring",
        file: filePath,
        line: lineOf(text, idx),
        detail:
          "A 429 (rate-limited) response is sent with no logging/metric nearby. Without monitoring you can't see abuse as it happens or tell whether limits are tuned. Log the throttled event (no PII) and emit a metric.",
      });
    }
  }
  return findings;
}
