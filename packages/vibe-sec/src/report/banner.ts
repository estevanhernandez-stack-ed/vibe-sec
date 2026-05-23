// Terminal banner — the ANSI in-chat channel (spec §7 channel 2; checklist 3.5).
//
// Live curation + education surface. Renders the four-band report compact for the
// terminal: severity counts, Band-1 action items, an abbreviated authorization
// matrix, the Band-4 complement leads. The first-run "scanning full git history"
// note already lives in the secrets scan SKILL — this banner is the post-scan
// summary, not the progress line.
//
// Color is opt-in (isTty + !noColor) so CI logs stay clean. No emoji in working
// output — glyphs are ASCII.

import { type Severity, SEVERITY_ORDER } from "../types.js";
import type { Finding } from "../state/findings.js";
import type { BandedReport } from "./bands.js";
import { graduationNote } from "./bands.js";
import type { AuthzMatrix } from "../detectors/auth-model/authz-matrix.js";
import { cellGlyph } from "../detectors/auth-model/authz-matrix.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[41;97m",
  high: "\x1b[31;1m",
  medium: "\x1b[33m",
  low: "\x1b[90m",
};
const RESET = "\x1b[0m";
const GREEN = "\x1b[32;1m";
const BOLD = "\x1b[1m";

export interface BannerOptions {
  /** Repo root, shown in the header line. */
  root?: string;
  /** Weighted score in [0,1], shown vs the tier threshold. */
  score?: number;
  /** The tier threshold the score is measured against. */
  threshold?: number;
  /** Gate pass/fail, shown as the verdict line. */
  gatePass?: boolean;
  /** Tools that produced findings this run, credited in the header. */
  toolsUsed?: readonly string[];
  /** The authorization matrix, rendered abbreviated when present. */
  authzMatrix?: AuthzMatrix | null;
  /** Disable ANSI color (CI / piped output). */
  noColor?: boolean;
  /** Whether stdout is a TTY (color only applies when true). */
  isTty?: boolean;
}

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const acc: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) acc[f.severity_tier_adjusted] += 1;
  return acc;
}

/**
 * Render the four-band report as an ANSI terminal banner.
 * Pure: returns the string, performs no I/O. The caller writes it to stdout.
 */
export function renderBanner(
  report: BandedReport,
  opts: BannerOptions = {},
): string {
  const useColor = Boolean(opts.isTty) && !opts.noColor;
  const c = useColor
    ? (code: string, s: string) => code + s + RESET
    : (_code: string, s: string) => s;

  const lines: string[] = [];
  const tools = opts.toolsUsed && opts.toolsUsed.length ? opts.toolsUsed.join(", ") : "in-house";

  lines.push("");
  lines.push(`  ${c(BOLD, "vibe-sec audit")} · tier: ${opts.root ? `${report.tier}` : report.tier} · ${tools}`);
  if (opts.root) lines.push(`  ${opts.root}`);

  // Score + gate verdict.
  if (typeof opts.score === "number") {
    const pct = (opts.score * 100).toFixed(0);
    const bar =
      typeof opts.threshold === "number"
        ? ` / ${(opts.threshold * 100).toFixed(0)}% ${report.tier} bar`
        : "";
    lines.push(`  weighted score: ${pct}%${bar}`);
  }
  if (typeof opts.gatePass === "boolean") {
    lines.push(
      opts.gatePass
        ? `  ${c(GREEN, "PASS")} — meets the ${report.tier} bar`
        : `  ${c(SEVERITY_COLORS.critical, "FAIL")} — below the ${report.tier} bar`,
    );
  }
  lines.push("");

  // Severity rollup across in-scope (Band 1 + Band 2) findings.
  const inScope = [...report.band1, ...report.band2];
  const counts = countBySeverity(inScope);
  const total = inScope.length;
  if (total === 0) {
    lines.push(`  ${c(GREEN, "clean")} — no in-scope findings at this tier.`);
  } else {
    const parts: string[] = [];
    for (const sev of ["critical", "high", "medium", "low"] as Severity[]) {
      if (counts[sev]) parts.push(c(SEVERITY_COLORS[sev], `${counts[sev]} ${sev}`));
    }
    lines.push(`  ${parts.join("  ")}`);
  }
  lines.push("");

  // Band 1 — action now.
  if (report.band1.length) {
    lines.push(`  ${c(BOLD, "Band 1 — action needed now")}`);
    for (const f of report.band1.slice(0, 12)) {
      lines.push(
        `    ${c(SEVERITY_COLORS[f.severity_tier_adjusted], f.severity_tier_adjusted.toUpperCase().padEnd(9))} ${f.title}${locSuffix(f)}`,
      );
    }
    if (report.band1.length > 12) {
      lines.push(`    … and ${report.band1.length - 12} more (see the markdown report)`);
    }
    lines.push("");
  }

  // Band 2 — worth reading (compact count; full text in markdown).
  if (report.band2.length) {
    lines.push(
      `  ${c(BOLD, "Band 2 — tier-appropriate, worth reading")}: ${report.band2.length} item(s)`,
    );
    lines.push("");
  }

  // Band 3 — graduating guidance.
  if (report.band3.length) {
    lines.push(
      `  ${c(BOLD, "Band 3 — if you graduate")}: ${report.band3.length} item(s). ${graduationNote(report.tier)}`,
    );
    lines.push("");
  }

  // Band 4 — Pattern #13 complements.
  if (report.band4.length) {
    lines.push(`  ${c(BOLD, "Band 4 — tools that catch what we miss")}`);
    for (const cm of report.band4.slice(0, 5)) {
      lines.push(`    ${cm.tool} — ${cm.reason}`);
    }
    lines.push("");
  }

  // Abbreviated authorization matrix (the signature artifact, compact form).
  if (opts.authzMatrix && opts.authzMatrix.rows.length) {
    lines.push(`  ${c(BOLD, "authorization matrix (abbreviated)")}`);
    lines.push(renderAuthzMatrixAbbreviated(opts.authzMatrix));
    lines.push("");
  }

  return lines.join("\n");
}

function locSuffix(f: Finding): string {
  if (f.file && f.line) return `  (${f.file}:${f.line})`;
  if (f.file) return `  (${f.file})`;
  if (f.surface) return `  (${f.surface})`;
  return "";
}

/**
 * Abbreviated authz matrix for the terminal — only routes with an ABSENT cell,
 * capped at 10 rows. The full matrix renders in the markdown report via
 * renderMatrixMarkdown(). This is the "where's the gap" curation, not the table.
 */
export function renderAuthzMatrixAbbreviated(matrix: AuthzMatrix): string {
  const gaps = matrix.rows.filter((r) =>
    matrix.dimensions.some((d) => r.cells[d] === "absent"),
  );
  if (gaps.length === 0) {
    return "    all inventoried routes enforce auth where applicable.";
  }
  const lines = gaps.slice(0, 10).map((r) => {
    const absentDims = matrix.dimensions
      .filter((d) => r.cells[d] === "absent")
      .map((d) => `${d}=${cellGlyph(r.cells[d])}`)
      .join(", ");
    return `    ${r.method.padEnd(6)} ${r.route} — ${absentDims}`;
  });
  if (gaps.length > 10) {
    lines.push(`    … and ${gaps.length - 10} more routes with gaps`);
  }
  return lines.join("\n");
}

/** Pull the worst severity in a set — exported for callers building verdicts. */
export function worstSeverity(findings: readonly Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_ORDER[f.severity_tier_adjusted] > SEVERITY_ORDER[worst]) {
      worst = f.severity_tier_adjusted;
    }
  }
  return worst;
}
