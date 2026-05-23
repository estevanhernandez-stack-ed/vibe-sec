// Markdown report — the durable artifact channel (spec §7 channel 1; checklist 3.5).
//
// Runbook-grade, diffable, written to docs/vibe-sec/<command>-report.md. Two
// structural moves the banner doesn't do:
//
//   1. The full four-band report with every finding rendered (banner abbreviates
//      Band 2/3/4 to counts; markdown carries the full text).
//   2. An OWASP-category-grouped subsection (Conflict 10 = A) — one finding is
//      rendered under EACH OWASP category it carries (2021 + 2025), with an
//      "also tagged as…" annotation so the dedup semantics stay clear: it's one
//      finding wearing all its tags, not duplicate findings.
//
// The authorization matrix renders via the existing renderMatrixMarkdown().
// Pure: returns the markdown string; the caller writes it to disk.

import { type Severity, type Tier, SEVERITY_ORDER } from "../types.js";
import type { Finding } from "../state/findings.js";
import type { BandedReport } from "./bands.js";
import { graduationNote } from "./bands.js";
import { dualTag, type Owasp2021 } from "../detectors/owasp-survey/dual-tag.js";
import {
  type AuthzMatrix,
  renderMatrixMarkdown,
} from "../detectors/auth-model/authz-matrix.js";
import { TIER_ASVS_LABEL, TIER_THRESHOLDS } from "../scoring/weighted-score.js";

export interface MarkdownReportOptions {
  /** The command this report came from (audit / scan / deps), for the filename + title. */
  command?: string;
  /** Weighted score in [0,1]. */
  score?: number;
  /** Gate pass/fail. */
  gatePass?: boolean;
  /** Tools that produced findings, credited in the header. */
  toolsUsed?: readonly string[];
  /** The authorization matrix, rendered in full when present. */
  authzMatrix?: AuthzMatrix | null;
  /** ISO timestamp for the report header; defaults to now. */
  generatedAt?: string;
}

const OWASP_TITLES: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable & Outdated Components",
  A07: "Identification & Authentication Failures",
  A08: "Software & Data Integrity Failures",
  A09: "Security Logging & Monitoring Failures",
  A10: "Server-Side Request Forgery (SSRF)",
};

function sevTag(s: Severity): string {
  return `**${s.toUpperCase()}**`;
}

function findingLine(f: Finding): string {
  const loc = f.file ? ` — \`${f.file}${f.line ? `:${f.line}` : ""}\`` : f.surface ? ` — \`${f.surface}\`` : "";
  const tool = f.tool_of_record !== "in-house" ? ` _(via ${f.tool_of_record})_` : "";
  return `- ${sevTag(f.severity_tier_adjusted)} **${f.title}**${loc}${tool}\n  ${f.description}`;
}

/**
 * Render the four-band report + OWASP-grouped subsection as markdown.
 * Findings should already be deduped by id (caller uses readFindingsDeduped).
 */
export function renderMarkdownReport(
  report: BandedReport,
  opts: MarkdownReportOptions = {},
): string {
  const command = opts.command ?? "audit";
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const out: string[] = [];

  // ─── Header ────────────────────────────────────────────────────────────
  out.push(`# Vibe Sec — ${command} report`);
  out.push("");
  out.push(`> Generated ${generatedAt}`);
  out.push("");
  out.push(`**Tier:** ${report.tier} (${TIER_ASVS_LABEL[report.tier]})`);
  out.push(`**Pass bar:** ${(TIER_THRESHOLDS[report.tier] * 100).toFixed(0)}%`);
  if (typeof opts.score === "number") {
    out.push(`**Weighted score:** ${(opts.score * 100).toFixed(0)}%`);
  }
  if (typeof opts.gatePass === "boolean") {
    out.push(`**Gate:** ${opts.gatePass ? "PASS" : "FAIL"}`);
  }
  if (opts.toolsUsed && opts.toolsUsed.length) {
    out.push(`**Tools of record:** ${opts.toolsUsed.join(", ")}`);
  } else {
    out.push(`**Tools of record:** in-house baseline`);
  }
  out.push("");

  // ─── Band 1 ───────────────────────────────────────────────────────────
  out.push("## Band 1 — action needed now");
  out.push("");
  out.push("_Critical and High findings in concerns that are in scope at this tier._");
  out.push("");
  if (report.band1.length === 0) {
    out.push("No critical or high findings. Clean at this tier.");
  } else {
    for (const f of report.band1) out.push(findingLine(f));
  }
  out.push("");

  // ─── Band 2 ───────────────────────────────────────────────────────────
  out.push("## Band 2 — tier-appropriate, worth reading");
  out.push("");
  out.push(
    "_Medium and Low findings at this tier, plus the OWASP 2021 → 2025 reclassifications worth knowing._",
  );
  out.push("");
  if (report.band2.length === 0) {
    out.push("Nothing in this band.");
  } else {
    for (const f of report.band2) {
      out.push(findingLine(f));
      // Surface the reclassification education when the pair shifted.
      if (f.owasp_2021 && f.owasp_2025 && f.owasp_2021 !== f.owasp_2025) {
        const tags = dualTag(f.owasp_2021 as Owasp2021);
        if (tags.shiftNote) out.push(`  > ${tags.shiftNote}`);
      }
    }
  }
  out.push("");

  // ─── Band 3 ───────────────────────────────────────────────────────────
  out.push("## Band 3 — if you graduate");
  out.push("");
  out.push(`_${graduationNote(report.tier)}_`);
  out.push("");
  if (report.band3.length === 0) {
    out.push("Nothing tier-inappropriate surfaced — every finding is in scope now.");
  } else {
    for (const f of report.band3) out.push(findingLine(f));
  }
  out.push("");

  // ─── Band 4 ───────────────────────────────────────────────────────────
  out.push("## Band 4 — tools that catch what the baseline misses");
  out.push("");
  out.push("_Pattern #13 complements, led by your detected context. Run these on a future pass when you're not mid-fatigue._");
  out.push("");
  if (report.band4.length === 0) {
    out.push("No additional tool recommendations for this context.");
  } else {
    for (const cm of report.band4) {
      out.push(`- **${cm.tool}** (${cm.concern}) — ${cm.reason}`);
    }
  }
  out.push("");

  // ─── OWASP-category-grouped subsection (Conflict 10 = A) ───────────────
  out.push(renderOwaspGrouped([...report.band1, ...report.band2, ...report.band3]));

  // ─── Authorization matrix ─────────────────────────────────────────────
  if (opts.authzMatrix && opts.authzMatrix.rows.length) {
    out.push("## Authorization matrix");
    out.push("");
    out.push(
      "_The signature artifact: every inventoried route × the authz dimensions. `ABSENT` is where the gap is._",
    );
    out.push("");
    out.push(renderMatrixMarkdown(opts.authzMatrix));
    out.push("");
  }

  return out.join("\n");
}

/**
 * OWASP-category-grouped subsection (Conflict 10 = A: one finding, all tags).
 *
 * A finding tagged owasp_2021=A02 + owasp_2025=A04 renders under BOTH the A02
 * and the A04 heading, each copy annotated "also tagged as A04-2025 / A02-2021"
 * so the reader sees it's one finding wearing all its tags — not duplicates.
 * This is Option B's "render under every category" UX with Option A's dedup
 * semantics (the finding is counted once in the score; only the rendering fans out).
 */
export function renderOwaspGrouped(findings: readonly Finding[]): string {
  const out: string[] = ["## By OWASP category", ""];
  out.push(
    "_One finding is rendered under each OWASP category it carries (2021 + 2025). It's one finding wearing all its tags — counted once in the score, shown under every applicable category here._",
  );
  out.push("");

  // category key → "2021" | "2025" → findings rendered under it
  type Edition = "2021" | "2025";
  const byCategory = new Map<string, Map<Edition, Finding[]>>();

  const add = (cat: string | null, edition: Edition, f: Finding): void => {
    if (!cat) return;
    let editions = byCategory.get(cat);
    if (!editions) {
      editions = new Map();
      byCategory.set(cat, editions);
    }
    const arr = editions.get(edition) ?? [];
    arr.push(f);
    editions.set(edition, arr);
  };

  for (const f of findings) {
    add(f.owasp_2021, "2021", f);
    // Only fan out to a separate 2025 entry when it differs from 2021.
    if (f.owasp_2025 && f.owasp_2025 !== f.owasp_2021) {
      add(f.owasp_2025, "2025", f);
    }
  }

  if (byCategory.size === 0) {
    out.push("No findings carry an OWASP category.");
    out.push("");
    return out.join("\n");
  }

  // Render A01..A10 in order.
  const ordered = [...byCategory.keys()].sort();
  for (const cat of ordered) {
    const editions = byCategory.get(cat)!;
    const title = OWASP_TITLES[cat] ?? cat;
    out.push(`### ${cat} — ${title}`);
    out.push("");
    // Dedup findings within a category (a finding tagged the same cat in both
    // editions should render once here), keep stable order by severity.
    const seen = new Set<string>();
    const merged: Finding[] = [];
    for (const ed of ["2021", "2025"] as Edition[]) {
      for (const f of editions.get(ed) ?? []) {
        if (seen.has(f.id)) continue;
        seen.add(f.id);
        merged.push(f);
      }
    }
    merged.sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity_tier_adjusted] -
        SEVERITY_ORDER[a.severity_tier_adjusted],
    );
    for (const f of merged) {
      out.push(findingLine(f));
      out.push(`  > also tagged as: ${alsoTaggedAs(f, cat)}`);
    }
    out.push("");
  }

  return out.join("\n");
}

/**
 * The "also tagged as…" annotation for a finding rendered under category `cat`.
 * Lists the OTHER OWASP editions/categories the finding carries, plus the
 * secondary concerns — so the cross-tagging is explicit at the point of render.
 */
export function alsoTaggedAs(f: Finding, cat: string): string {
  const tags: string[] = [];
  if (f.owasp_2021 && f.owasp_2021 !== cat) tags.push(`${f.owasp_2021}-2021`);
  if (f.owasp_2025 && f.owasp_2025 !== cat) tags.push(`${f.owasp_2025}-2025`);
  // When the current heading IS one edition, name the other edition explicitly.
  if (f.owasp_2021 === cat && f.owasp_2025 && f.owasp_2025 !== cat) {
    // already added above
  } else if (f.owasp_2025 === cat && f.owasp_2021 && f.owasp_2021 !== cat) {
    // already added above
  }
  if (f.secondary_concerns.length) {
    tags.push(`secondary: ${f.secondary_concerns.join(", ")}`);
  }
  tags.push(`primary concern: ${f.primary_concern}`);
  return tags.join("; ");
}
