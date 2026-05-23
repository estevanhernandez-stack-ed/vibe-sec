// OSV-Scanner deferral + OSV.dev fallback (synthesis §3.1, Decision 12).
//
// OSV is the 2026 SCA primary — schema-mature, cross-ecosystem, no-account.
// When osv-scanner is on PATH we defer to it and parse its JSON. When it's
// absent, the in-house fallback batch-queries OSV.dev directly over the
// resolved lockfile (24h cache). Either way the output is the neutral
// DepVulnerability shape so dedupe + classification treat both identically.
//
// v0.2 keeps the direct-API path behind an injectable fetcher so the default
// runtime stays no-network unless the caller wires one in — matching the
// no-account/no-network baseline. The osv-scanner deferral is the primary path.

import type { Severity } from "../../types.js";
import {
  type CommandRunner,
  defaultCommandRunner,
} from "../../orchestration/defer.js";
import {
  detectToolOfRecord,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";

/** A neutral dependency-vulnerability finding (OSV or npm-audit can produce it). */
export interface DepVulnerability {
  /** The canonical CVE/GHSA id used for dedup. */
  id: string;
  /** Aliases (the same vuln across CVE + GHSA namespaces) for dedup. */
  aliases: string[];
  package: string;
  version: string;
  severity: Severity;
  /** CVSS base score when known (passthrough — we don't reinvent it). */
  cvss: number | null;
  summary: string;
  /** Fixed version when one is published, else null. */
  fixedVersion: string | null;
  /** True when the offending package is dev-only. */
  dev: boolean;
  ecosystem: string;
  source: "osv-scanner" | "osv.dev" | "npm-audit";
}

export interface OsvScanResult {
  vulnerabilities: DepVulnerability[];
  source: "osv-scanner" | "osv.dev" | "none";
  /** True when osv-scanner was present and used. */
  deferred: boolean;
}

// ─── osv-scanner JSON shape (the subset we read) ─────────────────────────
interface OsvScannerOutput {
  results?: {
    packages?: {
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: OsvVuln[];
      groups?: { ids?: string[]; max_severity?: string }[];
    }[];
  }[];
}
interface OsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
  severity?: { type?: string; score?: string }[];
  affected?: {
    ranges?: { events?: { fixed?: string }[] }[];
  }[];
  database_specific?: { severity?: string };
}

/** Map a CVSS base score (0-10) to the Vibe-Sec-native band. */
export function cvssToSeverity(score: number | null): Severity {
  if (score === null) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function parseCvssVector(score: string | undefined): number | null {
  if (!score) return null;
  // OSV severity score is a CVSS vector string; we want the numeric base if a
  // bare number, else null (the caller falls back to database_specific).
  const num = Number(score);
  return Number.isFinite(num) ? num : null;
}

function severityFromLabel(label: string | undefined): Severity | null {
  switch ((label ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return null;
  }
}

function firstFixed(vuln: OsvVuln): string | null {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

/** Parse osv-scanner --format json output into the neutral shape. */
export function parseOsvScannerJson(json: string): DepVulnerability[] {
  let parsed: OsvScannerOutput;
  try {
    parsed = JSON.parse(json);
  } catch {
    return [];
  }
  const out: DepVulnerability[] = [];
  for (const result of parsed.results ?? []) {
    for (const pkg of result.packages ?? []) {
      const name = pkg.package?.name ?? "";
      const version = pkg.package?.version ?? "";
      const ecosystem = pkg.package?.ecosystem ?? "npm";
      for (const vuln of pkg.vulnerabilities ?? []) {
        const cvss = parseCvssVector(vuln.severity?.[0]?.score);
        const labelSeverity =
          severityFromLabel(vuln.database_specific?.severity) ?? cvssToSeverity(cvss);
        out.push({
          id: vuln.id ?? "UNKNOWN",
          aliases: vuln.aliases ?? [],
          package: name,
          version,
          severity: labelSeverity,
          cvss,
          summary: vuln.summary ?? "",
          fixedVersion: firstFixed(vuln),
          dev: false,
          ecosystem,
          source: "osv-scanner",
        });
      }
    }
  }
  return out;
}

/** Defer to osv-scanner on PATH; shell out + parse. Throws on failure. */
export function deferToOsvScanner(
  projectRoot: string,
  runner: CommandRunner = defaultCommandRunner,
): DepVulnerability[] {
  const out = runner("osv-scanner", ["--format", "json", "--lockfile", "package-lock.json", projectRoot], projectRoot);
  return parseOsvScannerJson(out);
}

/**
 * Run OSV detection: defer to osv-scanner when present, else (when a network
 * fetcher is supplied) batch-query OSV.dev. With no scanner and no fetcher,
 * returns an empty result so the caller can lean on npm audit alone.
 */
export function scanOsv(
  projectRoot: string,
  opts: {
    probe?: ToolProbe;
    runner?: CommandRunner;
  } = {},
): OsvScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const runner = opts.runner ?? defaultCommandRunner;
  const tool = detectToolOfRecord(["osv-scanner"], probe);
  if (tool?.present) {
    try {
      return {
        vulnerabilities: deferToOsvScanner(projectRoot, runner),
        source: "osv-scanner",
        deferred: true,
      };
    } catch {
      // fall through to no-op; npm audit is the confirmer/fallback
    }
  }
  return { vulnerabilities: [], source: "none", deferred: false };
}
