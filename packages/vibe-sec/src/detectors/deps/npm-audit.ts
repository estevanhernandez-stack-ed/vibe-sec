// npm audit confirmer (synthesis §3.1, Decisions 11/12/20).
//
// OSV wins on "does this CVE exist"; npm audit wins on "is there a fix and is
// it a breaking one." So we run both and dedupe by id (dedupe.ts). npm audit's
// `fixAvailable.isSemVerMajor` boolean is the fix-router:
//   - patch/minor in range → Auto (with lockfile-churn rollback, Decision 20)
//   - minor needing a range bump → Stage
//   - semver-major → Inline
//
// On application projects we pass --omit=dev (Decision 11) to drop the ~30%
// devDep noise. The npm interaction is behind the shared CommandRunner so tests
// feed canned `npm audit --json` output.

import type { Severity, FixClass } from "../../types.js";
import {
  type CommandRunner,
  defaultCommandRunner,
} from "../../orchestration/defer.js";
import type { DepVulnerability } from "./osv-client.js";

// ─── npm audit --json shape (npm v7+) ────────────────────────────────────
interface NpmAuditOutput {
  vulnerabilities?: Record<string, NpmAuditVuln>;
}
interface NpmAuditVuln {
  name?: string;
  severity?: string; // info|low|moderate|high|critical
  via?: (string | NpmAuditAdvisory)[];
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
  range?: string;
  isDirect?: boolean;
}
interface NpmAuditAdvisory {
  source?: number;
  name?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
  cvss?: { score?: number };
}

function npmSeverity(s: string | undefined): Severity {
  switch ((s ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
    case "info":
      return "low";
    default:
      return "medium";
  }
}

/**
 * Route an npm-audit fix to a fix class. The `isSemVerMajor` flag is the
 * load-bearing signal: a major bump can break the build, so it never auto-applies.
 */
export function routeFixFromAudit(
  fixAvailable: NpmAuditVuln["fixAvailable"],
): { fixClass: FixClass; fixedVersion: string | null; isMajor: boolean } {
  if (fixAvailable === false || fixAvailable === undefined) {
    return { fixClass: "inform-only", fixedVersion: null, isMajor: false };
  }
  if (fixAvailable === true) {
    // Simple in-range fix npm can apply → Auto (subject to churn rollback).
    return { fixClass: "auto", fixedVersion: null, isMajor: false };
  }
  const isMajor = Boolean(fixAvailable.isSemVerMajor);
  return {
    fixClass: isMajor ? "inline" : "stage",
    fixedVersion: fixAvailable.version ?? null,
    isMajor,
  };
}

/** Pull the canonical id (GHSA/CVE) + aliases from a via advisory. */
function idsFromVia(via: NpmAuditVuln["via"]): { id: string; aliases: string[]; cvss: number | null; summary: string } {
  for (const v of via ?? []) {
    if (typeof v === "object") {
      const url = v.url ?? "";
      const ghsa = url.match(/GHSA-[0-9a-z-]+/i)?.[0];
      const cve = (v.cwe ?? []).join(",");
      return {
        id: ghsa ?? `npm-${v.source ?? "advisory"}`,
        aliases: [ghsa, cve].filter(Boolean) as string[],
        cvss: v.cvss?.score ?? null,
        summary: v.title ?? "",
      };
    }
  }
  return { id: "npm-advisory", aliases: [], cvss: null, summary: "" };
}

export interface NpmAuditResult {
  vulnerabilities: (DepVulnerability & { fixClass: FixClass; isMajor: boolean })[];
  ran: boolean;
}

/** Parse `npm audit --json` output into the neutral shape + fix routing. */
export function parseNpmAudit(json: string): NpmAuditResult["vulnerabilities"] {
  let parsed: NpmAuditOutput;
  try {
    parsed = JSON.parse(json);
  } catch {
    return [];
  }
  const out: NpmAuditResult["vulnerabilities"] = [];
  for (const [pkgName, vuln] of Object.entries(parsed.vulnerabilities ?? {})) {
    const ids = idsFromVia(vuln.via);
    const route = routeFixFromAudit(vuln.fixAvailable);
    out.push({
      id: ids.id,
      aliases: ids.aliases,
      package: vuln.name ?? pkgName,
      version: vuln.range ?? "",
      severity: npmSeverity(vuln.severity),
      cvss: ids.cvss,
      summary: ids.summary,
      fixedVersion: route.fixedVersion,
      dev: false,
      ecosystem: "npm",
      source: "npm-audit",
      fixClass: route.fixClass,
      isMajor: route.isMajor,
    });
  }
  return out;
}

/**
 * Run `npm audit --json` (with --omit=dev on application projects). Never throws
 * — npm audit exits non-zero when vulns are found, which the runner surfaces as
 * a throw; we capture the stdout from that case via the runner contract. Tests
 * inject the runner.
 */
export function runNpmAudit(
  projectRoot: string,
  opts: { omitDev?: boolean; runner?: CommandRunner } = {},
): NpmAuditResult {
  const runner = opts.runner ?? defaultCommandRunner;
  const args = ["audit", "--json"];
  if (opts.omitDev) args.push("--omit=dev");
  let out = "";
  try {
    out = runner("npm", args, projectRoot);
  } catch (ex) {
    // npm audit exits 1 when vulns exist but still writes JSON to stdout. The
    // default runner throws on non-zero; recover the stdout from the error.
    const stdout = (ex as { stdout?: string | Buffer })?.stdout;
    if (stdout) {
      out = typeof stdout === "string" ? stdout : stdout.toString("utf8");
    } else {
      return { vulnerabilities: [], ran: false };
    }
  }
  return { vulnerabilities: parseNpmAudit(out), ran: true };
}
