// Deferral adapters (spec §1.2, §3; checklist 1.6).
//
// When the tool of record is present, shell out and parse its JSON into the
// neutral SecretFinding shape so downstream classification/severity/report
// treat external + in-house findings identically. This is the orchestration
// pattern's first concrete instance — the other concerns copy this contract.
//
// The runner is injectable (default = child_process) so deferral can be tested
// without the real binary on PATH.

import { execFileSync } from "node:child_process";
import type { SecretFinding } from "../detectors/secrets/scan-tree.js";
import { maskMatch } from "../detectors/secrets/scan-tree.js";
import type { ToolName } from "./tool-registry.js";
import type { Severity } from "../types.js";

/** Runs an external command and returns stdout, or throws on failure. */
export type CommandRunner = (cmd: string, args: string[], cwd: string) => string;

export const defaultCommandRunner: CommandRunner = (cmd, args, cwd) =>
  execFileSync(cmd, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120000,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  });

export interface DeferResult {
  tool: ToolName;
  findings: SecretFinding[];
}

// ─── gitleaks JSON adapter ───────────────────────────────────────────────
// gitleaks `detect --report-format json --report-path /dev/stdout` emits an
// array of findings: { RuleID, File, StartLine, StartColumn, Secret, Match, ... }.
interface GitleaksFinding {
  RuleID?: string;
  File?: string;
  StartLine?: number;
  StartColumn?: number;
  Secret?: string;
  Match?: string;
  Description?: string;
}

/** gitleaks rule-id → Vibe-Sec-native severity (high default; criticals named). */
function gitleaksSeverity(ruleId: string | undefined): Severity {
  const id = (ruleId ?? "").toLowerCase();
  if (
    id.includes("aws") ||
    id.includes("private-key") ||
    id.includes("stripe") && id.includes("live") ||
    id.includes("github-pat") ||
    id.includes("gcp")
  ) {
    return "critical";
  }
  return "high";
}

export function parseGitleaksJson(json: string): SecretFinding[] {
  let arr: GitleaksFinding[];
  try {
    const parsed = JSON.parse(json);
    arr = Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
  return arr.map((g) => {
    const raw = g.Secret ?? g.Match ?? "";
    return {
      pattern: g.RuleID ?? "gitleaks-rule",
      severity: gitleaksSeverity(g.RuleID),
      file: (g.File ?? "").replace(/\\/g, "/"),
      line: g.StartLine ?? 0,
      column: g.StartColumn ?? 0,
      match: raw ? maskMatch(raw) : "(masked)",
      preview: (g.Match ?? "").slice(0, 160),
      remediation: g.Description ?? "Rotate this secret and remove it from source.",
    };
  });
}

// ─── trufflehog JSONL adapter ────────────────────────────────────────────
// trufflehog filesystem --json emits one JSON object per line:
// { DetectorName, Raw, SourceMetadata: { Data: { Filesystem: { file, line } } }, Verified }
interface TrufflehogFinding {
  DetectorName?: string;
  Raw?: string;
  Verified?: boolean;
  SourceMetadata?: {
    Data?: { Filesystem?: { file?: string; line?: number } };
  };
}

export function parseTrufflehogJsonl(jsonl: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  for (const line of jsonl.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let obj: TrufflehogFinding;
    try {
      obj = JSON.parse(t) as TrufflehogFinding;
    } catch {
      continue;
    }
    const fsMeta = obj.SourceMetadata?.Data?.Filesystem;
    const raw = obj.Raw ?? "";
    out.push({
      pattern: obj.DetectorName ?? "trufflehog-detector",
      // A trufflehog-verified secret is a live credential → critical.
      severity: obj.Verified ? "critical" : "high",
      file: (fsMeta?.file ?? "").replace(/\\/g, "/"),
      line: fsMeta?.line ?? 0,
      column: 0,
      match: raw ? maskMatch(raw) : "(masked)",
      preview: "",
      remediation: obj.Verified
        ? "Verified live secret — rotate immediately, then remove from source."
        : "Rotate this secret and remove it from source.",
    });
  }
  return out;
}

/**
 * Defer secret detection to gitleaks. Shells out, parses JSON. On any failure
 * the caller should fall back to the in-house Layer A scan — this throws so the
 * caller's try/catch can make that decision.
 */
export function deferToGitleaks(
  projectRoot: string,
  runner: CommandRunner = defaultCommandRunner,
): DeferResult {
  // Report to stdout so we don't litter the tree; -v keeps it quiet on stderr.
  const out = runner(
    "gitleaks",
    ["detect", "--no-banner", "--report-format", "json", "--report-path", "-"],
    projectRoot,
  );
  return { tool: "gitleaks", findings: parseGitleaksJson(out) };
}

/** Defer secret detection to trufflehog (filesystem mode, JSON output). */
export function deferToTrufflehog(
  projectRoot: string,
  runner: CommandRunner = defaultCommandRunner,
): DeferResult {
  const out = runner("trufflehog", ["filesystem", projectRoot, "--json"], projectRoot);
  return { tool: "trufflehog", findings: parseTrufflehogJsonl(out) };
}

// ─── Semgrep CE adapter (Phase 3 — crypto-pii / auth-model / owasp-survey) ──
// `semgrep --json` (or scan --json) emits { results: [ { check_id, path,
// start: { line }, extra: { severity, message, metadata } }, … ] }. Semgrep
// severities are ERROR / WARNING / INFO — mapped to Vibe-Sec-native here. The
// neutral SemgrepFinding shape lets the structural detectors treat a deferred
// Semgrep result the same as their in-house finding before mapping to the schema.
export type SemgrepSeverityRaw = "ERROR" | "WARNING" | "INFO";

export interface SemgrepFinding {
  checkId: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  /** OWASP tag pulled from Semgrep rule metadata when present, else null. */
  owasp: string | null;
}

interface SemgrepRawResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    severity?: string;
    message?: string;
    metadata?: { owasp?: string | string[]; cwe?: string | string[] };
  };
}

function semgrepSeverity(raw: string | undefined): Severity {
  switch ((raw ?? "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    default:
      return "low";
  }
}

export function parseSemgrepJson(json: string): SemgrepFinding[] {
  let parsed: { results?: SemgrepRawResult[] };
  try {
    parsed = JSON.parse(json) as { results?: SemgrepRawResult[] };
  } catch {
    return [];
  }
  const results = Array.isArray(parsed.results) ? parsed.results : [];
  return results.map((r) => {
    const owaspMeta = r.extra?.metadata?.owasp;
    const owasp = Array.isArray(owaspMeta) ? (owaspMeta[0] ?? null) : (owaspMeta ?? null);
    return {
      checkId: r.check_id ?? "semgrep-rule",
      severity: semgrepSeverity(r.extra?.severity),
      file: (r.path ?? "").replace(/\\/g, "/"),
      line: r.start?.line ?? 0,
      message: r.extra?.message ?? "Semgrep finding.",
      owasp,
    };
  });
}

export interface SemgrepDeferResult {
  tool: ToolName;
  findings: SemgrepFinding[];
}

/**
 * Defer a structural concern to Semgrep CE, scoped to a config (e.g. the
 * "p/owasp-top-ten" or "p/secrets" registry pack, or a concern-specific rule
 * dir). Throws on failure so the caller can fall back to the in-house baseline.
 */
export function deferToSemgrep(
  projectRoot: string,
  config: string,
  runner: CommandRunner = defaultCommandRunner,
): SemgrepDeferResult {
  const out = runner(
    "semgrep",
    ["--config", config, "--json", "--quiet", "--no-git-ignore", projectRoot],
    projectRoot,
  );
  return { tool: "semgrep", findings: parseSemgrepJson(out) };
}

// ─── syft SBOM detection adapter (Phase 2.3, Decision 25) ────────────────
// v0.2 is SBOM detection-only — generation defers to v0.3. This adapter probes
// for an SBOM the project may already ship (CycloneDX / SPDX). Generation via
// `syft` is intentionally NOT invoked here; the supply-chain detector surfaces
// Syft as a Band-4 generation complement when no SBOM is present.
export const SBOM_FILENAMES: readonly string[] = [
  "bom.json",
  "sbom.json",
  "cyclonedx.json",
  "sbom.spdx.json",
  "sbom.cdx.json",
  ".sbom/bom.json",
];
