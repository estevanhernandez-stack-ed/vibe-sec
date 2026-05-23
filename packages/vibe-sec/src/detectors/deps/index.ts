// Dependency-CVE orchestrator (synthesis §3.1; checklist 2.2).
//
// Wires the pieces: classify app-vs-lib (drives --omit=dev), run OSV (defer to
// osv-scanner when present), run npm audit (the fix-availability confirmer),
// dedupe by id, and expose the lockfile-churn rollback rule for auto-applied
// fixes. EPSS/KEV hooks are present in the finding shape but unwired in v0.2
// (Decision 13).

import {
  scanOsv,
  type DepVulnerability,
} from "./osv-client.js";
import { runNpmAudit } from "./npm-audit.js";
import { mergeDepFindings, type MergedDepFinding } from "./dedupe.js";
import { classifyProject, type ProjectKind } from "./app-lib-classifier.js";
import type { ToolProbe } from "../../orchestration/tool-registry.js";
import type { CommandRunner } from "../../orchestration/defer.js";

export const LOCKFILE_CHURN_LIMIT = 50;

export interface DepScanOptions {
  probe?: ToolProbe;
  runner?: CommandRunner;
  /** Override the app/lib classification (default: auto-detect). */
  forceKind?: ProjectKind;
}

export interface DepScanResult {
  findings: MergedDepFinding[];
  projectKind: ProjectKind;
  omitDev: boolean;
  osvSource: "osv-scanner" | "osv.dev" | "none";
  npmAuditRan: boolean;
  /** EPSS/KEV hook: schema present, scoring unwired in v0.2 (Decision 13). */
  epssWired: false;
}

/**
 * Full dependency-CVE scan: OSV + npm audit, deduped, dev-filtered on apps.
 */
export function scanDependencies(
  projectRoot: string,
  opts: DepScanOptions = {},
): DepScanResult {
  const classification =
    opts.forceKind
      ? { kind: opts.forceKind, omitDev: opts.forceKind === "application", rationale: [] }
      : classifyProject(projectRoot);

  const osv = scanOsv(projectRoot, { probe: opts.probe, runner: opts.runner });
  const audit = runNpmAudit(projectRoot, {
    omitDev: classification.omitDev,
    runner: opts.runner,
  });

  const findings = mergeDepFindings(osv.vulnerabilities, audit.vulnerabilities);

  return {
    findings,
    projectKind: classification.kind,
    omitDev: classification.omitDev,
    osvSource: osv.source,
    npmAuditRan: audit.ran,
    epssWired: false,
  };
}

/**
 * Lockfile-churn safety check (Decision 20). An auto-applied SCA fix that
 * churns more than LOCKFILE_CHURN_LIMIT lines is too risky to land silently —
 * re-stage it for builder review instead. Returns true when the fix should be
 * downgraded from auto to stage.
 */
export function shouldRollbackChurn(diffLineCount: number): boolean {
  return diffLineCount > LOCKFILE_CHURN_LIMIT;
}

/**
 * Count changed lines in a unified diff (added + removed, excluding the @@/+++/---
 * headers). Used to apply the churn rule against an `npm audit fix` diff.
 */
export function countDiffLines(unifiedDiff: string): number {
  let count = 0;
  for (const line of unifiedDiff.split("\n")) {
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+") || line.startsWith("-")) count++;
  }
  return count;
}

export type { DepVulnerability, MergedDepFinding };
