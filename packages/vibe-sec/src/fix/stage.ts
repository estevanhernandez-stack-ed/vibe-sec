// Fix staging — write staged fixes to .vibe-sec/pending/fixes/*.diff (spec §8.1).
//
// The Stage route (0.70-0.89 confidence, plus stage-floor destructive kinds like
// auth-middleware adds + RLS migrations) writes a unified-diff file the builder
// reviews and applies by hand. We never apply staged fixes — staging IS the
// safety. One file per finding, named by finding id so re-runs overwrite the
// same staged diff instead of piling up.

import fs from "node:fs";
import path from "node:path";
import type { Finding } from "../state/findings.js";
import { pendingFixesDir } from "../state/paths.js";

export interface StagedFix {
  /** The finding this diff remediates. */
  findingId: string;
  /** The path the .diff was written to. */
  filePath: string;
  /** The relative fix_ref to record back on the finding. */
  fixRef: string;
}

/** Build the on-disk filename for a finding's staged diff. */
export function stagedFixFilename(finding: Finding): string {
  const slug = finding.finding_type.replace(/[^a-z0-9-]+/gi, "-").toLowerCase();
  return `${finding.id}-${slug}.diff`;
}

/** The relative fix_ref recorded on a finding (matches the schema example). */
export function stagedFixRef(finding: Finding, app?: string): string {
  const sub = app ? `apps/${app}/pending/fixes` : "pending/fixes";
  return `.vibe-sec/${sub}/${stagedFixFilename(finding)}`;
}

/**
 * Write a staged fix diff for a finding. The diff content is produced by the
 * caller (the SKILL synthesizes the actual patch); this owns the path + write.
 * Creates the pending/fixes dir as needed. Idempotent per finding id.
 */
export function stageFix(
  projectRoot: string,
  finding: Finding,
  diff: string,
  app?: string,
): StagedFix {
  const dir = pendingFixesDir(projectRoot, app);
  fs.mkdirSync(dir, { recursive: true });
  const filename = stagedFixFilename(finding);
  const filePath = path.join(dir, filename);

  // Header comment so a reviewer opening the diff cold has the context.
  const header = [
    `# Staged by vibe-sec — review before applying.`,
    `# finding: ${finding.id} (${finding.finding_type})`,
    `# severity: ${finding.severity_tier_adjusted} · confidence: ${finding.confidence.toFixed(2)}`,
    `# ${finding.title}`,
    `#`,
    `# This fix was NOT auto-applied. Read it, then apply with: git apply <this file>`,
    "",
  ].join("\n");

  fs.writeFileSync(filePath, header + diff + (diff.endsWith("\n") ? "" : "\n"), "utf8");

  return {
    findingId: finding.id,
    filePath,
    fixRef: stagedFixRef(finding, app),
  };
}

/** List the staged fixes currently pending review for a project. */
export function listStagedFixes(projectRoot: string, app?: string): string[] {
  const dir = pendingFixesDir(projectRoot, app);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".diff"))
    .map((f) => path.join(dir, f));
}

/** Remove a staged fix once the builder has applied it (clean-up helper). */
export function clearStagedFix(projectRoot: string, finding: Finding, app?: string): boolean {
  const filePath = path.join(pendingFixesDir(projectRoot, app), stagedFixFilename(finding));
  if (fs.existsSync(filePath)) {
    fs.rmSync(filePath);
    return true;
  }
  return false;
}
