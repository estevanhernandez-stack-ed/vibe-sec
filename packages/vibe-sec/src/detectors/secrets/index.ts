// Secret-detection orchestrator (spec §1.2 decision tree; checklist 1.6).
//
// The first concrete instance of the orchestration pattern:
//   1. detect tool of record (gitleaks → trufflehog) via the which-probe
//   2. if present → defer (shell-out + JSON-parse), credit the tool
//   3. if absent OR the deferral fails → run the in-house Layer A scan
// Findings come back in the neutral SecretFinding shape regardless of source,
// so classification/severity/report treat them identically.

import { scanTree, type ScanResult, type SecretFinding } from "./scan-tree.js";
import {
  detectToolOfRecord,
  SECRET_TOOL_CANDIDATES,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";
import {
  deferToGitleaks,
  deferToTrufflehog,
  type CommandRunner,
  defaultCommandRunner,
} from "../../orchestration/defer.js";
import type { ToolOfRecord } from "../../types.js";

export interface SecretScanOptions {
  /** Injectable which-probe (default shells out). */
  probe?: ToolProbe;
  /** Injectable external-command runner (default shells out). */
  runner?: CommandRunner;
}

export interface SecretScanResult extends ScanResult {
  /** Which detector produced these findings — for findings.jsonl + crediting. */
  toolOfRecord: ToolOfRecord;
  /** True when an external tool was used (vs in-house fallback). */
  deferred: boolean;
}

/**
 * Run secret detection over a working tree, deferring to the tool of record
 * when present and falling back to in-house Layer A when absent or on failure.
 */
export function scanSecrets(
  projectRoot: string,
  opts: SecretScanOptions = {},
): SecretScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const runner = opts.runner ?? defaultCommandRunner;

  const tool = detectToolOfRecord(SECRET_TOOL_CANDIDATES, probe);

  if (tool?.present) {
    try {
      const result =
        tool.name === "gitleaks"
          ? deferToGitleaks(projectRoot, runner)
          : deferToTrufflehog(projectRoot, runner);
      return {
        findings: result.findings,
        // External tools report file count differently; -1 signals "n/a".
        filesScanned: -1,
        toolOfRecord: tool.name as ToolOfRecord,
        deferred: true,
      };
    } catch {
      // Deferral failed (tool errored / unparseable). Fall through to in-house.
    }
  }

  const inhouse = scanTree(projectRoot);
  return {
    findings: inhouse.findings,
    filesScanned: inhouse.filesScanned,
    toolOfRecord: "in-house",
    deferred: false,
  };
}

export type { SecretFinding };
export { scanTree };
