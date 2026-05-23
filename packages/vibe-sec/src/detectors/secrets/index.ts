// Secret-detection orchestrator (spec §1.2 decision tree; checklist 1.6 + 2.1).
//
// The first concrete instance of the orchestration pattern:
//   1. detect tool of record (gitleaks → trufflehog) via the which-probe
//   2. if present → defer (shell-out + JSON-parse), credit the tool
//   3. if absent OR the deferral fails → run the in-house full stack:
//      Layer A (regex) + Layer B (entropy) + Layer C (AST), deduped
// Findings come back in the neutral SecretFinding shape regardless of source.
//
// Phase 2.1 adds: the full three-layer in-house stack, optional git-history
// scan (full first run, incremental after), and the --verify opt-in that defers
// to trufflehog's verifier.

import {
  scanTree,
  scanTreeWith,
  scanText,
  type ScanResult,
  type SecretFinding,
} from "./scan-tree.js";
import { scanEntropy } from "./entropy.js";
import { scanAst } from "./ast-walk.js";
import { scanHistory, type HistorySecretFinding } from "./history-scan.js";
import { verifySecrets } from "./verify.js";
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
  /** Run the full in-house stack (A+B+C) even when an external tool defers. */
  forceInhouse?: boolean;
  /** Scan git history too (Phase 2.1). Off by default for the fast :scan path. */
  history?: boolean;
  /** Confirm live secrets via trufflehog (--verify, Conflict 5 = A). */
  verify?: boolean;
}

export interface SecretScanResult extends ScanResult {
  /** Which detector produced these findings — for findings.jsonl + crediting. */
  toolOfRecord: ToolOfRecord;
  /** True when an external tool was used (vs in-house fallback). */
  deferred: boolean;
  /** Git-history findings, when history scanning was requested. */
  historyFindings?: HistorySecretFinding[];
  /** True when the repo looked shallow (history may be truncated). */
  shallow?: boolean;
  /** Verified-live findings, when --verify ran. */
  verifiedFindings?: SecretFinding[];
  /** Why verification was skipped, when it was. */
  verifySkippedReason?: string | null;
}

/** The in-house full stack: Layer A regex, Layer B entropy, Layer C AST. */
export function scanInhouseFull(projectRoot: string): ScanResult {
  return scanTreeWith(projectRoot, [scanText, scanEntropy, scanAst]);
}

/**
 * Run secret detection over a working tree, deferring to the tool of record
 * when present and falling back to the in-house full stack when absent/failed.
 * Optionally scans git history and verifies live secrets.
 */
export function scanSecrets(
  projectRoot: string,
  opts: SecretScanOptions = {},
): SecretScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const runner = opts.runner ?? defaultCommandRunner;

  let base: SecretScanResult;

  const tool = opts.forceInhouse
    ? null
    : detectToolOfRecord(SECRET_TOOL_CANDIDATES, probe);

  if (tool?.present) {
    try {
      const result =
        tool.name === "gitleaks"
          ? deferToGitleaks(projectRoot, runner)
          : deferToTrufflehog(projectRoot, runner);
      base = {
        findings: result.findings,
        filesScanned: -1, // external tools report file count differently
        toolOfRecord: tool.name as ToolOfRecord,
        deferred: true,
      };
    } catch {
      base = inhouseResult(projectRoot);
    }
  } else {
    base = inhouseResult(projectRoot);
  }

  // Git-history scan (Phase 2.1). Independent of the working-tree tool choice —
  // even when gitleaks handled the working tree, history is its own pass here
  // when explicitly requested via the in-house substrate.
  if (opts.history) {
    const hist = scanHistory(projectRoot);
    base.historyFindings = hist.findings;
    base.shallow = hist.shallow;
  }

  // Verification opt-in.
  if (opts.verify) {
    const v = verifySecrets(projectRoot, { probe, runner });
    base.verifiedFindings = v.findings;
    base.verifySkippedReason = v.skippedReason;
  }

  return base;
}

function inhouseResult(projectRoot: string): SecretScanResult {
  const inhouse = scanInhouseFull(projectRoot);
  return {
    findings: inhouse.findings,
    filesScanned: inhouse.filesScanned,
    toolOfRecord: "in-house",
    deferred: false,
  };
}

export type { SecretFinding };
export { scanTree };
