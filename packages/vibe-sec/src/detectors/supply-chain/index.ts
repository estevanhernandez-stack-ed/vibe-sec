// Supply-chain hardening orchestrator (synthesis §3.6; checklist 2.3).
//
// Bundles the supply-chain detectors over the shared lockfile parser:
//   - lockfile integrity + pinning classification (floating `latest`/`*` flagged)
//   - GitHub Actions ref-style + permissions parse
//   - typosquat (Levenshtein ≤2 vs popular) + dependency-confusion
//   - postinstall-script inspection
//   - SBOM detection-only (Syft generation defers to v0.3)
// Socket.dev / OpenSSF Scorecard are surfaced in Band 4 by the report layer
// (Decision 14) — not shelled out here.

import {
  readLockfile,
  readDeclaredDeps,
  classifyPin,
  type LockfileInfo,
  type PinStyle,
} from "./lockfile.js";
import { parseWorkflows, findActionsIssues, type ActionsFinding } from "./actions-parse.js";
import {
  findTyposquats,
  findDepConfusion,
  type TyposquatFinding,
  type DepConfusionFinding,
} from "./typosquat.js";
import { scanPostinstall, type PostinstallScanResult } from "./postinstall.js";
import { detectSbom, type SbomDetectResult } from "./sbom-detect.js";
import fs from "node:fs";
import path from "node:path";

export interface PinningFinding {
  package: string;
  range: string;
  pinStyle: PinStyle;
  dev: boolean;
}

export interface LockfileIntegrityResult {
  /** Lockfile present at all? Absence is itself a finding at Internal+. */
  present: boolean;
  manager: string;
  /** True when the lockfile carries integrity hashes (or is bun-binary). */
  hasIntegrity: boolean;
  /** Floating pins (`latest`/`*`/`x`) from the manifest — flagged at Internal+. */
  floatingPins: PinningFinding[];
}

/**
 * Lockfile integrity + pinning classification. A floating pin (`latest`, `*`)
 * means the resolved version drifts between installs — flagged at Internal+.
 */
export function checkLockfileIntegrity(projectRoot: string, lock?: LockfileInfo): LockfileIntegrityResult {
  const info = lock ?? readLockfile(projectRoot);
  const declared = readDeclaredDeps(projectRoot);
  const floatingPins: PinningFinding[] = [];
  for (const dep of declared) {
    const style = classifyPin(dep.range);
    if (style === "floating") {
      floatingPins.push({ package: dep.name, range: dep.range, pinStyle: style, dev: dep.dev });
    }
  }
  return {
    present: info.present,
    manager: info.manager,
    hasIntegrity: info.hasIntegrity,
    floatingPins,
  };
}

function hasPrivateRegistry(projectRoot: string): boolean {
  try {
    const npmrc = fs.readFileSync(path.join(projectRoot, ".npmrc"), "utf8");
    return /registry\s*=/.test(npmrc) || /:registry\s*=/.test(npmrc);
  } catch {
    return false;
  }
}

export interface SupplyChainScanResult {
  integrity: LockfileIntegrityResult;
  actions: ActionsFinding[];
  typosquats: TyposquatFinding[];
  depConfusion: DepConfusionFinding[];
  postinstall: PostinstallScanResult;
  sbom: SbomDetectResult;
}

export interface SupplyChainScanOptions {
  /** Skip the heavier passes for the fast :deps path (typosquat round-trips). */
  fast?: boolean;
  /** Postinstall inspection depth (Regulated goes full). */
  postinstallDepth?: number;
}

/** Run the full supply-chain hardening pass. */
export function scanSupplyChain(
  projectRoot: string,
  opts: SupplyChainScanOptions = {},
): SupplyChainScanResult {
  const integrity = checkLockfileIntegrity(projectRoot);
  const actions = findActionsIssues(parseWorkflows(projectRoot));
  const sbom = detectSbom(projectRoot);

  // The fast (:deps) subset skips typosquat round-trips + SBOM-depth postinstall.
  const typosquats = opts.fast ? [] : findTyposquats(projectRoot);
  const depConfusion = opts.fast ? [] : findDepConfusion(projectRoot, hasPrivateRegistry(projectRoot));
  const postinstall = opts.fast
    ? { findings: [], ignoreScriptsEnabled: false }
    : scanPostinstall(projectRoot, { depth: opts.postinstallDepth });

  return { integrity, actions, typosquats, depConfusion, postinstall, sbom };
}

export {
  parseWorkflows,
  findActionsIssues,
  findTyposquats,
  findDepConfusion,
  scanPostinstall,
  detectSbom,
};
export type {
  ActionsFinding,
  TyposquatFinding,
  DepConfusionFinding,
  PostinstallScanResult,
  SbomDetectResult,
};
