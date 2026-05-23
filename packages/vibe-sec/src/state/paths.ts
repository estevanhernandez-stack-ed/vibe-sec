// Data-directory resolution (spec §1.4 — locked data dirs).
// win32 + posix safe via node:path + node:os. No path is hardcoded with a
// separator; everything routes through path.join / path.resolve.

import os from "node:os";
import path from "node:path";

/**
 * Global data dir: ~/.claude/plugins/data/vibe-sec/
 * Holds profile.json, sessions/<date>.jsonl, friction.jsonl, wins.jsonl.
 */
export function globalDataDir(homeDir: string = os.homedir()): string {
  return path.join(homeDir, ".claude", "plugins", "data", "vibe-sec");
}

/**
 * Per-project state dir: <project>/.vibe-sec/state/
 * Holds findings.jsonl, audit.json, history-scan.json, osv-cache.json.
 *
 * Monorepo (Conflict 9 = C): when `app` is supplied, scope to
 * <project>/.vibe-sec/apps/<app>/state/.
 */
export function projectStateDir(projectRoot: string, app?: string): string {
  const base = path.join(path.resolve(projectRoot), ".vibe-sec");
  if (app) {
    return path.join(base, "apps", app, "state");
  }
  return path.join(base, "state");
}

/** Per-project pending fixes dir: <project>/.vibe-sec/pending/fixes/ */
export function pendingFixesDir(projectRoot: string, app?: string): string {
  const base = path.join(path.resolve(projectRoot), ".vibe-sec");
  if (app) {
    return path.join(base, "apps", app, "pending", "fixes");
  }
  return path.join(base, "pending", "fixes");
}

/** Per-project docs dir: <project>/docs/vibe-sec/ */
export function projectDocsDir(projectRoot: string): string {
  return path.join(path.resolve(projectRoot), "docs", "vibe-sec");
}

/**
 * SECURITY.md path: <project>/docs/SECURITY.md — the GitHub-recognized location
 * for a security policy (builder-facing, not under the vibe-sec subdir).
 */
export function securityMdPath(projectRoot: string): string {
  return path.join(path.resolve(projectRoot), "docs", "SECURITY.md");
}

/** findings.jsonl path. */
export function findingsPath(projectRoot: string, app?: string): string {
  return path.join(projectStateDir(projectRoot, app), "findings.jsonl");
}

/** audit.json path. */
export function auditStatePath(projectRoot: string, app?: string): string {
  return path.join(projectStateDir(projectRoot, app), "audit.json");
}

/** threat-model.json sidecar path (Threat-Dragon-compatible). */
export function threatModelStatePath(projectRoot: string, app?: string): string {
  return path.join(projectStateDir(projectRoot, app), "threat-model.json");
}

/** Vibe Test handshake file path: <project>/.vibe-test/state/covered-surfaces.json */
export function vibeTestCoveredSurfacesPath(projectRoot: string): string {
  return path.join(
    path.resolve(projectRoot),
    ".vibe-test",
    "state",
    "covered-surfaces.json",
  );
}
