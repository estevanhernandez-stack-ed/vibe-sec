// Git-history-scan cache state (spec §1.4, synthesis Decision 9).
//
// The first secret scan walks the FULL git history — 64% of 4-year-old leaked
// credentials are still valid, so "recent" is the wrong frame. That's slow, so
// we cache the last-scanned commit SHA in .vibe-sec/state/history-scan.json and
// scan only the new commits on subsequent runs (incremental).
//
// Pure I/O over a tiny JSON file. The detector (detectors/secrets/history-scan)
// owns the git interaction; this owns persistence.

import fs from "node:fs";
import path from "node:path";
import { projectStateDir } from "./paths.js";

/** The cached state of the last history scan. */
export interface HistoryScanCache {
  schema_version: 1;
  /** The commit SHA scanned up to (HEAD at last scan). Incremental boundary. */
  last_scanned_commit: string | null;
  /** ISO timestamp of the last scan. */
  scanned_at: string | null;
  /** True if the last run was a full-history scan (vs incremental). */
  full_scan_done: boolean;
}

export function historyScanCachePath(projectRoot: string, app?: string): string {
  return path.join(projectStateDir(projectRoot, app), "history-scan.json");
}

const EMPTY_CACHE: HistoryScanCache = {
  schema_version: 1,
  last_scanned_commit: null,
  scanned_at: null,
  full_scan_done: false,
};

/** Read the cache, or an empty default when absent/corrupt. Never throws. */
export function readHistoryScanCache(projectRoot: string, app?: string): HistoryScanCache {
  const file = historyScanCachePath(projectRoot, app);
  if (!fs.existsSync(file)) return { ...EMPTY_CACHE };
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<HistoryScanCache>;
    return {
      schema_version: 1,
      last_scanned_commit: parsed.last_scanned_commit ?? null,
      scanned_at: parsed.scanned_at ?? null,
      full_scan_done: parsed.full_scan_done ?? false,
    };
  } catch {
    return { ...EMPTY_CACHE };
  }
}

/** Write the cache atomically (mkdir -p the state dir as needed). */
export function writeHistoryScanCache(
  projectRoot: string,
  cache: HistoryScanCache,
  app?: string,
): void {
  const file = historyScanCachePath(projectRoot, app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(cache, null, 2), "utf8");
}

/**
 * Decide scan mode from cache: a never-scanned repo (or one that never finished
 * a full scan) gets a full walk; otherwise incremental from last_scanned_commit.
 */
export function decideScanMode(cache: HistoryScanCache): {
  mode: "full" | "incremental";
  since: string | null;
} {
  if (!cache.full_scan_done || !cache.last_scanned_commit) {
    return { mode: "full", since: null };
  }
  return { mode: "incremental", since: cache.last_scanned_commit };
}
