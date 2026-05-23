// Shared source-tree walker for the structural detectors (Phase 3).
//
// crypto-pii, auth-model, owasp-survey, and rate-limiting all need to walk a
// project's JS/TS source and run per-file scanners. The secret detector has its
// own scan-tree (it scans every text file, including config + env); the
// structural detectors only care about source code, so this is a lighter walker
// scoped to parseable extensions with the same node_modules/dist skip discipline.
//
// A per-file scanner is `(text, relPath) => T[]`; walkSource fans it across the
// tree and flattens. Read failures + oversized files are skipped, never thrown —
// one bad file should not blind a detector.

import fs from "node:fs";
import path from "node:path";

const MAX_FILE_BYTES = 1024 * 1024;

// Source extensions the structural detectors analyze.
const SOURCE_EXT = /\.(?:[mc]?[jt]sx?)$/i;

// Directories never worth walking for source analysis.
const SKIP_DIR_RE =
  /(?:^|\/)(?:node_modules|\.git|dist|build|out|coverage|\.next|\.turbo|\.vercel|\.cache|vendor)(?:\/|$)/;

export function isSourceFile(rel: string): boolean {
  return SOURCE_EXT.test(rel);
}

function* walk(dir: string, root: string): Generator<{ full: string; rel: string }> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full).replace(/\\/g, "/");
    if (SKIP_DIR_RE.test(rel)) continue;
    if (entry.isDirectory()) {
      yield* walk(full, root);
    } else if (entry.isFile() && SOURCE_EXT.test(entry.name)) {
      yield { full, rel };
    }
  }
}

/** A scanner that turns one file's text + relative path into zero or more findings. */
export type FileScanner<T> = (text: string, relPath: string) => T[];

/**
 * Walk a project's source files, run one or more scanners per file, and return
 * the flattened findings. The relative path uses forward slashes on every OS.
 */
export function walkSource<T>(
  root: string,
  scanners: readonly FileScanner<T>[],
): T[] {
  const out: T[] = [];
  const resolved = path.resolve(root);
  for (const { full, rel } of walk(resolved, resolved)) {
    let text: string;
    try {
      const stat = fs.statSync(full);
      if (stat.size > MAX_FILE_BYTES) continue;
      text = fs.readFileSync(full, "utf8");
    } catch {
      continue;
    }
    for (const scanner of scanners) {
      for (const f of scanner(text, rel)) out.push(f);
    }
  }
  return out;
}

/** Collect the relative paths of every source file (no content scan). */
export function listSourceFiles(root: string): string[] {
  const out: string[] = [];
  const resolved = path.resolve(root);
  for (const { rel } of walk(resolved, resolved)) out.push(rel);
  return out;
}

/** 1-based line number of a character index within text. */
export function lineOf(text: string, index: number): number {
  if (index <= 0) return 1;
  return text.slice(0, index).split("\n").length;
}
