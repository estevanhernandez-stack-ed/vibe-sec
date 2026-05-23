// Git-history secret scan (spec §4.2, synthesis Decision 9).
//
// The working tree is only the present. A secret committed three years ago and
// later deleted is still in the history — and 64% of old leaked credentials are
// still live. So the first scan walks the full history; later scans go
// incremental from the last cached commit.
//
// Mechanics: enumerate the commits in range, for each commit list the blobs
// touched, read each blob's content, run Layer A regex over it, and tag the
// finding with the commit SHA + date. The git interaction is behind an
// injectable runner so tests exercise the logic against a fixture repo without
// mocking the binary, and unit tests can feed canned git output.

import { execFileSync } from "node:child_process";
import { scanText } from "./scan-tree.js";
import type { SecretFinding } from "./scan-tree.js";
import {
  readHistoryScanCache,
  writeHistoryScanCache,
  decideScanMode,
} from "../../state/history-scan.js";

/** A finding located in history carries the commit it was introduced in. */
export interface HistorySecretFinding extends SecretFinding {
  commit: string;
  commit_date: string;
  /** The blob path at that commit. */
  historical_path: string;
}

/** Runs a git command in the repo and returns stdout. Injectable for tests. */
export type GitRunner = (args: string[], cwd: string) => string;

export const defaultGitRunner: GitRunner = (args, cwd) =>
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 120000,
    windowsHide: true,
    maxBuffer: 256 * 1024 * 1024,
  });

export interface HistoryScanResult {
  findings: HistorySecretFinding[];
  mode: "full" | "incremental";
  commitsScanned: number;
  /** True when the repo looks like a shallow clone — history may be truncated. */
  shallow: boolean;
  /** HEAD SHA after the scan (the new incremental boundary). */
  head: string | null;
}

export interface HistoryScanOptions {
  git?: GitRunner;
  app?: string;
  /** Cap on commits walked per run (defense against pathological histories). */
  maxCommits?: number;
}

function safeGit(git: GitRunner, args: string[], cwd: string): string {
  try {
    return git(args, cwd);
  } catch {
    return "";
  }
}

function isGitRepo(git: GitRunner, cwd: string): boolean {
  return safeGit(git, ["rev-parse", "--is-inside-work-tree"], cwd).trim() === "true";
}

function isShallow(git: GitRunner, cwd: string): boolean {
  return safeGit(git, ["rev-parse", "--is-shallow-repository"], cwd).trim() === "true";
}

function headSha(git: GitRunner, cwd: string): string | null {
  const out = safeGit(git, ["rev-parse", "HEAD"], cwd).trim();
  return out || null;
}

/** List commit SHAs (newest first) in the given range. */
function listCommits(
  git: GitRunner,
  cwd: string,
  since: string | null,
  max: number,
): { sha: string; date: string }[] {
  const range = since ? `${since}..HEAD` : "HEAD";
  const out = safeGit(
    git,
    ["log", range, `--max-count=${max}`, "--format=%H%x09%cI"],
    cwd,
  );
  const commits: { sha: string; date: string }[] = [];
  for (const line of out.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const [sha, date] = t.split("\t");
    if (sha) commits.push({ sha, date: date ?? "" });
  }
  return commits;
}

/** Files changed in a commit (added/modified), excluding deletes. */
function filesInCommit(git: GitRunner, cwd: string, sha: string): string[] {
  const out = safeGit(
    git,
    ["show", "--no-color", "--diff-filter=AM", "--name-only", "--format=", sha],
    cwd,
  );
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Read a blob's content at a commit. Empty string on any failure. */
function blobAt(git: GitRunner, cwd: string, sha: string, file: string): string {
  return safeGit(git, ["show", `${sha}:${file}`], cwd);
}

const BINARY_HINT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|woff2?|ttf|so|dll|bin)$/i;

/**
 * Scan git history for secrets. Full on first run (or when no full scan has
 * completed), incremental afterward. Updates the cache so the next run only
 * walks new commits. Never throws on a non-git directory — returns empty.
 */
export function scanHistory(
  projectRoot: string,
  opts: HistoryScanOptions = {},
): HistoryScanResult {
  const git = opts.git ?? defaultGitRunner;
  const maxCommits = opts.maxCommits ?? 5000;

  const empty: HistoryScanResult = {
    findings: [],
    mode: "full",
    commitsScanned: 0,
    shallow: false,
    head: null,
  };

  if (!isGitRepo(git, projectRoot)) return empty;

  const cache = readHistoryScanCache(projectRoot, opts.app);
  const { mode, since } = decideScanMode(cache);
  const shallow = isShallow(git, projectRoot);
  const commits = listCommits(git, projectRoot, since, maxCommits);

  const findings: HistorySecretFinding[] = [];
  const seen = new Set<string>();

  for (const { sha, date } of commits) {
    for (const file of filesInCommit(git, projectRoot, sha)) {
      if (BINARY_HINT.test(file)) continue;
      const content = blobAt(git, projectRoot, sha, file);
      if (!content) continue;
      for (const f of scanText(content, file)) {
        // Dedup by commit+file+line+pattern so re-touched files don't repeat.
        const key = `${sha}:${file}:${f.line}:${f.pattern}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          ...f,
          commit: sha,
          commit_date: date,
          historical_path: file,
        });
      }
    }
  }

  const head = headSha(git, projectRoot);
  // Persist the new boundary. A full scan that completed marks full_scan_done so
  // subsequent runs go incremental; an incremental run just advances the SHA.
  writeHistoryScanCache(
    projectRoot,
    {
      schema_version: 1,
      last_scanned_commit: head,
      scanned_at: new Date().toISOString(),
      full_scan_done: cache.full_scan_done || mode === "full",
    },
    opts.app,
  );

  return { findings, mode, commitsScanned: commits.length, shallow, head };
}
