// Backup-posture check (GAP-09; concern #12).
//
// For apps with persistence at Public-facing tier and above: is there ANY
// discoverable backup/export path? A static scanner can detect the ABSENCE of
// backup config with confidence; it can NEVER verify a restore works — that
// runtime leg belongs to vibe-ops, and the finding copy says so explicitly.
//
// Five discoverable surfaces:
//   1. package.json scripts — a script NAMED backup, or whose body runs
//      `gcloud firestore export` / `pg_dump` / `mongodump` / `mysqldump`.
//      A bare "export" script name deliberately does NOT count: `next export`
//      is a static-site export, not a data backup (real-estate trap).
//   2. CI workflows — the same dump/export commands in .github/workflows/, or
//      a workflow file named backup.
//   3. Script files — scripts/ tools/ bin/ entries named backup/dump, or whose
//      contents run the dump/export commands.
//   4. Backup-named scheduled functions — onSchedule( / pubsub.schedule( with
//      backup/export/dump in the surrounding window.
//   5. A restore runbook — markdown named backup / disaster-recovery /
//      restore-runbook(-plan/-drill/-procedure). A file named *_RESTORED.md
//      (past tense, "features restored") deliberately does NOT match.

import fs from "node:fs";
import path from "node:path";
import { walkSource, lineOf } from "../source-walk.js";
import { inDotDir } from "./dot-dir.js";

export type BackupSignalKind =
  | "package-script"
  | "ci-workflow"
  | "backup-script-file"
  | "scheduled-function"
  | "restore-runbook";

export interface BackupSignal {
  kind: BackupSignalKind;
  /** Repo-relative path (forward slashes). */
  file: string;
  line: number | null;
  detail: string;
}

export interface BackupPostureResult {
  signals: BackupSignal[];
  /** The surfaces the check actually looked at — feeds the honesty copy. */
  locationsChecked: string[];
}

// The specific data-dump commands. Generic "export" is NOT here on purpose.
const DUMP_COMMAND_RE =
  /\bgcloud\s+firestore\s+export\b|\bfirestore:export\b|\bpg_dump(?:all)?\b|\bmongodump\b|\bmysqldump\b/i;

const SCHEDULED_FN_RE = /\bonSchedule\s*\(|\.pubsub\s*\.\s*schedule\s*\(/g;
// Context that marks a scheduled function as backup-shaped. Deliberately NOT a
// bare /export/: every ES module has `export const` next to onSchedule(, so
// the bare word would flag every scheduled function in the codebase. Only
// data-export shapes count (exportDocuments is the Firestore managed-export API).
const SCHEDULE_CONTEXT_RE =
  /backup|dump|exportDocuments|export(?:Collections?|Data|Database|Db|Firestore)/i;
const SCHEDULE_WINDOW = 240;

// Runbook filenames. Tight on purpose: "restore" alone matches past-tense
// status docs (FEATURES_RESTORED.md), so it needs a runbook-ish companion word.
const RUNBOOK_NAME_RE =
  /backup|disaster[-_.]?recovery|restore[-_.]?(?:runbook|plan|drill|procedure|guide)/i;

const SKIP_DIR_RE =
  /(?:^|\/)(?:node_modules|\.git|dist|build|out|coverage|\.next|\.turbo|\.vercel|\.cache|vendor)(?:\/|$)/;

const SCRIPT_DIRS = ["scripts", "tools", "bin"];
const SCRIPT_EXT_RE = /\.(?:sh|ps1|psm1|bat|cmd|py|[mc]?[jt]s)$/i;
const MAX_RUNBOOK_WALK_DEPTH = 4;

function rel(projectRoot: string, full: string): string {
  return path.relative(projectRoot, full).replace(/\\/g, "/");
}

// ─── 1. package.json scripts ─────────────────────────────────────────────────

function checkPackageScripts(projectRoot: string): BackupSignal[] {
  let scripts: Record<string, string>;
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"),
    ) as { scripts?: Record<string, string> };
    scripts = pkg.scripts ?? {};
  } catch {
    return [];
  }
  const out: BackupSignal[] = [];
  for (const [name, body] of Object.entries(scripts)) {
    if (typeof body !== "string") continue;
    if (/backup/i.test(name)) {
      out.push({
        kind: "package-script",
        file: "package.json",
        line: null,
        detail: `npm script "${name}" is backup-named: ${body}`,
      });
    } else if (DUMP_COMMAND_RE.test(body)) {
      out.push({
        kind: "package-script",
        file: "package.json",
        line: null,
        detail: `npm script "${name}" runs a data-dump command: ${body}`,
      });
    }
  }
  return out;
}

// ─── 2. CI workflows ─────────────────────────────────────────────────────────

function checkWorkflows(projectRoot: string): BackupSignal[] {
  const wfDir = path.join(projectRoot, ".github", "workflows");
  let entries: string[];
  try {
    entries = fs.readdirSync(wfDir);
  } catch {
    return [];
  }
  const out: BackupSignal[] = [];
  for (const name of entries) {
    if (!/\.ya?ml$/i.test(name)) continue;
    const relPath = `.github/workflows/${name}`;
    if (/backup/i.test(name)) {
      out.push({
        kind: "ci-workflow",
        file: relPath,
        line: null,
        detail: `workflow ${name} is backup-named`,
      });
      continue;
    }
    let text: string;
    try {
      text = fs.readFileSync(path.join(wfDir, name), "utf8");
    } catch {
      continue;
    }
    const m = DUMP_COMMAND_RE.exec(text);
    if (m) {
      out.push({
        kind: "ci-workflow",
        file: relPath,
        line: lineOf(text, m.index),
        detail: `workflow ${name} runs a data-dump command (${m[0]})`,
      });
    }
  }
  return out;
}

// ─── 3. script files ─────────────────────────────────────────────────────────

function checkScriptFiles(projectRoot: string): BackupSignal[] {
  const out: BackupSignal[] = [];
  for (const dir of SCRIPT_DIRS) {
    const full = path.join(projectRoot, dir);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(full, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isFile() || !SCRIPT_EXT_RE.test(entry.name)) continue;
      const relPath = `${dir}/${entry.name}`;
      if (/backup|\bdump\b|[-_.]dump/i.test(entry.name)) {
        out.push({
          kind: "backup-script-file",
          file: relPath,
          line: null,
          detail: `script ${relPath} is backup/dump-named`,
        });
        continue;
      }
      let text: string;
      try {
        text = fs.readFileSync(path.join(full, entry.name), "utf8");
      } catch {
        continue;
      }
      const m = DUMP_COMMAND_RE.exec(text);
      if (m) {
        out.push({
          kind: "backup-script-file",
          file: relPath,
          line: lineOf(text, m.index),
          detail: `script ${relPath} runs a data-dump command (${m[0]})`,
        });
      }
    }
  }
  return out;
}

// ─── 4. backup-named scheduled functions ─────────────────────────────────────

function checkScheduledFunctions(projectRoot: string): BackupSignal[] {
  return walkSource<BackupSignal>(projectRoot, [
    (text, relPath) => {
      if (inDotDir(relPath)) return []; // duplicate checkouts / tooling state
      const out: BackupSignal[] = [];
      SCHEDULED_FN_RE.lastIndex = 0;
      for (const m of text.matchAll(SCHEDULED_FN_RE)) {
        const at = m.index ?? 0;
        const window = text.slice(
          Math.max(0, at - SCHEDULE_WINDOW),
          at + SCHEDULE_WINDOW,
        );
        if (SCHEDULE_CONTEXT_RE.test(window)) {
          out.push({
            kind: "scheduled-function",
            file: relPath,
            line: lineOf(text, at),
            detail: `scheduled function with backup/export context at ${relPath}:${lineOf(text, at)}`,
          });
        }
      }
      return out;
    },
  ]);
}

// ─── 5. restore runbook ──────────────────────────────────────────────────────

function checkRunbooks(projectRoot: string): BackupSignal[] {
  const out: BackupSignal[] = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_RUNBOOK_WALK_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const relPath = rel(projectRoot, full);
      if (SKIP_DIR_RE.test(relPath)) continue;
      if (entry.isDirectory() && entry.name.startsWith(".")) continue; // dup checkouts
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (/\.md$/i.test(entry.name) && RUNBOOK_NAME_RE.test(entry.name)) {
        out.push({
          kind: "restore-runbook",
          file: relPath,
          line: null,
          detail: `documented backup/restore runbook: ${relPath}`,
        });
      }
    }
  };
  walk(projectRoot, 0);
  return out;
}

/**
 * Sweep the five discoverable backup surfaces. Pure file-system reads; no
 * network, no cloud-project introspection (a configured GCP-side backup
 * schedule with zero repo footprint is invisible here — the honesty copy
 * downstream accounts for that).
 */
export function detectBackupPosture(projectRoot: string): BackupPostureResult {
  return {
    signals: [
      ...checkPackageScripts(projectRoot),
      ...checkWorkflows(projectRoot),
      ...checkScriptFiles(projectRoot),
      ...checkScheduledFunctions(projectRoot),
      ...checkRunbooks(projectRoot),
    ],
    locationsChecked: [
      "package.json scripts",
      ".github/workflows/",
      "scripts/ tools/ bin/",
      "scheduled functions in source",
      "backup/restore runbooks (*.md)",
    ],
  };
}
