// Fix suppression — per-project, prompt-for-global after 5 repetitions (spec §8.3).
//
// A builder who suppresses the same finding class 5 times across projects is
// telling us it's noise for their workflow — at the 5th, prompt once to promote
// it to a global suppression (matching Vibe Test's threshold). Until then,
// suppression is per-project: stored alongside the project's state, scoped to a
// finding_type (+ optional file), so it doesn't leak across repos.
//
// This module is the bookkeeping: record a suppression, count repetitions, and
// answer "should we offer global?" The actual prompt is the SKILL's job.

import fs from "node:fs";
import path from "node:path";
import { projectStateDir } from "../state/paths.js";

/** Repetition count at which we offer to promote a suppression to global. */
export const GLOBAL_PROMPT_THRESHOLD = 5;

export interface SuppressionRecord {
  finding_type: string;
  /** Optional file scope — null means suppress the type project-wide. */
  file: string | null;
  reason: string;
  suppressed_at: string;
}

interface SuppressionStore {
  schema_version: 1;
  records: SuppressionRecord[];
  /** Per-finding_type cross-project repetition counts (global tally). */
  globalRepetitions: Record<string, number>;
}

function suppressionStorePath(projectRoot: string, app?: string): string {
  return path.join(projectStateDir(projectRoot, app), "suppressions.json");
}

function emptyStore(): SuppressionStore {
  return { schema_version: 1, records: [], globalRepetitions: {} };
}

function readStore(projectRoot: string, app?: string): SuppressionStore {
  const file = suppressionStorePath(projectRoot, app);
  if (!fs.existsSync(file)) return emptyStore();
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<SuppressionStore>;
    return {
      schema_version: 1,
      records: parsed.records ?? [],
      globalRepetitions: parsed.globalRepetitions ?? {},
    };
  } catch {
    return emptyStore();
  }
}

function writeStore(projectRoot: string, store: SuppressionStore, app?: string): void {
  const file = suppressionStorePath(projectRoot, app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(store, null, 2) + "\n", "utf8");
}

export interface SuppressResult {
  /** The repetition count for this finding_type across all suppress calls. */
  repetitions: number;
  /** True when this suppression crossed the global-prompt threshold. */
  offerGlobal: boolean;
}

/**
 * Record a per-project suppression. Returns the running cross-project repetition
 * count for the finding_type and whether we should now offer a global suppression.
 * The 5th repetition (and only the 5th) returns offerGlobal=true so the SKILL
 * prompts once, not on every subsequent suppression.
 */
export function recordSuppression(
  projectRoot: string,
  entry: { finding_type: string; file?: string | null; reason: string },
  app?: string,
): SuppressResult {
  const store = readStore(projectRoot, app);
  store.records.push({
    finding_type: entry.finding_type,
    file: entry.file ?? null,
    reason: entry.reason,
    suppressed_at: new Date().toISOString(),
  });
  const prev = store.globalRepetitions[entry.finding_type] ?? 0;
  const repetitions = prev + 1;
  store.globalRepetitions[entry.finding_type] = repetitions;
  writeStore(projectRoot, store, app);

  return {
    repetitions,
    offerGlobal: repetitions === GLOBAL_PROMPT_THRESHOLD,
  };
}

/** True iff a finding_type (optionally file-scoped) is currently suppressed. */
export function isSuppressed(
  projectRoot: string,
  finding_type: string,
  file: string | null = null,
  app?: string,
): boolean {
  const store = readStore(projectRoot, app);
  return store.records.some(
    (r) => r.finding_type === finding_type && (r.file === null || r.file === file),
  );
}

/** All active suppression records for a project (for posture / audit display). */
export function listSuppressions(projectRoot: string, app?: string): SuppressionRecord[] {
  return readStore(projectRoot, app).records;
}
