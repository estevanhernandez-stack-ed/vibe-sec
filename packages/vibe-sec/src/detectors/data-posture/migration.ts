// Migration-discipline lint (GAP-09; concern #12).
//
// Statically inspect how the app evolves persisted data shapes. Two questions:
//   1. Is there schema versioning at all? A schemaless store (the Firestore
//      class) with no version field is unrecoverable under drift — you cannot
//      tell which shape a document is.
//   2. When migration machinery exists, how complete is it? The signals:
//        - do writes stamp a version?
//        - is there a backfill / completion path (something that can walk
//          old-shape documents independent of reads), or only lazy-on-read?
//        - is an in-flight migration gated (dual-read / feature-flag)?
//
// Real shapes this lint is calibrated against (2026-06-09 ground truth):
//   - Celestia3 PersistenceService.getHistory(): inline lazy migration in the
//     read path, no version field, no completion path → the lazy-only class.
//   - Project-626Labs-1 migrationService.ts: a dedicated migration module
//     (migrateUserData walks everything) → completion path present.
//
// Conservative by design: these are ADVISORY findings with file:line evidence,
// not accusations. False positives on a signature concern class burn trust
// (the auth-model 0.5.1 lesson). When in doubt, report a site, not a finding.

import fs from "node:fs";
import path from "node:path";
import { walkSource, lineOf } from "../source-walk.js";
import { inDotDir } from "./dot-dir.js";

export type MigrationSiteKind =
  | "migration-module" // a file/dir NAMED migrat* — invocable independent of reads
  | "migration-reference" // migrat* in source content (symbol, comment, log)
  | "lazy-read-path" // migration logic co-located with the read path
  | "schema-version-field" // schemaVersion / schema_version / dataVersion / "_v"
  | "version-checked-read" // a comparison against a version field
  | "write-stamps-version" // a write call whose payload carries a version field
  | "backfill-symbol" // backfill* / migrate* function symbol
  | "gating-flag"; // dual-read / feature-flag migration gate

export interface MigrationSite {
  kind: MigrationSiteKind;
  file: string;
  line: number;
  detail: string;
}

export interface MigrationScanResult {
  /** Any migration machinery at all (module, reference, backfill symbol). */
  machineryPresent: boolean;
  /** Any schema-version field anywhere (models, types, payloads). */
  schemaVersioningPresent: boolean;
  /** A write call stamps a version field into its payload. */
  writeStampsVersion: boolean;
  /** A path that can walk old-shape documents independent of reads. */
  completionPathPresent: boolean;
  /** Migration logic living inside a read path (the lazy shape). */
  lazyReadPathPresent: boolean;
  /** Dual-read / feature-flag gating around an in-flight migration. */
  gatingPresent: boolean;
  sites: MigrationSite[];
}

const MIGRATE_NAME_RE = /migrat/i;

// Word-ish migration mention in content (identifier, comment, or log string).
const MIGRATE_CONTENT_RE = /[A-Za-z_$]*migrat[A-Za-z0-9_$]*/i;

// Version fields. `_v` only as a quoted/declared property key — a bare `_v`
// identifier is too common to trust.
const VERSION_FIELD_RE =
  /\b(?:schemaVersion|schema_version|dataVersion|data_version|SCHEMA_VERSION|DATA_VERSION)\b|["']_v["']\s*:/;

// A comparison against a version field — the version-checked-read shape.
const VERSION_CHECK_RE =
  /\b(?:schemaVersion|schema_version|dataVersion|data_version)\b\s*(?:[<>]=?|[!=]==?)|(?:[<>]=?|[!=]==?)\s*\b(?:schemaVersion|schema_version|dataVersion|data_version)\b/;

// Write-call heads whose argument span we inspect for a version stamp.
const WRITE_CALL_RE =
  /\b(?:addDoc|setDoc|updateDoc)\s*\(|\.\s*(?:set|add|update|save|create|insert|insertOne|insertMany|updateOne|updateMany|upsert)\s*\(/g;

// A completion-path symbol: defined OR invoked. backfill* always counts;
// migrate* counts when it names a scope (All/User/Data/Project/Collection/
// Batch/Documents) — a bare `migrate(` is too generic.
const BACKFILL_SYMBOL_RE =
  /\b(backfill[A-Za-z0-9_]*|migrate(?:All|User|Data|Project|Collection|Batch|Document)[A-Za-z0-9_]*|runMigrations?)\s*\(/g;

// Read-path heads — getDocs/find*/query co-located with migration logic.
const READ_PATH_RE =
  /\bgetDocs?\s*\(|\bfindMany\s*\(|\bfindFirst\s*\(|\bfindUnique\s*\(|\bfindAll\s*\(|\bquery\s*\(/;

// Dual-read / feature-flag gating around a migration.
const GATING_RE =
  /\b(?:dualRead|dual_read|useNewSchema|use_new_schema|migrationFlag|migration_flag|migrationEnabled|migration_enabled|MIGRATION_ENABLED|ENABLE_MIGRATION)\b/;

// Well-known migration directories (SQL files there aren't in SOURCE_EXT, so
// the dir itself is the signal). Batch by construction → completion path.
const MIGRATION_DIRS = [
  "migrations",
  "supabase/migrations",
  "prisma/migrations",
  "drizzle/migrations",
  "db/migrations",
];

const MAX_REFERENCES_PER_FILE = 3;

function dirExists(projectRoot: string, relPath: string): boolean {
  try {
    return fs.statSync(path.join(projectRoot, relPath)).isDirectory();
  } catch {
    return false;
  }
}

/** Bracket-matched argument span of a call, bounded — same trick as tenant-isolation. */
function callArgSpan(text: string, openParenIdx: number): string {
  let depth = 0;
  let i = openParenIdx;
  for (; i < text.length && i < openParenIdx + 600; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) break;
    }
  }
  return text.slice(openParenIdx, i + 1);
}

/** Per-file scanner — returns every migration-relevant site in one file. */
export function scanMigrationFile(text: string, relPath: string): MigrationSite[] {
  // Dot directories are duplicate checkouts / tooling state, never the shipped
  // data layer (the .worktrees triple-count on Project-626Labs-1).
  if (inDotDir(relPath)) return [];
  const sites: MigrationSite[] = [];
  const isMigrationNamed = MIGRATE_NAME_RE.test(relPath);

  if (isMigrationNamed) {
    sites.push({
      kind: "migration-module",
      file: relPath,
      line: 1,
      detail: `dedicated migration module: ${relPath} (invocable independent of reads)`,
    });
  }

  // Version fields + version-checked reads.
  const vf = VERSION_FIELD_RE.exec(text);
  if (vf) {
    sites.push({
      kind: "schema-version-field",
      file: relPath,
      line: lineOf(text, vf.index),
      detail: `schema-version field "${vf[0].trim()}" at ${relPath}:${lineOf(text, vf.index)}`,
    });
  }
  const vc = VERSION_CHECK_RE.exec(text);
  if (vc) {
    sites.push({
      kind: "version-checked-read",
      file: relPath,
      line: lineOf(text, vc.index),
      detail: `version-checked read ("${vc[0].trim()}") at ${relPath}:${lineOf(text, vc.index)}`,
    });
  }

  // Writes that stamp a version into their payload.
  WRITE_CALL_RE.lastIndex = 0;
  for (const m of text.matchAll(WRITE_CALL_RE)) {
    const openParen = (m.index ?? 0) + m[0].length - 1;
    if (VERSION_FIELD_RE.test(callArgSpan(text, openParen))) {
      sites.push({
        kind: "write-stamps-version",
        file: relPath,
        line: lineOf(text, m.index ?? 0),
        detail: `write stamps a schema version at ${relPath}:${lineOf(text, m.index ?? 0)}`,
      });
      break; // one per file is enough evidence
    }
  }

  // Backfill / scoped-migrate symbols (definition or call site).
  BACKFILL_SYMBOL_RE.lastIndex = 0;
  const seenSymbols = new Set<string>();
  for (const m of text.matchAll(BACKFILL_SYMBOL_RE)) {
    const symbol = m[1] ?? "";
    if (seenSymbols.has(symbol)) continue;
    seenSymbols.add(symbol);
    sites.push({
      kind: "backfill-symbol",
      file: relPath,
      line: lineOf(text, m.index ?? 0),
      detail: `completion-path symbol ${symbol}() at ${relPath}:${lineOf(text, m.index ?? 0)}`,
    });
  }

  // Gating flags.
  const g = GATING_RE.exec(text);
  if (g) {
    sites.push({
      kind: "gating-flag",
      file: relPath,
      line: lineOf(text, g.index),
      detail: `migration gating flag "${g[0]}" at ${relPath}:${lineOf(text, g.index)}`,
    });
  }

  // Migration references in content (non-migration-named files only — a
  // migration module mentioning "migrate" is not news). Capped per file.
  if (!isMigrationNamed) {
    let count = 0;
    const re = new RegExp(MIGRATE_CONTENT_RE.source, "gi");
    const hasReadPath = READ_PATH_RE.test(text);
    let lazyMarked = false;
    for (const m of text.matchAll(re)) {
      if (count >= MAX_REFERENCES_PER_FILE) break;
      count++;
      const line = lineOf(text, m.index ?? 0);
      if (hasReadPath && !lazyMarked) {
        lazyMarked = true;
        sites.push({
          kind: "lazy-read-path",
          file: relPath,
          line,
          detail: `migration logic co-located with the read path (lazy-migration shape) at ${relPath}:${line} ("${m[0]}")`,
        });
      } else {
        sites.push({
          kind: "migration-reference",
          file: relPath,
          line,
          detail: `migration reference "${m[0]}" at ${relPath}:${line}`,
        });
      }
    }
  }

  return sites;
}

/**
 * Scan the project's migration discipline. Walks source once, then folds the
 * sites into the boolean verdict the policy layer consumes.
 */
export function scanMigrationDiscipline(projectRoot: string): MigrationScanResult {
  const sites = walkSource<MigrationSite>(projectRoot, [scanMigrationFile]);

  // Well-known migration directories count as completion paths by construction.
  for (const dir of MIGRATION_DIRS) {
    if (dirExists(projectRoot, dir)) {
      sites.push({
        kind: "migration-module",
        file: dir,
        line: 1,
        detail: `migration directory: ${dir}/ (batch migrations by construction)`,
      });
    }
  }

  const has = (kind: MigrationSiteKind) => sites.some((s) => s.kind === kind);

  const completionPathPresent = has("migration-module") || has("backfill-symbol");
  const machineryPresent =
    completionPathPresent || has("migration-reference") || has("lazy-read-path");

  return {
    machineryPresent,
    schemaVersioningPresent: has("schema-version-field") || has("version-checked-read"),
    writeStampsVersion: has("write-stamps-version"),
    completionPathPresent,
    lazyReadPathPresent: has("lazy-read-path"),
    gatingPresent: has("gating-flag"),
    sites,
  };
}
