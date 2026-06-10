// Persistence detection — the data-posture applicability gate (GAP-09; concern #12).
//
// The concern only exists when the app actually persists user data. A static
// scanner that scolds a stateless marketing site about backups is noise, and
// noise on an advisory concern burns trust (the auth-model 0.5.1 lesson). So
// applicability is detected first, and a no-persistence verdict reports
// NOT-APPLICABLE — out of the score denominator entirely, never a hollow pass.
//
// Detection mirrors license/distribution-model.ts: package.json dependency
// signals + file-structure hints, returned with the signals that fired. One
// deliberate disambiguation: a bare `firebase` / `firebase-admin` dependency is
// NOT persistence by itself (the SDK also serves auth-only and hosting-only
// apps). It confirms only when corroborated by firestore.rules /
// firestore.indexes.json or an actual firestore import in source.

import fs from "node:fs";
import path from "node:path";
import { walkSource, lineOf } from "../source-walk.js";
import { inDotDir } from "./dot-dir.js";

export type PersistenceKind =
  | "firestore"
  | "supabase"
  | "prisma"
  | "drizzle"
  | "sql"
  | "mongo"
  | "sqlite";

export interface PersistenceDetectionResult {
  /** True when the app persists data — the concern's applicability gate. */
  persists: boolean;
  /** Which data layers were detected (deduped). */
  kinds: PersistenceKind[];
  /** Human-readable signals that fired, distribution-model style. */
  signals: string[];
}

interface PkgJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function readPkg(projectRoot: string): PkgJson {
  try {
    return JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
  } catch {
    return {};
  }
}

function exists(projectRoot: string, rel: string): boolean {
  try {
    fs.accessSync(path.join(projectRoot, rel));
    return true;
  } catch {
    return false;
  }
}

function matchDeps(pkg: PkgJson, re: RegExp): string[] {
  const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  return Object.keys(all).filter((d) => re.test(d));
}

// Unambiguous persistence dependencies — the package IS a data-layer client.
const DEP_KINDS: { re: RegExp; kind: PersistenceKind }[] = [
  { re: /^@google-cloud\/firestore$|^@firebase\/firestore$/, kind: "firestore" },
  { re: /^@firebase\/data-connect$|^@dataconnect\//, kind: "sql" },
  { re: /^@supabase\/supabase-js$|^@supabase\/postgrest-js$/, kind: "supabase" },
  { re: /^@prisma\/client$|^prisma$/, kind: "prisma" },
  { re: /^drizzle-orm$|^drizzle-kit$/, kind: "drizzle" },
  {
    re: /^pg$|^postgres$|^mysql2?$|^mariadb$|^@neondatabase\/serverless$|^@planetscale\/database$|^typeorm$|^sequelize$|^knex$/,
    kind: "sql",
  },
  { re: /^mongodb$|^mongoose$/, kind: "mongo" },
  {
    re: /^better-sqlite3$|^sqlite3$|^sql\.js$|^@libsql\/client$|^expo-sqlite$/,
    kind: "sqlite",
  },
];

// The ambiguous pair: firebase SDKs that may be auth/hosting-only.
const FIREBASE_DEP_RE = /^firebase$|^firebase-admin$/;

// File-structure hints — each is persistence evidence on its own.
const FILE_KINDS: { rel: string; kind: PersistenceKind; label: string }[] = [
  { rel: "firestore.rules", kind: "firestore", label: "firestore.rules" },
  { rel: "firestore.indexes.json", kind: "firestore", label: "firestore.indexes.json" },
  { rel: "prisma/schema.prisma", kind: "prisma", label: "prisma/schema.prisma" },
  { rel: "drizzle.config.ts", kind: "drizzle", label: "drizzle.config.ts" },
  { rel: "drizzle.config.js", kind: "drizzle", label: "drizzle.config.js" },
  { rel: "supabase/migrations", kind: "supabase", label: "supabase/migrations/" },
  { rel: "dataconnect", kind: "sql", label: "dataconnect/ (Firebase Data Connect)" },
];

// Source-level firestore confirmation for the ambiguous firebase dep.
const FIRESTORE_SOURCE_RE =
  /from\s+["'](?:firebase\/firestore|@google-cloud\/firestore|firebase-admin\/firestore)["']|\bgetFirestore\s*\(|require\(\s*["']firebase\/firestore["']\s*\)/;

/** First firestore usage site in source, or null. Used to confirm a bare firebase dep. */
function findFirestoreSourceSignal(
  projectRoot: string,
): { file: string; line: number } | null {
  const hits = walkSource<{ file: string; line: number }>(projectRoot, [
    (text, rel) => {
      if (inDotDir(rel)) return []; // duplicate checkouts / tooling state
      const m = FIRESTORE_SOURCE_RE.exec(text);
      return m ? [{ file: rel, line: lineOf(text, m.index) }] : [];
    },
  ]);
  return hits[0] ?? null;
}

/**
 * Detect whether (and how) the app persists data. Pure file-system reads, no
 * network. Multi-root repos run this once per detected root, same as the other
 * manifest-rooted detectors.
 */
export function detectPersistence(projectRoot: string): PersistenceDetectionResult {
  const pkg = readPkg(projectRoot);
  const kinds = new Set<PersistenceKind>();
  const signals: string[] = [];

  for (const { re, kind } of DEP_KINDS) {
    for (const dep of matchDeps(pkg, re)) {
      kinds.add(kind);
      signals.push(`dependency: ${dep}`);
    }
  }

  for (const { rel, kind, label } of FILE_KINDS) {
    if (exists(projectRoot, rel)) {
      kinds.add(kind);
      signals.push(`file: ${label}`);
    }
  }

  // The firebase disambiguation: the bare SDK needs corroboration before it
  // counts as persistence (auth-only / hosting-only apps carry it too).
  const firebaseDeps = matchDeps(pkg, FIREBASE_DEP_RE);
  if (firebaseDeps.length > 0 && !kinds.has("firestore")) {
    const sourceHit = findFirestoreSourceSignal(projectRoot);
    if (sourceHit) {
      kinds.add("firestore");
      signals.push(
        `dependency: ${firebaseDeps.join(", ")} + firestore usage in source (${sourceHit.file}:${sourceHit.line})`,
      );
    } else {
      signals.push(
        `dependency: ${firebaseDeps.join(", ")} present but no firestore.rules / firestore source usage — treated as auth/hosting-only, not persistence`,
      );
    }
  } else if (firebaseDeps.length > 0) {
    // firestore already confirmed by rules/indexes — credit the SDK too.
    for (const dep of firebaseDeps) signals.push(`dependency: ${dep}`);
  }

  return {
    persists: kinds.size > 0,
    kinds: [...kinds],
    signals,
  };
}
