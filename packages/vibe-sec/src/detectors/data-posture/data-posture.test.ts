import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectPersistence } from "./persistence.js";
import { detectBackupPosture } from "./backup.js";
import { scanMigrationDiscipline } from "./migration.js";
import {
  scanDataPosture,
  dataPostureNotApplicableNote,
  type DataPostureFinding,
} from "./index.js";
import { dataPostureToFinding, resetFindingIds } from "../to-findings.js";
import { validateFinding, appendFindings, makeFinding } from "../../state/findings.js";
import { writeAuditState, type AuditState } from "../../state/audit-state.js";
import {
  isInScope,
  mandatoryConcerns,
} from "../../scoring/weighted-score.js";
import { foldConcernResults, runGate } from "../../gate/run-gate.js";
import { ALL_CONCERNS, ALL_TIERS } from "../../types.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-dataposture-"));
  resetFindingIds();
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

function writeRootPkg(pkg: object): void {
  write("package.json", JSON.stringify(pkg));
}

// The Celestia3 shape distilled: lazy migration inline in the read path, no
// version field, no completion path (PersistenceService.getHistory, 2026-06-09).
const LAZY_READ_PATH_SOURCE = `
import { collection, addDoc, query, getDocs } from "firebase/firestore";
import { db } from "./firebase";
export class PersistenceService {
  static async getHistory(userId: string) {
    let snap = await getDocs(query(collection(db, "v3_users", userId, "memories")));
    // Lazy Migration Check
    if (snap.empty) {
      const old = await getDocs(query(collection(db, "v3_memories")));
      for (const d of old.docs) {
        await addDoc(collection(db, "v3_users", userId, "memories"), d.data());
      }
    }
    return snap;
  }
}
`;

// ─── persistence detection (the applicability gate) ──────────────────────────

describe("detectPersistence", () => {
  it("empty repo → no persistence", () => {
    writeRootPkg({ name: "app" });
    const r = detectPersistence(tmp);
    expect(r.persists).toBe(false);
    expect(r.kinds).toEqual([]);
  });

  it("prisma client dependency → persists (prisma)", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    const r = detectPersistence(tmp);
    expect(r.persists).toBe(true);
    expect(r.kinds).toContain("prisma");
    expect(r.signals.some((s) => s.includes("@prisma/client"))).toBe(true);
  });

  it("firestore.rules file alone → persists (firestore)", () => {
    writeRootPkg({ name: "app" });
    write("firestore.rules", "service cloud.firestore {}");
    const r = detectPersistence(tmp);
    expect(r.persists).toBe(true);
    expect(r.kinds).toContain("firestore");
  });

  it("bare firebase dep with NO corroboration → NOT persistence (auth/hosting-only)", () => {
    writeRootPkg({ name: "app", dependencies: { firebase: "10.0.0" } });
    const r = detectPersistence(tmp);
    expect(r.persists).toBe(false);
    expect(r.signals.some((s) => /auth\/hosting-only/.test(s))).toBe(true);
  });

  it("firebase dep + firestore import in source → persists, signal cites file:line", () => {
    writeRootPkg({ name: "app", dependencies: { firebase: "10.0.0" } });
    write("src/lib/store.ts", 'import { getFirestore } from "firebase/firestore";\n');
    const r = detectPersistence(tmp);
    expect(r.persists).toBe(true);
    expect(r.kinds).toContain("firestore");
    expect(r.signals.some((s) => s.includes("src/lib/store.ts:1"))).toBe(true);
  });

  it("drizzle config file → persists (drizzle)", () => {
    writeRootPkg({ name: "app" });
    write("drizzle.config.ts", "export default {};");
    expect(detectPersistence(tmp).kinds).toContain("drizzle");
  });

  it("mongoose → mongo; @neondatabase/serverless → sql; better-sqlite3 → sqlite", () => {
    writeRootPkg({
      name: "app",
      dependencies: {
        mongoose: "8.0.0",
        "@neondatabase/serverless": "0.9.0",
        "better-sqlite3": "11.0.0",
      },
    });
    const r = detectPersistence(tmp);
    expect(r.kinds).toEqual(expect.arrayContaining(["mongo", "sql", "sqlite"]));
  });
});

// ─── backup-posture sweep ─────────────────────────────────────────────────────

describe("detectBackupPosture", () => {
  it("backup-named npm script → package-script signal", () => {
    writeRootPkg({ name: "app", scripts: { "backup:db": "node tools/x.js" } });
    const r = detectBackupPosture(tmp);
    expect(r.signals).toHaveLength(1);
    expect(r.signals[0]!.kind).toBe("package-script");
  });

  it("npm script running gcloud firestore export → package-script signal", () => {
    writeRootPkg({
      name: "app",
      scripts: { "db:snapshot": "gcloud firestore export gs://bucket/exports" },
    });
    expect(detectBackupPosture(tmp).signals[0]!.kind).toBe("package-script");
  });

  it("a `next export` script does NOT count (static-site export, not a data backup)", () => {
    writeRootPkg({ name: "app", scripts: { export: "next export" } });
    expect(detectBackupPosture(tmp).signals).toHaveLength(0);
  });

  it("CI workflow running pg_dump → ci-workflow signal with a line", () => {
    write(
      ".github/workflows/nightly.yml",
      "on: schedule\njobs:\n  dump:\n    steps:\n      - run: pg_dump $DATABASE_URL > out.sql\n",
    );
    const r = detectBackupPosture(tmp);
    expect(r.signals).toHaveLength(1);
    expect(r.signals[0]!.kind).toBe("ci-workflow");
    expect(r.signals[0]!.line).toBe(5);
  });

  it("backup-named workflow file counts by name alone", () => {
    write(".github/workflows/backup.yml", "on: schedule\n");
    expect(detectBackupPosture(tmp).signals[0]!.kind).toBe("ci-workflow");
  });

  it("scripts/backup-db.sh → backup-script-file (by name)", () => {
    write("scripts/backup-db.sh", "#!/bin/sh\necho hi\n");
    expect(detectBackupPosture(tmp).signals[0]!.kind).toBe("backup-script-file");
  });

  it("script file whose content runs mongodump → backup-script-file (by content)", () => {
    write("scripts/snapshot.sh", "#!/bin/sh\nmongodump --uri $MONGO_URI\n");
    const r = detectBackupPosture(tmp);
    expect(r.signals[0]!.kind).toBe("backup-script-file");
    expect(r.signals[0]!.line).toBe(2);
  });

  it("onSchedule function with backup context → scheduled-function signal", () => {
    write(
      "functions/src/backupJob.ts",
      'export const nightlyBackup = onSchedule("every 24 hours", async () => {\n  await exportCollections();\n});\n',
    );
    const r = detectBackupPosture(tmp);
    expect(r.signals.some((s) => s.kind === "scheduled-function")).toBe(true);
  });

  it("onSchedule with NO backup context does not count", () => {
    write(
      "functions/src/digest.ts",
      'export const digest = onSchedule("every 24 hours", async () => {\n  await sendWeeklyDigest();\n});\n',
    );
    expect(
      detectBackupPosture(tmp).signals.filter((s) => s.kind === "scheduled-function"),
    ).toHaveLength(0);
  });

  it("docs/BACKUP.md and RESTORE_RUNBOOK.md count as restore-runbook", () => {
    write("docs/BACKUP.md", "# Backup\n");
    write("docs/RESTORE_RUNBOOK.md", "# Restore\n");
    const kinds = detectBackupPosture(tmp).signals.map((s) => s.kind);
    expect(kinds.filter((k) => k === "restore-runbook")).toHaveLength(2);
  });

  it("THE real-estate trap: FEATURES_RESTORED.md (past tense) does NOT count", () => {
    write("docs/ARCHITECT_FEATURES_RESTORED.md", "# Features restored\n");
    expect(detectBackupPosture(tmp).signals).toHaveLength(0);
  });

  it("empty repo → zero signals, locationsChecked names the surfaces", () => {
    writeRootPkg({ name: "app" });
    const r = detectBackupPosture(tmp);
    expect(r.signals).toHaveLength(0);
    expect(r.locationsChecked.length).toBeGreaterThanOrEqual(5);
  });
});

// ─── migration-discipline lint ────────────────────────────────────────────────

describe("scanMigrationDiscipline", () => {
  it("clean repo → no machinery, no versioning", () => {
    write("src/app.ts", "export const x = 1;\n");
    const r = scanMigrationDiscipline(tmp);
    expect(r.machineryPresent).toBe(false);
    expect(r.schemaVersioningPresent).toBe(false);
    expect(r.lazyReadPathPresent).toBe(false);
  });

  it("schemaVersion field in a model → schemaVersioningPresent", () => {
    write("src/types.ts", "export interface Doc { schemaVersion: number; }\n");
    const r = scanMigrationDiscipline(tmp);
    expect(r.schemaVersioningPresent).toBe(true);
    expect(r.sites.some((s) => s.kind === "schema-version-field")).toBe(true);
  });

  it('quoted "_v" property counts; a bare _v identifier does NOT', () => {
    write("src/a.ts", 'const doc = { "_v": 2, name: "x" };\n');
    expect(scanMigrationDiscipline(tmp).schemaVersioningPresent).toBe(true);
    fs.rmSync(path.join(tmp, "src", "a.ts"));
    write("src/b.ts", "const _v = 1;\nexport default _v;\n");
    expect(scanMigrationDiscipline(tmp).schemaVersioningPresent).toBe(false);
  });

  it("version-checked read (doc.schemaVersion < 2) → version-checked-read site", () => {
    write("src/read.ts", "if (doc.schemaVersion < CURRENT) { upgrade(doc); }\n");
    const r = scanMigrationDiscipline(tmp);
    expect(r.sites.some((s) => s.kind === "version-checked-read")).toBe(true);
    expect(r.schemaVersioningPresent).toBe(true);
  });

  it("write call stamping a version → writeStampsVersion", () => {
    write(
      "src/save.ts",
      'await setDoc(ref, { ...data, schemaVersion: 3, updatedAt: now() });\n',
    );
    expect(scanMigrationDiscipline(tmp).writeStampsVersion).toBe(true);
  });

  it("THE Celestia3 shape: lazy migration in the read path, no completion path", () => {
    write("src/lib/PersistenceService.ts", LAZY_READ_PATH_SOURCE);
    const r = scanMigrationDiscipline(tmp);
    expect(r.machineryPresent).toBe(true);
    expect(r.lazyReadPathPresent).toBe(true);
    expect(r.completionPathPresent).toBe(false);
    const lazy = r.sites.find((s) => s.kind === "lazy-read-path");
    expect(lazy!.file).toBe("src/lib/PersistenceService.ts");
    expect(lazy!.line).toBeGreaterThan(1);
  });

  it("THE 626Labs shape: a migration-named module is a completion path", () => {
    write(
      "services/business/migrationService.ts",
      "export async function migrateUserData(uid: string) { /* walks everything */ }\n",
    );
    const r = scanMigrationDiscipline(tmp);
    expect(r.machineryPresent).toBe(true);
    expect(r.completionPathPresent).toBe(true);
    expect(r.sites.some((s) => s.kind === "migration-module")).toBe(true);
  });

  it("a scoped migrate symbol (migrateAllUsers) in a non-migration file → backfill-symbol", () => {
    write(
      "src/admin.ts",
      "async function migrateAllUsers() { for (const u of users) await fix(u); }\n",
    );
    const r = scanMigrationDiscipline(tmp);
    expect(r.completionPathPresent).toBe(true);
    expect(r.sites.some((s) => s.kind === "backfill-symbol")).toBe(true);
  });

  it("a migrations/ directory counts as a completion path by construction", () => {
    fs.mkdirSync(path.join(tmp, "migrations"), { recursive: true });
    write("migrations/001_init.sql", "create table users (id int);");
    const r = scanMigrationDiscipline(tmp);
    expect(r.completionPathPresent).toBe(true);
  });

  it("gating flags (MIGRATION_ENABLED / dualRead) → gatingPresent", () => {
    write("src/flags.ts", "if (process.env.MIGRATION_ENABLED === 'true') { dualRead(); }\n");
    expect(scanMigrationDiscipline(tmp).gatingPresent).toBe(true);
  });

  it("dot directories are excluded — a .worktrees checkout never counts (626Labs triple-count)", () => {
    write(
      ".worktrees/branch-x/services/migrationService.ts",
      "export async function migrateUserData(uid: string) {}\n",
    );
    write(".worktrees/branch-x/src/lazy.ts", LAZY_READ_PATH_SOURCE);
    const r = scanMigrationDiscipline(tmp);
    expect(r.machineryPresent).toBe(false);
    expect(r.sites).toHaveLength(0);
  });
});

// ─── scanDataPosture — the policy map ────────────────────────────────────────

describe("scanDataPosture — applicability gate", () => {
  it("no persistence → NOT APPLICABLE: zero findings, denominator note", () => {
    writeRootPkg({ name: "app", dependencies: { react: "18.0.0" } });
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    expect(r.applicable).toBe(false);
    expect(r.findings).toHaveLength(0);
    expect(r.checksRun).toEqual([]);
    expect(r.notes[0]).toMatch(/NOT APPLICABLE/);
    expect(r.notes[0]).toMatch(/denominator/);
    expect(r.notes[0]).toMatch(/not the same as a pass/);
  });

  it("the not-applicable note is exported standalone for report reuse", () => {
    const note = dataPostureNotApplicableNote({ persists: false, kinds: [], signals: [] });
    expect(note).toMatch(/NOT APPLICABLE/);
  });

  it("prototype and internal tiers run no checks even with persistence", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    for (const tier of ["prototype", "internal"] as const) {
      const r = scanDataPosture(tmp, { tier });
      expect(r.applicable).toBe(true);
      expect(r.checksRun).toEqual([]);
      expect(r.findings).toHaveLength(0);
    }
  });

  it("public-facing is lightweight: backup check only, no migration lint", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    const r = scanDataPosture(tmp, { tier: "public-facing" });
    expect(r.checksRun).toEqual(["backup"]);
    expect(r.migration).toBeNull();
    // backup absence still fires at public-facing
    expect(r.findings.some((f) => f.finding_type === "no-discoverable-backup-path")).toBe(true);
    // but no migration findings, even though there's no schema versioning
    expect(r.findings.some((f) => f.finding_type === "no-schema-versioning")).toBe(false);
  });
});

describe("scanDataPosture — backup policy", () => {
  it("persistence + zero backup signals → MEDIUM no-discoverable-backup-path", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    const f = r.findings.find((x) => x.finding_type === "no-discoverable-backup-path");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("medium");
    expect(f!.fixClass).toBe("advisory");
    expect(f!.detail).toMatch(/untested by definition/);
    expect(f!.remediation).toMatch(/restore drill/);
  });

  it("backup present → no finding, honesty-cap note names vibe-ops", () => {
    writeRootPkg({
      name: "app",
      dependencies: { "@prisma/client": "5.0.0" },
      scripts: { backup: "pg_dump $DATABASE_URL > backup.sql" },
    });
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    expect(r.findings.some((f) => f.finding_type === "no-discoverable-backup-path")).toBe(false);
    const note = r.notes.find((n) => /backup path discovered/.test(n));
    expect(note).toBeDefined();
    expect(note).toMatch(/NOT a verified restore/);
    expect(note).toMatch(/vibe-ops/);
  });
});

describe("scanDataPosture — migration policy (full tiers)", () => {
  it("persistence + no schema versioning anywhere → LOW no-schema-versioning", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    const f = r.findings.find((x) => x.finding_type === "no-schema-versioning");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("low");
    expect(f!.detail).toMatch(/can't tell which shape a document is/);
  });

  it("schemaVersion field present → no no-schema-versioning finding", () => {
    writeRootPkg({ name: "app", dependencies: { "@prisma/client": "5.0.0" } });
    write("src/types.ts", "export interface Doc { schemaVersion: number; }\n");
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    expect(r.findings.some((f) => f.finding_type === "no-schema-versioning")).toBe(false);
  });

  it("lazy migration without a completion path → MEDIUM naming the file:line", () => {
    writeRootPkg({ name: "app", dependencies: { firebase: "10.0.0" } });
    write("src/lib/PersistenceService.ts", LAZY_READ_PATH_SOURCE);
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    const f = r.findings.find((x) => x.finding_type === "lazy-migration-without-backfill");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("medium");
    expect(f!.file).toBe("src/lib/PersistenceService.ts");
    expect(f!.line).toBeGreaterThan(1);
    expect(f!.detail).toMatch(/cold documents/i);
    // honesty: a static read of code shape, not an accusation
    expect(f!.detail).toMatch(/not proof/);
  });

  it("multiple lazy sites → ONE finding naming every site (Celestia3 has three)", () => {
    writeRootPkg({ name: "app", dependencies: { firebase: "10.0.0" } });
    write("src/lib/PersistenceService.ts", LAZY_READ_PATH_SOURCE);
    write(
      "src/lib/GrimoireService.ts",
      LAZY_READ_PATH_SOURCE.replace("PersistenceService", "GrimoireService"),
    );
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    const lazy = r.findings.filter(
      (f) => f.finding_type === "lazy-migration-without-backfill",
    );
    expect(lazy).toHaveLength(1); // one finding, not one per file
    expect(lazy[0]!.detail).toMatch(/Also detected at: src\/lib\/Persistence/);
  });

  it("lazy migration WITH a dedicated migration module → no lazy finding", () => {
    writeRootPkg({ name: "app", dependencies: { firebase: "10.0.0" } });
    write("src/lib/PersistenceService.ts", LAZY_READ_PATH_SOURCE);
    write(
      "services/migrationService.ts",
      "export async function migrateUserData(uid: string) {}\n",
    );
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    expect(
      r.findings.some((f) => f.finding_type === "lazy-migration-without-backfill"),
    ).toBe(false);
    // and the completeness summary note reports the signals honestly
    const note = r.notes.find((n) => /completeness signals/.test(n));
    expect(note).toMatch(/completion path yes/);
    expect(note).toMatch(/schema-version fields no/);
  });

  it("the schemaless detail names the Firestore/Mongo class when applicable", () => {
    writeRootPkg({ name: "app" });
    write("firestore.rules", "service cloud.firestore {}");
    const r = scanDataPosture(tmp, { tier: "customer-facing-saas" });
    const f = r.findings.find((x) => x.finding_type === "no-schema-versioning");
    expect(f!.detail).toMatch(/schemaless-store/);
  });
});

// ─── findings.jsonl mapping ──────────────────────────────────────────────────

describe("data-posture → Finding mapper", () => {
  function policyFinding(partial: Partial<DataPostureFinding> = {}): DataPostureFinding {
    return {
      finding_type: "no-discoverable-backup-path",
      severity: "medium",
      fixClass: "advisory",
      file: null,
      line: null,
      detail: "Persistent user data with no discoverable backup path.",
      remediation: "Name a backup path and run a restore drill.",
      ...partial,
    };
  }

  it("produces a valid Finding with the GAP-09 contract (no OWASP tag)", () => {
    const f = dataPostureToFinding(policyFinding(), "customer-facing-saas");
    expect(validateFinding(f)).toEqual([]);
    expect(f.primary_concern).toBe("data-posture");
    expect(f.secondary_concerns).toEqual([]);
    expect(f.owasp_2021).toBeNull(); // data integrity posture, not a weakness category
    expect(f.owasp_2025).toBeNull();
    expect(f.fix_class).toBe("advisory");
    expect(f.confidence).toBe(0.7);
    expect(f.severity_tier_adjusted).toBe("medium");
    expect(f.description).toMatch(/restore drill/);
  });

  it("file-bearing findings carry file + line through", () => {
    const f = dataPostureToFinding(
      policyFinding({
        finding_type: "lazy-migration-without-backfill",
        file: "src/lib/PersistenceService.ts",
        line: 58,
      }),
      "customer-facing-saas",
    );
    expect(validateFinding(f)).toEqual([]);
    expect(f.file).toBe("src/lib/PersistenceService.ts");
    expect(f.line).toBe(58);
    expect(f.title).toMatch(/Lazy migration/);
  });
});

// ─── tier gating + the not-applicable denominator rule ───────────────────────

describe("data-posture tier scope (GAP-09 gating)", () => {
  it("is registered as the 12th concern", () => {
    expect(ALL_CONCERNS).toContain("data-posture");
    expect(ALL_CONCERNS).toHaveLength(12);
  });

  it("prototype and internal skip it entirely; public-facing+ runs it", () => {
    expect(isInScope("data-posture", "prototype")).toBe(false);
    expect(isInScope("data-posture", "internal")).toBe(false);
    expect(isInScope("data-posture", "public-facing")).toBe(true);
    expect(isInScope("data-posture", "customer-facing-saas")).toBe(true);
    expect(isInScope("data-posture", "regulated")).toBe(true);
  });

  it("is never gate-mandatory — even at regulated (advisory class; restore verification is vibe-ops)", () => {
    for (const tier of ALL_TIERS) {
      expect(mandatoryConcerns(tier)).not.toContain("data-posture");
    }
  });

  it("folds into the gate's concern results at in-scope tiers", () => {
    const atSaas = foldConcernResults([], "customer-facing-saas");
    expect(atSaas.some((r) => r.concern === "data-posture")).toBe(true);
    const atProto = foldConcernResults([], "prototype");
    expect(atProto.some((r) => r.concern === "data-posture")).toBe(false);
  });

  it("the notApplicable list drops the concern from the denominator", () => {
    const results = foldConcernResults([], "customer-facing-saas", ["data-posture"]);
    expect(results.some((r) => r.concern === "data-posture")).toBe(false);
  });

  it("runGate honors not_applicable_concerns from the cached audit state", () => {
    const state: AuditState = {
      schema_version: 1,
      scanned_at: new Date().toISOString(),
      tier: "customer-facing-saas",
      tier_confidence: 0.9,
      score: 1,
      gate_pass: true,
      counts: { critical: 0, high: 0, medium: 1, low: 0 },
      findings_total: 1,
      tools_used: ["in-house"],
      not_applicable_concerns: ["data-posture"],
    };
    writeAuditState(tmp, state);
    // One medium data-posture finding on disk — if the concern stayed in the
    // fold it would shave the score below 1.0.
    appendFindings(tmp, [
      makeFinding({
        id: "dataposture-001",
        primary_concern: "data-posture",
        severity_base: "medium",
        severity_tier_adjusted: "medium",
        confidence: 0.7,
        finding_type: "no-discoverable-backup-path",
        title: "Persistent user data with no discoverable backup path",
        tier: "customer-facing-saas",
        fix_class: "advisory",
        tool_of_record: "in-house",
      }),
    ]);
    const withNa = runGate(tmp);
    expect(withNa.score).toBe(1); // dropped from the denominator entirely

    // Same state WITHOUT the not-applicable record → the finding counts.
    writeAuditState(tmp, { ...state, not_applicable_concerns: [] });
    const without = runGate(tmp);
    expect(without.score).toBeLessThan(1);
  });
});
