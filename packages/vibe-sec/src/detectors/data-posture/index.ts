// Data-posture orchestrator (GAP-09 static half; concern #12).
//
// Wires the pieces: persistence detection (persistence.ts — the applicability
// gate), backup-posture sweep (backup.ts), and the migration-discipline lint
// (migration.ts), folded through the policy map.
//
// SCOPE RULING (GAP-09): this is the STATIC half only. Live document sampling
// and shape correspondence are runtime work and belong to the future vibe-ops
// plugin. A static scanner can detect the ABSENCE of a backup config; it can
// never verify a restore works — every copy line here says so. Never overclaim.
//
// The policy map, keyed to tier (the detector takes the tier because the
// CHECKS differ by tier, not just the scoring):
//   - prototype / internal       → out of scope entirely (skip in SCOPE_GRID;
//     the detector returns an empty checksRun if called anyway)
//   - public-facing              → lightweight: backup check only
//   - customer-facing-saas / regulated → full: backup + migration lint
//
// Findings (all advisory — never gate-mandatory, max severity MEDIUM):
//   - persistence + zero discoverable backup signals → MEDIUM
//     "no-discoverable-backup-path" (restore is untested by definition)
//   - persistence + no schema versioning anywhere    → LOW
//     "no-schema-versioning" (the schemaless-drift class)
//   - lazy-on-read migration with no completion path → MEDIUM
//     "lazy-migration-without-backfill" (cold documents stay old-shape forever)
//
// NOT-APPLICABLE is a first-class verdict: no persistence → applicable: false,
// zero findings, and the concern drops OUT of the score denominator (see
// not_applicable_concerns in audit-state + foldConcernResults). Never a
// hollow pass, never a scold.

import type { FixClass, Severity, Tier } from "../../types.js";
import {
  detectPersistence,
  type PersistenceDetectionResult,
  type PersistenceKind,
} from "./persistence.js";
import {
  detectBackupPosture,
  type BackupPostureResult,
  type BackupSignal,
  type BackupSignalKind,
} from "./backup.js";
import {
  scanMigrationDiscipline,
  type MigrationScanResult,
  type MigrationSite,
  type MigrationSiteKind,
} from "./migration.js";

export type DataPostureFindingType =
  | "no-discoverable-backup-path"
  | "no-schema-versioning"
  | "lazy-migration-without-backfill";

export interface DataPostureFinding {
  finding_type: DataPostureFindingType;
  severity: Severity;
  fixClass: FixClass;
  file: string | null;
  line: number | null;
  detail: string;
  /** One-line remediation direction — operational work, not a code patch. */
  remediation: string;
}

export type DataPostureCheck = "backup" | "migration";

export interface DataPostureScanResult {
  /** False = no persistence layer → the concern is NOT APPLICABLE. */
  applicable: boolean;
  persistence: PersistenceDetectionResult;
  tier: Tier;
  /** Which checks the tier actually ran (lightweight = backup only). */
  checksRun: DataPostureCheck[];
  /** null when the check didn't run (not applicable, or out of tier scope). */
  backup: BackupPostureResult | null;
  migration: MigrationScanResult | null;
  findings: DataPostureFinding[];
  /**
   * Honesty notes the report must surface verbatim-ish: the not-applicable
   * verdict, the backup-presence cap (config ≠ verified restore), and the
   * migration completeness summary. Score-neutral by design — good posture
   * never shaves the score.
   */
  notes: string[];
}

export interface DataPostureScanOptions {
  tier: Tier;
}

const FULL_TIERS = new Set<Tier>(["customer-facing-saas", "regulated"]);
const SKIP_TIERS = new Set<Tier>(["prototype", "internal"]);

/** The copy for the not-applicable verdict — exported so reports stay consistent. */
export function dataPostureNotApplicableNote(
  persistence: PersistenceDetectionResult,
): string {
  const checked =
    persistence.signals.length > 0
      ? ` Signals seen: ${persistence.signals.join("; ")}.`
      : "";
  return (
    "data-posture: NOT APPLICABLE — no persistence layer detected (checked " +
    "package.json dependencies, framework config files, and source imports)." +
    checked +
    " The concern is excluded from the score denominator: nothing to protect " +
    "is not the same as a pass."
  );
}

function backupAbsenceFinding(backup: BackupPostureResult): DataPostureFinding {
  return {
    finding_type: "no-discoverable-backup-path",
    severity: "medium",
    fixClass: "advisory",
    file: null,
    line: null,
    detail:
      "Persistent user data with no discoverable backup path — restore is " +
      "untested by definition. Checked: " +
      backup.locationsChecked.join(", ") +
      ". A cloud-side backup schedule with zero repo footprint would be " +
      "invisible to this static check; if one exists, document it in the repo " +
      "so it is discoverable.",
    remediation:
      "Name a backup path (scheduled export, dump script, or managed backup) " +
      "and run a restore drill; document both in the repo.",
  };
}

function backupPresenceNote(backup: BackupPostureResult): string {
  const found = backup.signals
    .map((s) => `${s.kind}: ${s.file}${s.line ? `:${s.line}` : ""}`)
    .join("; ");
  return (
    `data-posture: backup path discovered (${found}). Honesty cap: the ` +
    "existence of backup config is NOT a verified restore — a schedule that " +
    "has never been restored from is untested by definition. The " +
    "restore-actually-works verification leg is runtime work and belongs to " +
    "vibe-ops."
  );
}

function noSchemaVersioningFinding(
  migration: MigrationScanResult,
  kinds: readonly PersistenceKind[],
): DataPostureFinding {
  const schemaless = kinds.includes("firestore") || kinds.includes("mongo");
  const machineryClause = migration.machineryPresent
    ? "Migration machinery exists, but no document carries a version stamp — " +
      "the migration keys on location or shape-guessing instead of a version field. "
    : "No migration machinery and no version field were detected. ";
  return {
    finding_type: "no-schema-versioning",
    severity: "low",
    fixClass: "advisory",
    file: null,
    line: null,
    detail:
      "Persisted documents carry no schema version (no schemaVersion / " +
      "schema_version / dataVersion / _v field found). " +
      machineryClause +
      "Schema drift is unrecoverable when you can't tell which shape a " +
      "document is" +
      (schemaless ? " — the schemaless-store (Firestore/Mongo) failure class" : "") +
      ".",
    remediation:
      "Add a schema-version field stamped on every write; version-check reads " +
      "so old shapes are detected instead of guessed.",
  };
}

function lazyWithoutBackfillFinding(
  sites: readonly MigrationSite[],
): DataPostureFinding {
  const first = sites[0]!;
  const also =
    sites.length > 1
      ? ` Also detected at: ${sites
          .slice(1)
          .map((s) => `${s.file}:${s.line}`)
          .join(", ")}.`
      : "";
  return {
    finding_type: "lazy-migration-without-backfill",
    severity: "medium",
    fixClass: "advisory",
    file: first.file,
    line: first.line,
    detail:
      `Lazy-on-read migration with no discoverable backfill/completion path (${first.detail}).${also} ` +
      "Lazy migration only converts documents that get read — cold documents " +
      "stay on the old shape forever, and the old-shape read path can never " +
      "be deleted. This is a static read of the code shape, not proof the " +
      "migration is incomplete; if a completion job exists outside this repo, " +
      "document it here.",
    remediation:
      "Add a backfill/completion job that walks remaining old-shape documents, " +
      "then retire the lazy branch.",
  };
}

function migrationSummaryNote(migration: MigrationScanResult): string {
  const yn = (b: boolean) => (b ? "yes" : "no");
  return (
    "data-posture: migration machinery present — completeness signals " +
    `(static): completion path ${yn(migration.completionPathPresent)}, ` +
    `schema-version fields ${yn(migration.schemaVersioningPresent)}, ` +
    `writes stamp a version ${yn(migration.writeStampsVersion)}, ` +
    `lazy-on-read shape ${yn(migration.lazyReadPathPresent)}, ` +
    `in-flight gating (dual-read/flag) ${yn(migration.gatingPresent)}.`
  );
}

/**
 * Full data-posture scan over one package root: persistence gate → tier-scoped
 * checks → policy map. Pure file-system reads; the policy matrix lives here
 * and nowhere else.
 */
export function scanDataPosture(
  projectRoot: string,
  opts: DataPostureScanOptions,
): DataPostureScanResult {
  const tier = opts.tier;
  const persistence = detectPersistence(projectRoot);

  // The applicability gate — out of the denominator, never a hollow pass.
  if (!persistence.persists) {
    return {
      applicable: false,
      persistence,
      tier,
      checksRun: [],
      backup: null,
      migration: null,
      findings: [],
      notes: [dataPostureNotApplicableNote(persistence)],
    };
  }

  // Tier scope: prototype/internal never run the checks (SCOPE_GRID skips the
  // concern there; this guard keeps a direct call honest too).
  if (SKIP_TIERS.has(tier)) {
    return {
      applicable: true,
      persistence,
      tier,
      checksRun: [],
      backup: null,
      migration: null,
      findings: [],
      notes: [
        `data-posture: persistence detected but the concern is out of scope at ${tier} tier (backup/migration obligations attach to user-facing operation).`,
      ],
    };
  }

  const findings: DataPostureFinding[] = [];
  const notes: string[] = [];
  const checksRun: DataPostureCheck[] = ["backup"];

  // Backup posture — every in-scope tier.
  const backup = detectBackupPosture(projectRoot);
  if (backup.signals.length === 0) {
    findings.push(backupAbsenceFinding(backup));
  } else {
    notes.push(backupPresenceNote(backup));
  }

  // Migration lint — full tiers only (public-facing is lightweight).
  let migration: MigrationScanResult | null = null;
  if (FULL_TIERS.has(tier)) {
    checksRun.push("migration");
    migration = scanMigrationDiscipline(projectRoot);

    if (!migration.schemaVersioningPresent) {
      findings.push(noSchemaVersioningFinding(migration, persistence.kinds));
    }

    if (migration.machineryPresent) {
      notes.push(migrationSummaryNote(migration));
      if (migration.lazyReadPathPresent && !migration.completionPathPresent) {
        const sites = migration.sites.filter((s) => s.kind === "lazy-read-path");
        if (sites.length > 0) findings.push(lazyWithoutBackfillFinding(sites));
      }
    }
  }

  return {
    applicable: true,
    persistence,
    tier,
    checksRun,
    backup,
    migration,
    findings,
    notes,
  };
}

export { detectPersistence, detectBackupPosture, scanMigrationDiscipline };
export type {
  PersistenceDetectionResult,
  PersistenceKind,
  BackupPostureResult,
  BackupSignal,
  BackupSignalKind,
  MigrationScanResult,
  MigrationSite,
  MigrationSiteKind,
};
