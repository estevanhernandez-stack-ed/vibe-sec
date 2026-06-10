// GAP-09 ground-truth harness — runs the data-posture detector against real repos.
// Read-only on the targets. Run: npm run build && node scripts/ground-truth-data-posture.mjs
import { scanDataPosture } from "../dist/index.js";

const TIER = "customer-facing-saas"; // force full checks (backup + migration lint)

const TARGETS = [
  {
    root: "C:/Users/estev/Projects/Celestia3",
    label:
      "Celestia3 (expected: Firestore persistence; lazy migration in PersistenceService read path; backup posture as found)",
  },
  {
    root: "C:/Users/estev/Projects/Project-626Labs-1",
    label:
      "Project-626Labs-1 (expected: persistence; in-flight Firestore->Data-Connect migration via migrationService; lint verdict as found)",
  },
];

const LOAD_BEARING_KINDS = new Set([
  "migration-module",
  "backfill-symbol",
  "lazy-read-path",
  "schema-version-field",
  "version-checked-read",
  "write-stamps-version",
  "gating-flag",
]);
const MAX_SITES_PER_KIND = 8;

for (const { root, label } of TARGETS) {
  console.log("=".repeat(78));
  console.log(`TARGET: ${label}`);
  console.log(`ROOT:   ${root}`);
  console.log(`TIER:   ${TIER} (forced — full checks)`);
  const r = scanDataPosture(root, { tier: TIER });

  console.log(`applicable: ${r.applicable}`);
  console.log(
    `persistence: kinds=[${r.persistence.kinds.join(", ")}] — signals: ${r.persistence.signals.join("; ") || "none"}`,
  );
  console.log(`checks run: ${r.checksRun.join(", ") || "none"}`);

  if (r.backup) {
    console.log(`backup signals: ${r.backup.signals.length}`);
    for (const s of r.backup.signals.slice(0, 12)) {
      console.log(`  - [${s.kind}] ${s.file}${s.line ? `:${s.line}` : ""} — ${s.detail}`);
    }
  }

  if (r.migration) {
    const m = r.migration;
    console.log(
      `migration lint: machinery=${m.machineryPresent} schemaVersioning=${m.schemaVersioningPresent} ` +
        `writeStampsVersion=${m.writeStampsVersion} completionPath=${m.completionPathPresent} ` +
        `lazyReadPath=${m.lazyReadPathPresent} gating=${m.gatingPresent}`,
    );
    const byKind = new Map();
    for (const s of m.sites) {
      const arr = byKind.get(s.kind) ?? [];
      arr.push(s);
      byKind.set(s.kind, arr);
    }
    for (const [kind, sites] of byKind) {
      console.log(`  ${kind}: ${sites.length} site(s)`);
      if (!LOAD_BEARING_KINDS.has(kind)) continue;
      for (const s of sites.slice(0, MAX_SITES_PER_KIND)) {
        console.log(`    - ${s.file}:${s.line} — ${s.detail}`);
      }
      if (sites.length > MAX_SITES_PER_KIND) {
        console.log(`    … and ${sites.length - MAX_SITES_PER_KIND} more`);
      }
    }
  }

  console.log(`findings: ${r.findings.length}`);
  for (const f of r.findings) {
    const loc = f.file ? ` @ ${f.file}${f.line ? `:${f.line}` : ""}` : "";
    console.log(`  [${f.severity.toUpperCase()}] ${f.finding_type}${loc}`);
    console.log(`      ${f.detail}`);
    console.log(`      remediation: ${f.remediation}`);
  }
  for (const n of r.notes) console.log(`note: ${n}`);
}
