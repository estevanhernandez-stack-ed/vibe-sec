// GAP-26 ground-truth harness — runs the license detector against real repos.
// Read-only on the targets. Run: npm run build && node scripts/ground-truth-license.mjs
import { scanLicenses, licenseCoverageAdvisory } from "../dist/index.js";

const TARGETS = [
  {
    root: "C:/Users/estev/Projects/Celestia3",
    label: "Celestia3 (expected TRUE POSITIVE: swisseph-wasm GPL-3.0 in a Capacitor-distributed commercial app -> HIGH)",
  },
  {
    root: "C:/Users/estev/Projects/Project-626Labs-1",
    label: "Project-626Labs-1 (expected TRUE NEGATIVE: node-forge (BSD-3-Clause OR GPL-2.0) must NOT flag)",
  },
];

for (const { root, label } of TARGETS) {
  console.log("=".repeat(78));
  console.log(`TARGET: ${label}`);
  console.log(`ROOT:   ${root}`);
  const r = scanLicenses(root);
  console.log(
    `distribution model: ${r.distribution.model} (confidence ${r.distribution.confidence}) — signals: ${r.distribution.signals.join("; ") || "none"}`,
  );
  if (r.notScanned) {
    console.log(`NOT SCANNED — ${licenseCoverageAdvisory().detail}`);
    continue;
  }
  console.log(`packages inventoried: ${r.packages.length}`);
  console.log(`findings: ${r.findings.length}`);
  for (const f of r.findings) {
    const subject = f.package
      ? `${f.package}@${f.version} [${f.licenseExpression}]`
      : `${f.members?.length ?? 0} packages batched`;
    console.log(`  [${f.severity.toUpperCase()}] ${f.finding_type} — ${subject}`);
    if (f.members) {
      for (const m of f.members.slice(0, 12)) {
        console.log(`      - ${m.package}@${m.version} [${m.licenseExpression ?? "no license field"}] (${m.classification})`);
      }
      if (f.members.length > 12) console.log(`      … and ${f.members.length - 12} more`);
    }
  }
  // The two named verdicts.
  const swisseph = r.findings.find((f) => f.package === "swisseph-wasm");
  if (swisseph) {
    console.log(
      `VERDICT swisseph-wasm: ${swisseph.severity.toUpperCase()} ${swisseph.finding_type} (${swisseph.licenseExpression})`,
    );
  }
  const forge = r.packages.find((p) => p.name === "node-forge");
  if (forge) {
    const flagged = r.findings.some(
      (f) => f.package === "node-forge" || f.members?.some((m) => m.package === "node-forge"),
    );
    console.log(
      `VERDICT node-forge: present ${forge.name}@${forge.version} [${forge.licenseExpression}] classified ${forge.classification} — flagged: ${flagged}`,
    );
  }
}
