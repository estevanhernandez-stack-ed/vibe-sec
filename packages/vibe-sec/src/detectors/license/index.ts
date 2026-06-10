// License-compliance orchestrator (GAP-26; concern #11).
//
// Wires the pieces: inventory the installed tree (inventory.ts), classify each
// license expression (spdx.ts), detect the distribution model
// (distribution-model.ts), and grade every package through the policy map.
//
// The policy map, keyed to distribution model:
//   - strong-copyleft (GPL)   × distributed-binary → HIGH (conveyance triggers
//     source obligations)
//   - network-copyleft (AGPL) × any model          → HIGH (the network clause
//     reaches through SaaS)
//   - strong-copyleft         × saas               → MEDIUM advisory (no
//     conveyance — document the position)
//   - strong-copyleft         × unknown model      → MEDIUM (confirm the model;
//     becomes HIGH if the app ships a binary)
//   - weak-copyleft (LGPL/MPL/EPL) production deps → one LOW batch (dynamic-
//     linking nuance — don't cry wolf)
//   - missing / UNLICENSED / unparseable prod deps → one LOW batch
//   - copyleft devDependencies                     → one LOW inform-only batch
//     (not conveyed with the shipped artifact)
//   - dual-licensed with a permissive arm          → clean, no finding (the OR
//     rule in spdx.ts already classified it permissive)
//
// No license finding is ever gate-mandatory (see scoring/weighted-score.ts):
// remediation routes to business decisions — purchase, swap, open the source,
// or document the SaaS position — not code fixes.

import type { FixClass, Severity } from "../../types.js";
import {
  detectDistributionModel,
  type DistributionModel,
  type DistributionModelResult,
} from "./distribution-model.js";
import {
  inventoryLicenses,
  type LicenseInventoryResult,
  type PackageLicenseRecord,
} from "./inventory.js";
import type { LicenseClass } from "./spdx.js";

export type LicenseFindingType =
  | "strong-copyleft-in-distributed-binary"
  | "network-copyleft-dependency"
  | "strong-copyleft-server-side"
  | "strong-copyleft-unknown-distribution"
  | "weak-copyleft-dependencies"
  | "license-missing-or-unverifiable"
  | "dev-dependency-copyleft";

/** A member row of a batched (rollup) finding. */
export interface LicenseBatchMember {
  package: string;
  version: string;
  licenseExpression: string | null;
  classification: LicenseClass;
}

export interface LicensePolicyFinding {
  finding_type: LicenseFindingType;
  severity: Severity;
  fixClass: FixClass;
  /** Per-package findings carry the package; batches carry members instead. */
  package: string | null;
  version: string | null;
  licenseExpression: string | null;
  classification: LicenseClass | null;
  model: DistributionModel;
  dev: boolean;
  detail: string;
  /** One-line remediation direction (license purchase / swap / open / document). */
  remediation: string;
  /** Members of a batched finding; null on per-package findings. */
  members: LicenseBatchMember[] | null;
}

function member(p: PackageLicenseRecord): LicenseBatchMember {
  return {
    package: p.name,
    version: p.version,
    licenseExpression: p.licenseExpression,
    classification: p.classification,
  };
}

function describeModel(distribution: DistributionModelResult): string {
  const top = distribution.signals[0];
  return top
    ? `${distribution.model} (${top})`
    : distribution.model;
}

/**
 * Grade an inventoried package list against the distribution model. Pure —
 * the policy matrix lives here and nowhere else.
 */
export function evaluateLicensePolicy(
  packages: readonly PackageLicenseRecord[],
  distribution: DistributionModelResult,
): LicensePolicyFinding[] {
  const model = distribution.model;
  const modelLabel = describeModel(distribution);
  const findings: LicensePolicyFinding[] = [];

  const prod = packages.filter((p) => !p.dev);
  const dev = packages.filter((p) => p.dev);

  for (const p of prod) {
    if (p.classification === "network-copyleft") {
      findings.push({
        finding_type: "network-copyleft-dependency",
        severity: "high",
        fixClass: "advisory",
        package: p.name,
        version: p.version,
        licenseExpression: p.licenseExpression,
        classification: p.classification,
        model,
        dev: false,
        detail: `${p.name}@${p.version} is licensed ${p.licenseExpression} (network-copyleft). Distribution model: ${modelLabel}. The AGPL-class network clause attaches source obligations to user-reachable use — SaaS does not shield it.`,
        remediation:
          "Purchase a commercial license, swap for a permissively-licensed alternative, or open the user-reachable source under the same terms.",
        members: null,
      });
      continue;
    }
    if (p.classification === "strong-copyleft") {
      if (model === "distributed-binary") {
        findings.push({
          finding_type: "strong-copyleft-in-distributed-binary",
          severity: "high",
          fixClass: "advisory",
          package: p.name,
          version: p.version,
          licenseExpression: p.licenseExpression,
          classification: p.classification,
          model,
          dev: false,
          detail: `${p.name}@${p.version} is licensed ${p.licenseExpression} (strong-copyleft). Distribution model: ${modelLabel}. Conveying the binary triggers GPL source obligations for the combined work.`,
          remediation:
            "Purchase a commercial license, swap the dependency for a permissive alternative, or open the app's source under the GPL.",
          members: null,
        });
      } else if (model === "saas") {
        findings.push({
          finding_type: "strong-copyleft-server-side",
          severity: "medium",
          fixClass: "advisory",
          package: p.name,
          version: p.version,
          licenseExpression: p.licenseExpression,
          classification: p.classification,
          model,
          dev: false,
          detail: `${p.name}@${p.version} is licensed ${p.licenseExpression} (strong-copyleft). Distribution model: ${modelLabel}. Server-side use conveys nothing, so GPL source obligations do not trigger today.`,
          remediation:
            "Document the SaaS position; re-check if the distribution model changes or the dependency relicenses to AGPL.",
          members: null,
        });
      } else {
        findings.push({
          finding_type: "strong-copyleft-unknown-distribution",
          severity: "medium",
          fixClass: "advisory",
          package: p.name,
          version: p.version,
          licenseExpression: p.licenseExpression,
          classification: p.classification,
          model,
          dev: false,
          detail: `${p.name}@${p.version} is licensed ${p.licenseExpression} (strong-copyleft) and the distribution model could not be determined. If the app ships as an installed binary this is a HIGH conveyance obligation.`,
          remediation:
            "Confirm the distribution model — then license, swap, open the source, or document the SaaS position accordingly.",
          members: null,
        });
      }
    }
  }

  // Weak-copyleft production deps: one batch, LOW, advisory — the dynamic-
  // linking carve-outs (LGPL) and file-level scope (MPL/EPL) make these
  // routine-but-worth-knowing, not alarms.
  const weak = prod.filter((p) => p.classification === "weak-copyleft");
  if (weak.length > 0) {
    findings.push({
      finding_type: "weak-copyleft-dependencies",
      severity: "low",
      fixClass: "advisory",
      package: null,
      version: null,
      licenseExpression: null,
      classification: "weak-copyleft",
      model,
      dev: false,
      detail: `${weak.length} production ${weak.length === 1 ? "dependency carries" : "dependencies carry"} a weak-copyleft license (LGPL/MPL/EPL class): ${weak.map((p) => `${p.name}@${p.version} (${p.licenseExpression})`).join(", ")}. Distribution model: ${modelLabel}. Dynamic linking / file-level scope generally keeps your code unaffected as long as the libraries ship unmodified.`,
      remediation:
        "Keep these libraries unmodified, or publish your modifications to them; no obligation attaches to your own code.",
      members: weak.map(member),
    });
  }

  // Missing / UNLICENSED / unparseable production deps: one batch, LOW.
  const murky = prod.filter(
    (p) =>
      p.classification === "missing" ||
      p.classification === "unknown" ||
      p.classification === "proprietary",
  );
  if (murky.length > 0) {
    findings.push({
      finding_type: "license-missing-or-unverifiable",
      severity: "low",
      fixClass: "advisory",
      package: null,
      version: null,
      licenseExpression: null,
      classification: null,
      model,
      dev: false,
      detail: `${murky.length} production ${murky.length === 1 ? "dependency has" : "dependencies have"} a missing, UNLICENSED, or unparseable license field: ${murky.map((p) => `${p.name}@${p.version} (${p.licenseExpression ?? "no license field"})`).join(", ")}. An ungranted license defaults to all-rights-reserved.`,
      remediation:
        "Verify each license upstream (repo LICENSE file / npm page) and replace any dependency that grants no rights.",
      members: murky.map(member),
    });
  }

  // Copyleft devDependencies: capped at LOW inform-only — build-time tools are
  // not conveyed with the shipped artifact, so no distribution obligation
  // attaches. Missing-license dev deps are skipped outright (pure noise).
  const devCopyleft = dev.filter(
    (p) =>
      p.classification === "strong-copyleft" ||
      p.classification === "network-copyleft" ||
      p.classification === "weak-copyleft",
  );
  if (devCopyleft.length > 0) {
    findings.push({
      finding_type: "dev-dependency-copyleft",
      severity: "low",
      fixClass: "inform-only",
      package: null,
      version: null,
      licenseExpression: null,
      classification: null,
      model,
      dev: true,
      detail: `${devCopyleft.length} devDependenc${devCopyleft.length === 1 ? "y carries" : "ies carry"} a copyleft license: ${devCopyleft.map((p) => `${p.name}@${p.version} (${p.licenseExpression})`).join(", ")}. Severity is capped here because devDependencies are build-time only — they are not conveyed with the shipped artifact, so distribution obligations do not attach.`,
      remediation:
        "No action required while these stay dev-only; re-grade any that move into dependencies.",
      members: devCopyleft.map(member),
    });
  }

  return findings;
}

// ─── coverage advisory (mirror of deps depCoverageAdvisory) ──────────────────

export interface LicenseCoverageAdvisory {
  finding_type: "license-scan-not-performed";
  detail: string;
}

/**
 * The advisory the caller emits when node_modules is absent. A 0-finding
 * result in that state means "couldn't look," not "clean" — same honesty rule
 * as the dependency-CVE notChecked advisory.
 */
export function licenseCoverageAdvisory(): LicenseCoverageAdvisory {
  return {
    finding_type: "license-scan-not-performed",
    detail:
      "License scan requires installed node_modules — no node_modules directory was found under this root, so per-package license fields could not be read. This is NOT a clean pass: unchecked, not safe. Run npm/pnpm install, then re-run.",
  };
}

// ─── orchestrator ─────────────────────────────────────────────────────────────

export interface LicenseScanOptions {
  /** Override the detected distribution model (e.g. a CI-pinned model). */
  forceModel?: DistributionModel;
}

export interface LicenseScanResult {
  nodeModulesPresent: boolean;
  /**
   * True when the scan could not look at all (node_modules absent). The caller
   * must surface licenseCoverageAdvisory() so the empty findings list never
   * reads as a clean pass.
   */
  notScanned: boolean;
  distribution: DistributionModelResult;
  packages: PackageLicenseRecord[];
  findings: LicensePolicyFinding[];
}

/**
 * Full license-compliance scan over one package root: inventory → classify →
 * distribution model → policy map.
 */
export function scanLicenses(
  projectRoot: string,
  opts: LicenseScanOptions = {},
): LicenseScanResult {
  const detected = detectDistributionModel(projectRoot);
  const distribution: DistributionModelResult = opts.forceModel
    ? { model: opts.forceModel, confidence: 1, signals: ["forced by caller"] }
    : detected;

  const inventory: LicenseInventoryResult = inventoryLicenses(projectRoot);
  if (!inventory.nodeModulesPresent) {
    return {
      nodeModulesPresent: false,
      notScanned: true,
      distribution,
      packages: [],
      findings: [],
    };
  }

  return {
    nodeModulesPresent: true,
    notScanned: false,
    distribution,
    packages: inventory.packages,
    findings: evaluateLicensePolicy(inventory.packages, distribution),
  };
}

export { detectDistributionModel, inventoryLicenses };
export type {
  DistributionModel,
  DistributionModelResult,
  PackageLicenseRecord,
  LicenseInventoryResult,
};
export {
  classifyLicenseId,
  classifySpdxExpression,
  classifyLicenseField,
} from "./spdx.js";
export type { LicenseClass, ClassifiedLicenseField } from "./spdx.js";
