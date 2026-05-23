// CVE dedup across OSV + npm audit (synthesis Decision 12).
//
// Run both scanners, then collapse to one finding per vulnerability. The merge
// rule: OSV wins on existence + the canonical id; npm audit wins on
// fix-availability (it knows whether a published fix is a breaking change). Two
// findings are the same vuln when their id sets (id ∪ aliases) intersect — a
// CVE in one namespace and its GHSA twin in the other must collapse.

import type { FixClass } from "../../types.js";
import type { DepVulnerability } from "./osv-client.js";

/** A deduped finding carries the fix routing npm audit contributed. */
export interface MergedDepFinding extends DepVulnerability {
  fixClass: FixClass;
  isMajor: boolean;
  /** Which scanners reported this vuln (for crediting + FP comparison). */
  sources: string[];
}

type AuditFinding = DepVulnerability & { fixClass?: FixClass; isMajor?: boolean };

/** Build the id-set for a finding (canonical id + all aliases, normalized). */
function idSet(f: DepVulnerability): Set<string> {
  const s = new Set<string>();
  if (f.id) s.add(f.id.toUpperCase());
  for (const a of f.aliases) if (a) s.add(a.toUpperCase());
  return s;
}

function intersects(a: Set<string>, b: Set<string>): boolean {
  for (const x of a) if (b.has(x)) return true;
  return false;
}

/**
 * Dedupe + merge OSV findings with npm-audit findings into one list, one entry
 * per vulnerability. OSV provides the canonical record; npm audit's fix routing
 * is layered on when it reported the same vuln. npm-audit-only vulns (OSV
 * missed or wasn't run) are kept with their own routing.
 */
export function mergeDepFindings(
  osv: readonly DepVulnerability[],
  audit: readonly AuditFinding[],
): MergedDepFinding[] {
  const merged: MergedDepFinding[] = [];

  // Seed with OSV findings (the existence authority).
  for (const o of osv) {
    merged.push({
      ...o,
      fixClass: o.fixedVersion ? "stage" : "inform-only",
      isMajor: false,
      sources: [o.source],
    });
  }

  for (const a of audit) {
    const aIds = idSet(a);
    // Match against an already-merged entry by id-set intersection AND package.
    const hit = merged.find(
      (m) => intersects(idSet(m), aIds) && m.package === a.package,
    );
    if (hit) {
      // npm audit wins on fix-availability.
      hit.fixClass = a.fixClass ?? hit.fixClass;
      hit.isMajor = a.isMajor ?? hit.isMajor;
      if (a.fixedVersion) hit.fixedVersion = a.fixedVersion;
      if (!hit.sources.includes(a.source)) hit.sources.push(a.source);
      // Merge aliases so future merges still match.
      hit.aliases = [...new Set([...hit.aliases, ...a.aliases, a.id])].filter(
        (x) => x && x !== hit.id,
      );
    } else {
      merged.push({
        ...a,
        fixClass: a.fixClass ?? (a.fixedVersion ? "stage" : "inform-only"),
        isMajor: a.isMajor ?? false,
        sources: [a.source],
      });
    }
  }

  return merged;
}
