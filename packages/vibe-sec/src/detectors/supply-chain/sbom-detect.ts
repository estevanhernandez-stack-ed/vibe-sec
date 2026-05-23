// SBOM detection — detection only (synthesis §3.6, Decision 25).
//
// v0.2 detects whether the project already ships an SBOM (CycloneDX / SPDX) and
// surfaces Syft as the Band-4 generation complement when it doesn't. SBOM
// GENERATION is a v0.3 emitter with its own correctness bar (Syft passthrough)
// — we deliberately do not invoke `syft` here, only probe for an existing bill
// of materials. US EO 14028 + EU CRA are pushing SBOM down to anyone shipping
// software, so even at lower tiers we report presence as informational context.

import fs from "node:fs";
import path from "node:path";
import { SBOM_FILENAMES } from "../../orchestration/defer.js";

export type SbomFormat = "cyclonedx" | "spdx" | "unknown";

export interface SbomDetectResult {
  present: boolean;
  /** The SBOM file path when found. */
  file: string | null;
  format: SbomFormat;
}

function sniffFormat(text: string): SbomFormat {
  try {
    const json = JSON.parse(text) as { bomFormat?: string; spdxVersion?: string };
    if (json.bomFormat === "CycloneDX") return "cyclonedx";
    if (json.spdxVersion) return "spdx";
  } catch {
    // not JSON or unreadable
  }
  if (/CycloneDX/i.test(text)) return "cyclonedx";
  if (/SPDX-/i.test(text)) return "spdx";
  return "unknown";
}

/**
 * Detect an existing SBOM in the project. Detection-only — never generates one.
 * Returns present=false when none of the known SBOM filenames exist.
 */
export function detectSbom(projectRoot: string): SbomDetectResult {
  for (const name of SBOM_FILENAMES) {
    const p = path.join(projectRoot, name);
    if (fs.existsSync(p)) {
      let text = "";
      try {
        text = fs.readFileSync(p, "utf8");
      } catch {
        // present but unreadable — still counts as present
      }
      return { present: true, file: name, format: sniffFormat(text) };
    }
  }
  return { present: false, file: null, format: "unknown" };
}
