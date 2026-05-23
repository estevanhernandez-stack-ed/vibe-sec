// Tool-of-record detection (spec §1.2, §3; checklist 1.6).
//
// The orchestration layer's first move per concern: is the external tool of
// record on PATH? This is the which-probe + version detect. The probe is
// injectable so tests can mock "gitleaks present" without a real binary, and
// so the deferral path can be exercised deterministically.

import { execFileSync } from "node:child_process";

export type ToolName =
  | "gitleaks"
  | "trufflehog"
  | "osv-scanner"
  | "semgrep"
  | "syft"
  | "trivy";

export interface ToolPresence {
  name: ToolName;
  present: boolean;
  version: string | null;
}

/**
 * A probe answers "is <tool> on PATH, and what version?" The default probe
 * shells out; tests inject a fake. Returns null version when undetectable.
 */
export type ToolProbe = (tool: ToolName) => ToolPresence;

/** The version flag each tool understands. */
const VERSION_FLAG: Record<ToolName, string[]> = {
  gitleaks: ["version"],
  trufflehog: ["--version"],
  "osv-scanner": ["--version"],
  semgrep: ["--version"],
  syft: ["version"],
  trivy: ["--version"],
};

/**
 * Default probe: run `<tool> <version-flag>` and capture stdout. A non-zero
 * exit or spawn error means "not present." Cross-platform: execFileSync
 * resolves the executable via PATH on win32 (.cmd/.exe) and posix alike.
 */
export const defaultToolProbe: ToolProbe = (tool) => {
  try {
    const out = execFileSync(tool, VERSION_FLAG[tool], {
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
      timeout: 5000,
      windowsHide: true,
    });
    return { name: tool, present: true, version: parseVersion(out) };
  } catch {
    return { name: tool, present: false, version: null };
  }
};

function parseVersion(out: string): string | null {
  const m = out.match(/\d+\.\d+(?:\.\d+)?/);
  return m ? m[0] : out.trim().split("\n")[0]?.trim() || null;
}

/**
 * Detect which tool of record (if any) is present for a list of candidates,
 * in priority order. Returns the first present tool, or null when none are.
 */
export function detectToolOfRecord(
  candidates: readonly ToolName[],
  probe: ToolProbe = defaultToolProbe,
): ToolPresence | null {
  for (const tool of candidates) {
    const presence = probe(tool);
    if (presence.present) return presence;
  }
  return null;
}

/** Convenience: the secret-detection tool-of-record priority order. */
export const SECRET_TOOL_CANDIDATES: readonly ToolName[] = [
  "gitleaks",
  "trufflehog",
];

/** Dependency-CVE tool-of-record priority order (OSV-Scanner primary). */
export const DEP_TOOL_CANDIDATES: readonly ToolName[] = ["osv-scanner"];

/** Supply-chain SBOM-generation tool-of-record (Syft — detection only in v0.2). */
export const SBOM_TOOL_CANDIDATES: readonly ToolName[] = ["syft"];
