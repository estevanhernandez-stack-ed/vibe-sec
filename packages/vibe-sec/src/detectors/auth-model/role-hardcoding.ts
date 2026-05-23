// Role-hardcoding detection (spec §4.8 probe 6, synthesis §3.8).
//
// Zero-trust per-request authz beats role-string comparison. A `role === 'admin'`
// scattered across many files is an architectural finding at Public-facing+:
// each comparison is a place the rule can drift, and there's no single source of
// truth. We count distinct files with hardcoded role-string comparisons; the
// finding fires once at the project level when the count crosses a threshold,
// recommending a policy engine (Casbin / CASL / Cerbos / OPA) — but every site
// is recorded so the report can list them.
//
// A single role check is fine (informational); the architectural smell is the
// scatter. Threshold: 3+ distinct files (synthesis "scattered across files").

import { lineOf } from "../source-walk.js";

export interface RoleHardcodeSite {
  role: string;
  file: string;
  line: number;
}

export interface RoleHardcodeFinding {
  finding_type: "role-hardcoding-scattered";
  /** Number of distinct files with hardcoded role comparisons. */
  fileCount: number;
  sites: RoleHardcodeSite[];
  detail: string;
}

// `role === 'admin'` / `user.role == "editor"` / `'admin' === claims.role`.
const ROLE_COMPARE_RE =
  /(?:\brole\s*===?\s*["'`](\w+)["'`]|["'`](\w+)["'`]\s*===?\s*\w*\.?role\b)/g;

/** Collect hardcoded role-comparison sites in one source file. */
export function scanRoleHardcoding(text: string, filePath: string): RoleHardcodeSite[] {
  const sites: RoleHardcodeSite[] = [];
  ROLE_COMPARE_RE.lastIndex = 0;
  for (const m of text.matchAll(ROLE_COMPARE_RE)) {
    sites.push({
      role: m[1] ?? m[2] ?? "role",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
    });
  }
  return sites;
}

const SCATTER_THRESHOLD = 3;

/**
 * Roll the per-file sites up into a single architectural finding when role
 * checks are scattered across SCATTER_THRESHOLD+ distinct files. Returns null
 * when below threshold (a couple of role checks is normal).
 */
export function rollupRoleHardcoding(sites: readonly RoleHardcodeSite[]): RoleHardcodeFinding | null {
  const files = new Set(sites.map((s) => s.file));
  if (files.size < SCATTER_THRESHOLD) return null;
  return {
    finding_type: "role-hardcoding-scattered",
    fileCount: files.size,
    sites: [...sites],
    detail: `Hardcoded role-string comparisons are scattered across ${files.size} files. Each is a place the rule drifts and there's no single source of truth. Centralize authorization behind a policy engine (Casbin / CASL / Cerbos / OPA) so the rule lives in one place.`,
  };
}

export { SCATTER_THRESHOLD };
