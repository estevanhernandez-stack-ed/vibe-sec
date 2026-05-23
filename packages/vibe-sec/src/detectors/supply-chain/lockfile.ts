// Shared lockfile parser (spec §4.6, synthesis §3.6; checklist 2.2 + 2.3 share it).
//
// Both dependency-CVE (#1) and supply-chain hardening (#6) read the lockfile:
// CVE needs the resolved dependency tree, supply-chain needs pinning + integrity
// posture. Rather than two parsers drifting apart, this is the one module both
// import — it detects the package manager, parses the lockfile into a neutral
// shape (packages + their resolved versions + integrity presence), and reads the
// manifest's declared pin styles.
//
// Format coverage: npm (package-lock.json v2/v3), yarn (yarn.lock classic +
// berry), pnpm (pnpm-lock.yaml), bun (bun.lockb is binary — presence only).
// The parsers are intentionally tolerant: a field we don't recognize is skipped,
// never thrown. A lockfile we can't parse still reports its presence + manager.

import fs from "node:fs";
import path from "node:path";

export type PackageManager = "npm" | "yarn" | "pnpm" | "bun" | "unknown";

/** A resolved dependency entry from the lockfile. */
export interface LockEntry {
  name: string;
  version: string;
  /** True when the entry carries an integrity hash (sha512/sha1). */
  hasIntegrity: boolean;
  /** True when this is a dev-only dependency (best-effort per format). */
  dev: boolean;
}

/** A declared dependency pin from package.json (the manifest, not the lock). */
export interface DeclaredDep {
  name: string;
  /** The raw range string, e.g. "^1.2.3", "~2.0.0", "latest", "*", "1.2.3". */
  range: string;
  dev: boolean;
}

export type PinStyle = "exact" | "caret" | "tilde" | "floating" | "range" | "url" | "other";

export interface LockfileInfo {
  manager: PackageManager;
  lockfilePath: string | null;
  present: boolean;
  /** Parsed entries; empty for binary/unparseable lockfiles. */
  entries: LockEntry[];
  /** True when at least one entry carries an integrity hash. */
  hasIntegrity: boolean;
  /** True when the format is binary (bun.lockb) — presence only, no entries. */
  binary: boolean;
}

const LOCKFILES: { file: string; manager: PackageManager; binary?: boolean }[] = [
  { file: "package-lock.json", manager: "npm" },
  { file: "npm-shrinkwrap.json", manager: "npm" },
  { file: "pnpm-lock.yaml", manager: "pnpm" },
  { file: "yarn.lock", manager: "yarn" },
  { file: "bun.lockb", manager: "bun", binary: true },
];

/** Detect the lockfile (first match wins by the precedence above). */
export function detectLockfile(projectRoot: string): {
  file: string;
  manager: PackageManager;
  binary: boolean;
} | null {
  for (const lf of LOCKFILES) {
    const p = path.join(projectRoot, lf.file);
    if (fs.existsSync(p)) {
      return { file: p, manager: lf.manager, binary: Boolean(lf.binary) };
    }
  }
  return null;
}

// ─── npm package-lock.json (v2/v3) ───────────────────────────────────────
function parseNpmLock(text: string): LockEntry[] {
  let json: { packages?: Record<string, NpmPkg>; dependencies?: Record<string, NpmPkg> };
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  const entries: LockEntry[] = [];
  // v2/v3: the `packages` map keyed by node_modules path.
  if (json.packages) {
    for (const [key, pkg] of Object.entries(json.packages)) {
      if (key === "") continue; // the root project itself
      const name = key.replace(/^.*node_modules\//, "");
      if (!name || !pkg.version) continue;
      entries.push({
        name,
        version: pkg.version,
        hasIntegrity: Boolean(pkg.integrity),
        dev: Boolean(pkg.dev),
      });
    }
  } else if (json.dependencies) {
    // v1 fallback.
    walkNpmV1(json.dependencies, entries);
  }
  return entries;
}

interface NpmPkg {
  version?: string;
  integrity?: string;
  dev?: boolean;
  dependencies?: Record<string, NpmPkg>;
}

function walkNpmV1(deps: Record<string, NpmPkg>, out: LockEntry[]): void {
  for (const [name, pkg] of Object.entries(deps)) {
    if (pkg.version) {
      out.push({
        name,
        version: pkg.version,
        hasIntegrity: Boolean(pkg.integrity),
        dev: Boolean(pkg.dev),
      });
    }
    if (pkg.dependencies) walkNpmV1(pkg.dependencies, out);
  }
}

// ─── yarn.lock (classic) ─────────────────────────────────────────────────
function parseYarnLock(text: string): LockEntry[] {
  const entries: LockEntry[] = [];
  // Blocks separated by blank lines; header line lists one-or-more specs, body
  // has `  version "x"` and `  integrity ...`.
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    if (block.startsWith("#") || block.startsWith("__metadata")) continue;
    const header = block.split("\n")[0] ?? "";
    const spec = header.split(",")[0]?.trim().replace(/:$/, "").replace(/^"|"$/g, "") ?? "";
    // spec is like `name@^1.2.3` or `@scope/name@npm:^1.0.0`
    const at = spec.lastIndexOf("@");
    const name = at > 0 ? spec.slice(0, at) : spec;
    const versionMatch = block.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!name || !versionMatch) continue;
    entries.push({
      name,
      version: versionMatch[1]!.trim(),
      hasIntegrity: /\n\s+integrity\s+/.test(block) || /\n\s+checksum:\s+/.test(block),
      dev: false, // yarn.lock doesn't mark dev — classifier handles dev split
    });
  }
  return entries;
}

// ─── pnpm-lock.yaml ──────────────────────────────────────────────────────
function parsePnpmLock(text: string): LockEntry[] {
  const entries: LockEntry[] = [];
  // The `packages:` section keys are like `/name@1.2.3:` or `name@1.2.3:` (v9).
  const pkgSection = text.split(/\npackages:\n/)[1];
  if (!pkgSection) return entries;
  const lines = pkgSection.split("\n");
  let currentHasIntegrity = false;
  let current: { name: string; version: string } | null = null;
  const flush = () => {
    if (current) {
      entries.push({ ...current, hasIntegrity: currentHasIntegrity, dev: false });
    }
  };
  for (const line of lines) {
    const keyMatch = line.match(/^ {2}\/?(@?[^@\s]+(?:\/[^@\s]+)?)@([^():\s]+).*:$/);
    if (keyMatch) {
      flush();
      current = { name: keyMatch[1]!, version: keyMatch[2]! };
      currentHasIntegrity = false;
    } else if (current && /^\s+(integrity|resolution):/.test(line) && /integrity/.test(line)) {
      currentHasIntegrity = true;
    } else if (/^\S/.test(line)) {
      // left the packages section
      break;
    }
  }
  flush();
  return entries;
}

/** Parse a lockfile into the neutral shape. Tolerant — never throws. */
export function readLockfile(projectRoot: string): LockfileInfo {
  const detected = detectLockfile(projectRoot);
  if (!detected) {
    return {
      manager: "unknown",
      lockfilePath: null,
      present: false,
      entries: [],
      hasIntegrity: false,
      binary: false,
    };
  }
  if (detected.binary) {
    return {
      manager: detected.manager,
      lockfilePath: detected.file,
      present: true,
      entries: [],
      // bun.lockb is integrity-bearing by design; we just can't enumerate it.
      hasIntegrity: true,
      binary: true,
    };
  }
  let text = "";
  try {
    text = fs.readFileSync(detected.file, "utf8");
  } catch {
    // unreadable
  }
  let entries: LockEntry[] = [];
  switch (detected.manager) {
    case "npm":
      entries = parseNpmLock(text);
      break;
    case "yarn":
      entries = parseYarnLock(text);
      break;
    case "pnpm":
      entries = parsePnpmLock(text);
      break;
  }
  return {
    manager: detected.manager,
    lockfilePath: detected.file,
    present: true,
    entries,
    hasIntegrity: entries.some((e) => e.hasIntegrity),
    binary: false,
  };
}

// ─── manifest (package.json) pin styles ──────────────────────────────────
/** Classify a version range string into a pin style. */
export function classifyPin(range: string): PinStyle {
  const r = range.trim();
  if (r === "latest" || r === "*" || r === "" || r === "x") return "floating";
  if (/^(?:https?:|git\+|github:|file:|link:|workspace:)/.test(r)) return "url";
  if (/^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(r)) return "exact";
  if (r.startsWith("^")) return "caret";
  if (r.startsWith("~")) return "tilde";
  if (/[\s|<>=]/.test(r) || r.includes(" - ")) return "range";
  if (/^\d+(\.\d+)?(\.x)?$/.test(r) || r.endsWith(".x")) return "floating";
  return "other";
}

/** Read declared dependencies + their pin ranges from package.json. */
export function readDeclaredDeps(projectRoot: string): DeclaredDep[] {
  const pkgPath = path.join(projectRoot, "package.json");
  let json: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };
  try {
    json = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  } catch {
    return [];
  }
  const out: DeclaredDep[] = [];
  for (const [name, range] of Object.entries(json.dependencies ?? {})) {
    out.push({ name, range, dev: false });
  }
  for (const [name, range] of Object.entries(json.optionalDependencies ?? {})) {
    out.push({ name, range, dev: false });
  }
  for (const [name, range] of Object.entries(json.devDependencies ?? {})) {
    out.push({ name, range, dev: true });
  }
  return out;
}
