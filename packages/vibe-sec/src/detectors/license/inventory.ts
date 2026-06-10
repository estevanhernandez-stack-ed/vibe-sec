// node_modules license inventory (GAP-26; concern #11).
//
// Walks the INSTALLED tree — node_modules/*/package.json plus the scoped
// node_modules/@scope/*/package.json layer — reading each package's `license`
// field (string SPDX, legacy `licenses` array, `{ type }` object all handled
// by spdx.ts). Installed-tree-over-manifest is deliberate: the manifest names
// direct deps only; license obligations attach to everything conveyed,
// transitives included.
//
// Depth-bounded by construction: the walk reads exactly the top level (+ one
// level for @scopes) and never recurses into a package's own nested
// node_modules — nested copies are the same packages again.
//
// When node_modules is absent the result says so (nodeModulesPresent: false)
// and the caller emits a coverage advisory — mirroring the deps detector's
// notChecked rule: 0 findings must mean "looked and found nothing," never
// "couldn't look."
//
// Dev-flagging: npm's package-lock carries per-entry dev flags (best source —
// covers transitives). yarn/pnpm lockfiles don't mark dev in our neutral parse,
// and a missing lockfile leaves only the manifest's direct split. Anything
// unresolvable defaults to PROD — the conservative direction for a compliance
// scan (a dep wrongly treated as prod over-reports; wrongly treated as dev
// silently waives an obligation).

import fs from "node:fs";
import path from "node:path";
import { readDeclaredDeps, readLockfile } from "../supply-chain/lockfile.js";
import { classifyLicenseField, type LicenseClass } from "./spdx.js";

export interface PackageLicenseRecord {
  name: string;
  version: string;
  /** Normalized license expression; null when the field is absent. */
  licenseExpression: string | null;
  classification: LicenseClass;
  /** True only when positively identified as dev-only (see header note). */
  dev: boolean;
  /** Path of the package's manifest relative to the scanned root. */
  manifestPath: string;
}

export interface LicenseInventoryResult {
  nodeModulesPresent: boolean;
  packages: PackageLicenseRecord[];
}

/**
 * name → dev-only? A package that appears as BOTH a dev and a prod entry in
 * the lockfile (pulled by both sides) counts as prod — obligations attach to
 * the conveyed copy.
 */
function buildDevMap(projectRoot: string): Map<string, boolean> {
  const map = new Map<string, boolean>();
  const lock = readLockfile(projectRoot);
  for (const e of lock.entries) {
    const prev = map.get(e.name);
    map.set(e.name, prev === undefined ? e.dev : prev && e.dev);
  }
  if (map.size === 0) {
    // No parseable lockfile — fall back to the manifest's direct split.
    for (const d of readDeclaredDeps(projectRoot)) {
      const prev = map.get(d.name);
      map.set(d.name, prev === undefined ? d.dev : prev && d.dev);
    }
  }
  return map;
}

function readPackageRecord(
  pkgDir: string,
  name: string,
  manifestPath: string,
  devMap: ReadonlyMap<string, boolean>,
): PackageLicenseRecord | null {
  const manifestFile = path.join(pkgDir, "package.json");
  let raw: string;
  try {
    raw = fs.readFileSync(manifestFile, "utf8");
  } catch {
    return null; // not a package (leftover dir, .bin sibling, etc.)
  }
  let json: { name?: unknown; version?: unknown; license?: unknown; licenses?: unknown };
  try {
    json = JSON.parse(raw);
  } catch {
    // A package dir whose manifest won't parse still gets a record — its
    // license is unverifiable, which is itself the finding.
    return {
      name,
      version: "?",
      licenseExpression: null,
      classification: "unknown",
      dev: devMap.get(name) ?? false,
      manifestPath,
    };
  }
  const { expression, classification } = classifyLicenseField(
    json.license !== undefined ? json.license : json.licenses,
  );
  return {
    name: typeof json.name === "string" && json.name !== "" ? json.name : name,
    version: typeof json.version === "string" ? json.version : "?",
    licenseExpression: expression,
    classification,
    dev: devMap.get(name) ?? false,
    manifestPath,
  };
}

/**
 * Inventory every installed package's license under one package root.
 * Multi-root repos run this once per detected root, same as the other
 * manifest-rooted detectors.
 */
export function inventoryLicenses(projectRoot: string): LicenseInventoryResult {
  const nm = path.join(projectRoot, "node_modules");
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(nm, { withFileTypes: true });
  } catch {
    return { nodeModulesPresent: false, packages: [] };
  }

  const devMap = buildDevMap(projectRoot);
  const packages: PackageLicenseRecord[] = [];

  for (const entry of entries) {
    // Skip infrastructure: .bin, .cache, .package-lock.json, .pnpm (pnpm's
    // store — its packages surface through the top-level symlinks).
    if (entry.name.startsWith(".")) continue;

    if (entry.name.startsWith("@")) {
      // Scoped layer: node_modules/@scope/*/package.json.
      const scopeDir = path.join(nm, entry.name);
      let children: string[];
      try {
        children = fs.readdirSync(scopeDir);
      } catch {
        continue;
      }
      for (const child of children) {
        if (child.startsWith(".")) continue;
        const record = readPackageRecord(
          path.join(scopeDir, child),
          `${entry.name}/${child}`,
          path.posix.join("node_modules", entry.name, child, "package.json"),
          devMap,
        );
        if (record) packages.push(record);
      }
      continue;
    }

    const record = readPackageRecord(
      path.join(nm, entry.name),
      entry.name,
      path.posix.join("node_modules", entry.name, "package.json"),
      devMap,
    );
    if (record) packages.push(record);
  }

  return { nodeModulesPresent: true, packages };
}
