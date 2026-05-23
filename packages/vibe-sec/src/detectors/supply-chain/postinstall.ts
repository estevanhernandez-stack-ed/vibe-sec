// Postinstall-script inspection (synthesis §3.6).
//
// Postinstall hooks are the worm-propagation vector (Shai-Hulud, the npm
// install-time malware family). A package's install/postinstall/preinstall
// script runs arbitrary code the moment it lands in node_modules. pnpm v10 and
// bun default-disable these; npm is the remaining risk surface, so the hardening
// move is `ignore-scripts=true` in .npmrc at Public-facing+.
//
// This inspects:
//   1. the project's own package.json install hooks (informational — yours)
//   2. whether .npmrc sets ignore-scripts (the mitigation)
//   3. (depth-2 default) installed dependencies' install hooks via node_modules
//      package.json scan — the actual third-party risk surface.

import fs from "node:fs";
import path from "node:path";

const INSTALL_HOOKS = ["preinstall", "install", "postinstall"] as const;

export interface PostinstallFinding {
  package: string;
  hook: string;
  script: string;
  /** True when this is the project's own package (vs a dependency). */
  own: boolean;
}

export interface PostinstallScanResult {
  findings: PostinstallFinding[];
  /** True when .npmrc sets ignore-scripts=true (the mitigation is in place). */
  ignoreScriptsEnabled: boolean;
}

function readScripts(pkgPath: string): Record<string, string> {
  try {
    const json = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
      scripts?: Record<string, string>;
    };
    return json.scripts ?? {};
  } catch {
    return {};
  }
}

function npmrcIgnoresScripts(projectRoot: string): boolean {
  const npmrc = path.join(projectRoot, ".npmrc");
  try {
    const text = fs.readFileSync(npmrc, "utf8");
    return /^\s*ignore-scripts\s*=\s*true\s*$/im.test(text);
  } catch {
    return false;
  }
}

/**
 * Scan install hooks. `depth` controls dependency inspection: 0 = own package
 * only, 1+ = also scan node_modules top-level packages (Regulated goes full).
 */
export function scanPostinstall(
  projectRoot: string,
  opts: { depth?: number } = {},
): PostinstallScanResult {
  const depth = opts.depth ?? 2;
  const findings: PostinstallFinding[] = [];

  // 1. own package.json
  const ownScripts = readScripts(path.join(projectRoot, "package.json"));
  for (const hook of INSTALL_HOOKS) {
    if (ownScripts[hook]) {
      findings.push({ package: "(this project)", hook, script: ownScripts[hook]!, own: true });
    }
  }

  // 2. dependencies (depth ≥ 1)
  if (depth >= 1) {
    const nm = path.join(projectRoot, "node_modules");
    for (const dir of listNodeModulesPackages(nm)) {
      const scripts = readScripts(path.join(dir.full, "package.json"));
      for (const hook of INSTALL_HOOKS) {
        if (scripts[hook]) {
          findings.push({ package: dir.name, hook, script: scripts[hook]!, own: false });
        }
      }
    }
  }

  return { findings, ignoreScriptsEnabled: npmrcIgnoresScripts(projectRoot) };
}

/** List top-level (and @scope/*) package dirs under node_modules. */
function listNodeModulesPackages(nm: string): { name: string; full: string }[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(nm, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: { name: string; full: string }[] = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === ".bin" || e.name === ".cache") continue;
    if (e.name.startsWith("@")) {
      const scopeDir = path.join(nm, e.name);
      try {
        for (const inner of fs.readdirSync(scopeDir, { withFileTypes: true })) {
          if (inner.isDirectory()) {
            out.push({ name: `${e.name}/${inner.name}`, full: path.join(scopeDir, inner.name) });
          }
        }
      } catch {
        // skip unreadable scope
      }
    } else {
      out.push({ name: e.name, full: path.join(nm, e.name) });
    }
  }
  return out;
}
