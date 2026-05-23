// Application-vs-library classifier (synthesis Decision 11).
//
// Dev-dep CVEs are ~30% of raw npm-audit noise on application projects — a
// vulnerable test runner that never ships to prod isn't a runtime risk. So the
// default is `--omit=dev` on applications and full-tree on libraries (a
// library's devDeps ship to nobody, but a library is itself someone's dep, so
// its prod tree is what matters — and we don't want to hide a lib's own dev
// surface from its maintainer the way we'd hide an app's).
//
// The signal: a package with no `main`/`exports`/`bin` and a `private: true`
// flag (or a build/start script + framework deps) is an application. A package
// with `main`/`exports` and no `private` is a publishable library.

import fs from "node:fs";
import path from "node:path";

export type ProjectKind = "application" | "library";

export interface ClassifyProjectResult {
  kind: ProjectKind;
  /** Whether to pass --omit=dev to the audit (true for applications). */
  omitDev: boolean;
  rationale: string[];
}

interface Pkg {
  private?: boolean;
  main?: string;
  module?: string;
  exports?: unknown;
  bin?: unknown;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
}

const APP_FRAMEWORK_DEPS = new Set([
  "next",
  "react-scripts",
  "@remix-run/node",
  "vite",
  "@nestjs/core",
  "express",
  "fastify",
  "@sveltejs/kit",
  "nuxt",
  "astro",
  "@angular/core",
]);

/**
 * Classify a project as application or library from its package.json. An
 * unreadable/absent manifest defaults to application (the conservative choice:
 * apply dev filtering rather than flooding with devDep noise).
 */
export function classifyProject(projectRoot: string): ClassifyProjectResult {
  const pkgPath = path.join(projectRoot, "package.json");
  let pkg: Pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  } catch {
    return {
      kind: "application",
      omitDev: true,
      rationale: ["no readable package.json → default to application"],
    };
  }

  const rationale: string[] = [];
  let appScore = 0;
  let libScore = 0;

  if (pkg.private === true) {
    appScore += 2;
    rationale.push("private: true → application");
  }
  if (pkg.main || pkg.module || pkg.exports) {
    libScore += 2;
    rationale.push("has main/module/exports → library entry points");
  }
  if (pkg.bin && !pkg.main && !pkg.exports) {
    // CLI tool — treat as application for dev-filtering purposes.
    appScore += 1;
    rationale.push("bin without library entry → CLI application");
  }
  const scripts = pkg.scripts ?? {};
  if (scripts["start"] || scripts["dev"] || scripts["serve"]) {
    appScore += 1;
    rationale.push("has start/dev/serve script → application");
  }
  if (scripts["prepublishOnly"] || scripts["prepack"]) {
    libScore += 1;
    rationale.push("has publish lifecycle script → library");
  }
  const deps = pkg.dependencies ?? {};
  const frameworkHit = Object.keys(deps).find((d) => APP_FRAMEWORK_DEPS.has(d));
  if (frameworkHit) {
    appScore += 1;
    rationale.push(`depends on app framework (${frameworkHit}) → application`);
  }

  const kind: ProjectKind = appScore >= libScore ? "application" : "library";
  if (rationale.length === 0) {
    rationale.push("no strong signal → default to application");
  }
  return { kind, omitDev: kind === "application", rationale };
}
