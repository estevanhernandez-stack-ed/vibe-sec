// Distribution-model detection (GAP-26; concern #11).
//
// License obligations key on HOW the app reaches users: a GPL dependency in a
// conveyed binary (Capacitor APK, Electron installer, Tauri bundle) triggers
// source obligations; the same dependency behind a SaaS endpoint does not
// (only AGPL reaches through the network). So the policy map needs the app's
// distribution model before it can grade a license class.
//
// Detection mirrors scanner/platform-fingerprint.ts: package.json dependency
// signals + file-structure hints, returned with confidence + the signals that
// fired. Binary signals win over SaaS signals — an app can be both (Celestia3:
// firebase.json AND @capacitor/android), and conveyance dominates the policy.

import fs from "node:fs";
import path from "node:path";

export type DistributionModel = "distributed-binary" | "saas" | "unknown";

export interface DistributionModelResult {
  model: DistributionModel;
  confidence: number;
  signals: string[];
}

interface PkgJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function readPkg(projectRoot: string): PkgJson {
  try {
    return JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
  } catch {
    return {};
  }
}

function exists(projectRoot: string, rel: string): boolean {
  try {
    fs.accessSync(path.join(projectRoot, rel));
    return true;
  } catch {
    return false;
  }
}

function matchDeps(pkg: PkgJson, re: RegExp): string[] {
  const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  return Object.keys(all).filter((d) => re.test(d));
}

// Wrapper frameworks that convey the JS bundle inside an installed artifact.
const BINARY_DEP_RE =
  /^(?:@capacitor\/|electron$|electron-builder$|@electron-forge\/|@tauri-apps\/|tauri$|react-native$|expo$)/;

// File-structure hints for a conveyed-binary build, including the .NET-adjacent
// packaging files (.nuspec / MSIX manifest) that show up in store-shipped apps.
const BINARY_FILE_HINTS = [
  "capacitor.config.ts",
  "capacitor.config.js",
  "capacitor.config.json",
  "src-tauri",
  "electron-builder.yml",
  "electron-builder.yaml",
  "electron-builder.json",
  "forge.config.js",
  "Package.appxmanifest",
  "appxmanifest.xml",
];

// Server frameworks / deploy configs → the app runs where the user can't
// receive a copy: SaaS.
const SERVER_DEP_RE =
  /^(?:express$|fastify$|koa$|hono$|@nestjs\/|next$|nuxt$|@sveltejs\/kit$|@remix-run\/|astro$|firebase-functions$)/;

const SAAS_FILE_HINTS = [
  "vercel.json",
  "netlify.toml",
  "firebase.json",
  "fly.toml",
  "render.yaml",
  "app.yaml",
  "serverless.yml",
  "Dockerfile",
];

// Client-side web frameworks — a plain web app with no binary wrapper defaults
// to SaaS (served, not conveyed).
const WEB_DEP_RE = /^(?:react$|react-dom$|vue$|svelte$|@angular\/core$|preact$|solid-js$)/;

/** Root-level *.nuspec sweep (NuGet packaging hint — store-shipped desktop). */
function hasRootNuspec(projectRoot: string): boolean {
  try {
    return fs.readdirSync(projectRoot).some((f) => f.toLowerCase().endsWith(".nuspec"));
  } catch {
    return false;
  }
}

/**
 * Detect how the app reaches users. Binary signals are checked first and win:
 * a conveyed artifact triggers the strictest license obligations regardless of
 * any server-side surface the same repo also ships.
 */
export function detectDistributionModel(projectRoot: string): DistributionModelResult {
  const pkg = readPkg(projectRoot);
  const signals: string[] = [];

  const binaryDeps = matchDeps(pkg, BINARY_DEP_RE);
  const binaryFiles = BINARY_FILE_HINTS.filter((f) => exists(projectRoot, f));
  if (hasRootNuspec(projectRoot)) binaryFiles.push("*.nuspec");

  if (binaryDeps.length > 0 || binaryFiles.length > 0) {
    for (const d of binaryDeps) signals.push(`dependency: ${d}`);
    for (const f of binaryFiles) signals.push(`file: ${f}`);
    return {
      model: "distributed-binary",
      confidence: binaryDeps.length > 0 ? 0.9 : 0.7,
      signals,
    };
  }

  const serverDeps = matchDeps(pkg, SERVER_DEP_RE);
  const saasFiles = SAAS_FILE_HINTS.filter((f) => exists(projectRoot, f));
  if (serverDeps.length > 0 || saasFiles.length > 0) {
    for (const d of serverDeps) signals.push(`dependency: ${d}`);
    for (const f of saasFiles) signals.push(`file: ${f}`);
    return { model: "saas", confidence: 0.7, signals };
  }

  const webDeps = matchDeps(pkg, WEB_DEP_RE);
  if (webDeps.length > 0) {
    for (const d of webDeps) signals.push(`dependency: ${d}`);
    signals.push("default: web app with no binary wrapper → saas");
    return { model: "saas", confidence: 0.5, signals };
  }

  return { model: "unknown", confidence: 0.3, signals };
}
