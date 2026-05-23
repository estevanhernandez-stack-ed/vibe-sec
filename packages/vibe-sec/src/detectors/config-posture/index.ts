// Config-posture orchestrator (synthesis §3.5; checklist 2.4).
//
// Gathers the framework-config + header-declaring surfaces across the stack,
// runs the sub-detectors, and returns a unified posture. The config files we
// read for headers: next.config.*, vercel.json, netlify.toml, public/_headers,
// nginx.conf, .htaccess, plus middleware/server source for helmet + cookie +
// CORS call sites. Firebase rules + CVE-2025-29927 are checked from their own
// file/manifest sources.

import fs from "node:fs";
import path from "node:path";
import { analyzeHeaders, headerFindings, type HeaderFinding, type HeaderPosture } from "./headers.js";
import { scanCors, type CorsFinding } from "./cors.js";
import { scanCookies, type CookieFinding } from "./cookies.js";
import {
  scanFirebaseRules,
  isFirebaseRulesFile,
  type FirebaseRulesFinding,
} from "./firebase-rules.js";
import { detectCve202529927, type Cve202529927Result } from "./cve-2025-29927.js";

// Files that declare security headers somewhere in the stack.
const HEADER_CONFIG_FILES = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "vercel.json",
  "netlify.toml",
  "public/_headers",
  "_headers",
  "nginx.conf",
  ".htaccess",
];

// Source files likely to hold helmet/cookie/CORS call sites. We scan a shallow
// set of common server-entry locations rather than the whole tree.
const SERVER_SOURCE_GLOBS = [
  "server.js",
  "server.ts",
  "app.js",
  "app.ts",
  "index.js",
  "index.ts",
  "middleware.ts",
  "middleware.js",
  "src/server.ts",
  "src/app.ts",
  "src/index.ts",
  "src/middleware.ts",
];

const FIREBASE_RULES_FILES = [
  "firestore.rules",
  "storage.rules",
  "database.rules.json",
];

function readIfExists(projectRoot: string, rel: string): string | null {
  try {
    return fs.readFileSync(path.join(projectRoot, rel), "utf8");
  } catch {
    return null;
  }
}

export interface ConfigPostureResult {
  headers: HeaderPosture;
  headerFindings: HeaderFinding[];
  cors: CorsFinding[];
  cookies: CookieFinding[];
  firebaseRules: FirebaseRulesFinding[];
  cve202529927: Cve202529927Result;
}

/** Run the full config-posture pass over a project. */
export function scanConfigPosture(projectRoot: string): ConfigPostureResult {
  // 1. Headers — concatenate the config + server source so helmet defaults +
  //    explicit header declarations are both visible.
  const headerBlobs: string[] = [];
  for (const f of [...HEADER_CONFIG_FILES, ...SERVER_SOURCE_GLOBS]) {
    const text = readIfExists(projectRoot, f);
    if (text) headerBlobs.push(text);
  }
  const headers = analyzeHeaders(headerBlobs.join("\n"));

  // 2. CORS + cookies — scan the server source files.
  const cors: CorsFinding[] = [];
  const cookies: CookieFinding[] = [];
  for (const f of SERVER_SOURCE_GLOBS) {
    const text = readIfExists(projectRoot, f);
    if (!text) continue;
    cors.push(...scanCors(text, f));
    cookies.push(...scanCookies(text, f));
  }

  // 3. Firebase rules.
  const firebaseRules: FirebaseRulesFinding[] = [];
  for (const f of FIREBASE_RULES_FILES) {
    const text = readIfExists(projectRoot, f);
    if (text && isFirebaseRulesFile(f)) {
      firebaseRules.push(...scanFirebaseRules(text, f));
    }
  }

  // 4. CVE-2025-29927 (Next.js middleware bypass).
  const cve202529927 = detectCve202529927(projectRoot);

  return {
    headers,
    headerFindings: headerFindings(headers),
    cors,
    cookies,
    firebaseRules,
    cve202529927,
  };
}

export {
  analyzeHeaders,
  headerFindings,
  scanCors,
  scanCookies,
  scanFirebaseRules,
  isFirebaseRulesFile,
  detectCve202529927,
};
export type {
  HeaderPosture,
  HeaderFinding,
  CorsFinding,
  CookieFinding,
  FirebaseRulesFinding,
  Cve202529927Result,
};
