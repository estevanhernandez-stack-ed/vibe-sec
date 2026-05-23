// Auth-model orchestrator (concern #8 — the signature concern; spec §4.8,
// synthesis §3.8; checklist 3.2).
//
// The deepest detector. Six probes + the authorization matrix + the platform
// fingerprint prior + the joint CVE-2025-29927 (reused from config-posture, not
// re-implemented). Follows the established orchestration pattern: probe for the
// tool of record (Semgrep CE authz rules, CodeQL), defer when present, run the
// in-house baseline when absent — this concern is "always in-house" (synthesis
// §3.8): it's Vibe Sec's unique contribution, so the baseline always runs and
// Semgrep/CodeQL are Band-4 complements.
//
// Probes:
//   1. route-inventory   — enumerate routes per framework
//   2. admin-audit       — admin routes without role gating
//   3. tenant-isolation  — Supabase RLS gaps + Firestore + query tenant filter
//   4. idor              — gated Public-facing+ high-confidence (Decision 18)
//   5. session           — JWT-in-web-storage, cookie maxAge, library classify
//   6. role-hardcoding   — scattered role-string comparisons → policy engine
//   + authz-matrix       — the signature artifact (Decision 19)

import fs from "node:fs";
import path from "node:path";
import { walkSource } from "../source-walk.js";
import {
  scanRoutes,
  type Route,
  type RouteFramework,
  type AuthStatus,
} from "./route-inventory.js";
import { auditAdminRoutes, type AdminFinding } from "./admin-audit.js";
import {
  scanSupabaseMigration,
  scanFirestoreTenant,
  scanQueryTenantFilter,
  detectsTenantColumn,
  type TenantFinding,
} from "./tenant-isolation.js";
import { scanIdor, type IdorFinding } from "./idor.js";
import { scanSession, classifySessionLibrary, type SessionFinding, type SessionLibrary } from "./session.js";
import {
  scanRoleHardcoding,
  rollupRoleHardcoding,
  type RoleHardcodeFinding,
  type RoleHardcodeSite,
} from "./role-hardcoding.js";
import { buildAuthzMatrix, type AuthzMatrix } from "./authz-matrix.js";
import { fingerprintPlatform, type FingerprintResult } from "../../scanner/platform-fingerprint.js";
import { detectCve202529927, type Cve202529927Result } from "../config-posture/cve-2025-29927.js";
import {
  detectToolOfRecord,
  SEMGREP_TOOL_CANDIDATES,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";

// Project-wide centralized authz signal — defends IDOR structurally.
const CENTRALIZED_AUTHZ_RE =
  /\b(?:casbin|newEnforcer|@casl\/|defineAbility|cerbos|@cerbos\/|opa\.|prisma\.\$extends)\b/i;

// Supabase migration files (SQL + RLS).
const MIGRATION_GLOBS = [/supabase\/migrations\/.*\.sql$/, /(?:^|\/)migrations\/.*\.sql$/];
const FIRESTORE_RULES = ["firestore.rules", "storage.rules"];

export interface AuthModelScanResult {
  platform: FingerprintResult;
  routes: Route[];
  admin: AdminFinding[];
  tenant: TenantFinding[];
  /** All IDOR signals; the mapper gates ≥0.9 to Band-1 at Public-facing+. */
  idor: IdorFinding[];
  session: SessionFinding[];
  sessionLibrary: SessionLibrary;
  roleHardcoding: RoleHardcodeFinding | null;
  /** The signature artifact. */
  matrix: AuthzMatrix;
  cve202529927: Cve202529927Result;
  semgrepAvailable: boolean;
}

export interface AuthModelScanOptions {
  probe?: ToolProbe;
}

function readSqlAndRules(projectRoot: string): { file: string; text: string }[] {
  const out: { file: string; text: string }[] = [];
  // Firestore rules (fixed names).
  for (const rel of FIRESTORE_RULES) {
    try {
      out.push({ file: rel, text: fs.readFileSync(path.join(projectRoot, rel), "utf8") });
    } catch {
      // skip
    }
  }
  // SQL migrations — walk for *.sql under migration dirs.
  const walkDir = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      const rel = path.relative(projectRoot, full).replace(/\\/g, "/");
      if (/node_modules|\.git/.test(rel)) continue;
      if (e.isDirectory()) walkDir(full);
      else if (e.isFile() && rel.endsWith(".sql") && MIGRATION_GLOBS.some((re) => re.test(rel))) {
        try {
          out.push({ file: rel, text: fs.readFileSync(full, "utf8") });
        } catch {
          // skip
        }
      }
    }
  };
  walkDir(projectRoot);
  return out;
}

/** Run the full auth-model pass over a project. */
export function scanAuthModel(
  projectRoot: string,
  opts: AuthModelScanOptions = {},
): AuthModelScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const semgrep = detectToolOfRecord(SEMGREP_TOOL_CANDIDATES, probe);
  const platform = fingerprintPlatform(projectRoot);

  // Single source-tree pass collects per-file text + the route inventory.
  const fileText = new Map<string, string>();
  const routes: Route[] = [];
  let projectAuthzText = "";
  let tenantScoped = false;

  walkSource(projectRoot, [
    (text, rel) => {
      fileText.set(rel, text);
      projectAuthzText += text.includes("casbin") || text.includes("cerbos") || text.includes("$extends") ? text : "";
      if (detectsTenantColumn(text)) tenantScoped = true;
      routes.push(...scanRoutes(text, rel));
      return [];
    },
  ]);

  const hasCentralizedAuthz = CENTRALIZED_AUTHZ_RE.test(projectAuthzText);

  // Probe 2: admin audit (consumes the inventory).
  const admin = auditAdminRoutes(routes, fileText);

  // Probe 3: tenant isolation — SQL migrations + Firestore rules + source queries.
  const tenant: TenantFinding[] = [];
  const sqlAndRules = readSqlAndRules(projectRoot);
  for (const { file, text } of sqlAndRules) {
    if (file.endsWith(".rules")) tenant.push(...scanFirestoreTenant(text, file));
    else tenant.push(...scanSupabaseMigration(text, file));
    if (detectsTenantColumn(text)) tenantScoped = true;
  }
  for (const [file, text] of fileText) {
    tenant.push(...scanQueryTenantFilter(text, file, tenantScoped));
  }

  // Probe 4: IDOR (gated downstream; here we score every file).
  const idor: IdorFinding[] = [];
  for (const [file, text] of fileText) {
    idor.push(...scanIdor(text, file, hasCentralizedAuthz));
  }

  // Probe 5: session.
  const session: SessionFinding[] = [];
  let sessionLibrary: SessionLibrary = "unknown";
  for (const [file, text] of fileText) {
    session.push(...scanSession(text, file));
    if (sessionLibrary === "unknown") {
      const lib = classifySessionLibrary(text);
      if (lib !== "unknown") sessionLibrary = lib;
    }
  }

  // Probe 6: role-hardcoding (roll up across files).
  const roleSites: RoleHardcodeSite[] = [];
  for (const [file, text] of fileText) {
    roleSites.push(...scanRoleHardcoding(text, file));
  }
  const roleHardcoding = rollupRoleHardcoding(roleSites);

  // The signature artifact.
  const rlsApplicable =
    platform.platform === "lovable" ||
    sqlAndRules.some((f) => f.file.endsWith(".rules") || /enable\s+row\s+level\s+security/i.test(f.text));
  const matrix = buildAuthzMatrix({ routes, fileText, rlsApplicable });

  // Joint CVE-2025-29927 (reuse config-posture's rule, do not re-implement).
  const cve202529927 = detectCve202529927(projectRoot);

  return {
    platform,
    routes,
    admin,
    tenant,
    idor,
    session,
    sessionLibrary,
    roleHardcoding,
    matrix,
    cve202529927,
    semgrepAvailable: Boolean(semgrep?.present),
  };
}

export {
  scanRoutes,
  auditAdminRoutes,
  scanSupabaseMigration,
  scanFirestoreTenant,
  scanQueryTenantFilter,
  scanIdor,
  scanSession,
  classifySessionLibrary,
  scanRoleHardcoding,
  rollupRoleHardcoding,
  buildAuthzMatrix,
  fingerprintPlatform,
};
export type {
  Route,
  RouteFramework,
  AuthStatus,
  AdminFinding,
  TenantFinding,
  IdorFinding,
  SessionFinding,
  SessionLibrary,
  RoleHardcodeFinding,
  RoleHardcodeSite,
  AuthzMatrix,
  FingerprintResult,
};
