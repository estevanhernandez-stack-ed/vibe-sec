// Tenant-isolation query scan (spec §4.8 probe 3, synthesis §3.8).
//
// The Lovable/Supabase finding no other plugin catches, and the single most
// important statement in the auth-model brief: multi-tenant data leaks. Four
// surfaces:
//   - Supabase: a `create table` migration with no matching `enable row level
//     security` / `create policy`, OR an RLS policy of `using (true)`. An
//     RLS-less table on a Supabase project is a Critical candidate at
//     Customer-facing-SaaS+ (the tier scaling happens in the mapper).
//   - Firestore: `allow read, write: if true` (delegated jointly with
//     config-posture's firebase-rules; here we surface it as a tenant-isolation
//     signal so the matrix shows it).
//   - Prisma/Drizzle: a findMany / select on a tenant-scoped model with no
//     `where: { userId | tenantId | orgId }` clause — a horizontal-access risk.
//
// "Tenant-scoped" is inferred: the project declares a tenant_id / user_id / org_id
// column somewhere, so queries that omit it on the same models are suspicious.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface TenantFinding {
  finding_type:
    | "supabase-table-without-rls"
    | "supabase-rls-policy-true"
    | "firestore-permissive-rule"
    | "query-missing-tenant-filter";
  severity: Severity;
  subject: string;
  file: string;
  line: number;
  detail: string;
}

// ─── Supabase migrations ───────────────────────────────────────────────────
const CREATE_TABLE_RE = /\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?["']?(\w+)["']?/gi;
const ENABLE_RLS_RE = /\balter\s+table\s+(?:public\.)?["']?(\w+)["']?\s+enable\s+row\s+level\s+security/gi;
const RLS_POLICY_TRUE_RE = /\bcreate\s+policy\b[^;]*\busing\s*\(\s*true\s*\)/gi;

/** Scan a Supabase/SQL migration for RLS gaps. */
export function scanSupabaseMigration(text: string, filePath: string): TenantFinding[] {
  const findings: TenantFinding[] = [];

  // Tables that get RLS enabled somewhere in this file.
  const rlsEnabled = new Set<string>();
  ENABLE_RLS_RE.lastIndex = 0;
  for (const m of text.matchAll(ENABLE_RLS_RE)) {
    rlsEnabled.add((m[1] ?? "").toLowerCase());
  }

  // Tables created without a matching RLS-enable.
  CREATE_TABLE_RE.lastIndex = 0;
  for (const m of text.matchAll(CREATE_TABLE_RE)) {
    const table = (m[1] ?? "").toLowerCase();
    if (!rlsEnabled.has(table)) {
      findings.push({
        finding_type: "supabase-table-without-rls",
        severity: "critical",
        subject: table,
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        detail: `Supabase table "${table}" is created without enabling Row Level Security. With the anon/public key, any client can read and write every row. Run \`alter table ${table} enable row level security\` and add per-user policies.`,
      });
    }
  }

  // `using (true)` policies — RLS on, but the policy lets everyone through.
  RLS_POLICY_TRUE_RE.lastIndex = 0;
  for (const m of text.matchAll(RLS_POLICY_TRUE_RE)) {
    findings.push({
      finding_type: "supabase-rls-policy-true",
      severity: "critical",
      subject: "rls-policy",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "An RLS policy uses `using (true)` — it permits every row to every caller, which defeats the point of enabling RLS. Scope the policy to the authenticated user, e.g. `using (auth.uid() = user_id)`.",
    });
  }

  return findings;
}

// ─── Firestore rules (tenant-isolation view; joint with config-posture) ────
const FIRESTORE_TRUE_RE = /\ballow\s+(?:read|write|get|list|create|update|delete)[^;{]*:\s*if\s+true\b/gi;

export function scanFirestoreTenant(text: string, filePath: string): TenantFinding[] {
  const findings: TenantFinding[] = [];
  FIRESTORE_TRUE_RE.lastIndex = 0;
  for (const m of text.matchAll(FIRESTORE_TRUE_RE)) {
    findings.push({
      finding_type: "firestore-permissive-rule",
      severity: "critical",
      subject: "firestore-rule",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "A Firestore rule allows access `if true` — any client can read/write this collection. Scope it to request.auth.uid against the document owner.",
    });
  }
  return findings;
}

// ─── Prisma / Drizzle query tenant-filter scan ─────────────────────────────
// A query that selects rows with no co-located tenant/owner filter.
const PRISMA_QUERY_RE =
  /\b(?:prisma|db|ctx\.db|tx)\s*\.\s*(\w+)\s*\.\s*(findMany|findFirst|findUnique|update|updateMany|delete|deleteMany)\s*\(/g;
const TENANT_FILTER_RE = /\b(?:userId|user_id|tenantId|tenant_id|orgId|org_id|ownerId|owner_id|accountId)\b/;

function callArgSpan(text: string, openParenIdx: number): string {
  let depth = 0;
  let i = openParenIdx;
  for (; i < text.length && i < openParenIdx + 500; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) break;
    }
  }
  return text.slice(openParenIdx, i + 1);
}

/**
 * Scan source for Prisma/Drizzle reads/writes that omit a tenant filter. Only
 * fires when the project clearly has a tenant column (the caller passes
 * `tenantScoped`), to avoid flagging genuinely-global tables.
 */
export function scanQueryTenantFilter(
  text: string,
  filePath: string,
  tenantScoped: boolean,
): TenantFinding[] {
  if (!tenantScoped) return [];
  const findings: TenantFinding[] = [];
  PRISMA_QUERY_RE.lastIndex = 0;
  for (const m of text.matchAll(PRISMA_QUERY_RE)) {
    const model = m[1] ?? "";
    const op = m[2] ?? "";
    const idx = m.index ?? 0;
    const openParen = idx + m[0].length - 1;
    const args = callArgSpan(text, openParen);
    // findUnique by primary key is fine if it's an IDOR concern (covered by idor.ts);
    // here we care about findMany/updateMany-style ops that should be tenant-scoped.
    if (!TENANT_FILTER_RE.test(args)) {
      findings.push({
        finding_type: "query-missing-tenant-filter",
        severity: op.includes("Many") || op === "findMany" ? "high" : "medium",
        subject: `${model}.${op}`,
        file: filePath,
        line: lineOf(text, idx),
        detail: `${model}.${op}() runs with no tenant/owner filter (userId/tenantId/orgId). On a multi-tenant model this returns or mutates rows across tenants. Add the tenant scope to the where clause, or enforce it with RLS.`,
      });
    }
  }
  return findings;
}

/** Detect whether the project schema declares a tenant/owner column. */
export function detectsTenantColumn(text: string): boolean {
  return /\b(?:tenant_?[Ii]d|user_?[Ii]d|org_?[Ii]d|owner_?[Ii]d|account_?[Ii]d)\b/.test(text);
}
