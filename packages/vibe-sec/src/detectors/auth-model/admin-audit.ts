// Admin role-gating audit (spec §4.8 probe 2, synthesis §3.8).
//
// An admin route that isn't role-gated is the textbook broken-access-control
// finding (A01). This consumes the route inventory: for each route that reads as
// admin-scoped (path or handler name contains "admin"), check whether a role
// gate is present in the same handler/file — a `role === 'admin'`, `isAdmin`,
// `hasRole('admin')`, `requireRole`, `@Roles('admin')`, or RBAC middleware.
//
// "auth enforced" is necessary but NOT sufficient for an admin route — an
// authenticated non-admin user must still be rejected. So an admin route with
// auth but no role gate is flagged High (a logged-in user can reach admin), and
// an admin route with neither auth nor role gate is Critical.

import { lineOf } from "../source-walk.js";
import type { Route } from "./route-inventory.js";
import type { Severity } from "../../types.js";

export interface AdminFinding {
  finding_type: "admin-route-no-role-gate" | "admin-route-no-auth";
  severity: Severity;
  route: string;
  file: string;
  line: number;
  detail: string;
}

// A role gate is any of: a role compared (== or !=, allow-or-reject) against an
// "admin"/"manager" literal, a role helper (isAdmin / hasRole / checkAdminRole /
// requireRole / @Roles), a `<obj>.role` access compared to a string, a role
// field read (user.role / session.user.role / data.role), or roles.includes.
// Recognizing the REJECT form (`role !== 'admin'`) matters: hand-rolled Firebase
// admin servers commonly gate by rejecting non-admins (WSYATM dogfood).
const ROLE_GATE_RE =
  /\b(?:role\s*[!=]==?\s*["'`](?:admin|manager)["'`]|["'`](?:admin|manager)["'`]\s*[!=]==?\s*\w*role|isAdmin\b|hasRole\s*\(|requireRole\s*\(|checkRole\s*\(|checkAdminRole\s*\(|checkManagerRole\s*\(|@Roles\s*\(|\w*\.role\s*[!=]==?|user\.role|session\.user\.role|\w*[Dd]ata\.role|roles?\.includes\s*\(\s*["'`](?:admin|manager))/i;

/**
 * Audit the admin routes in an inventory against the source text of their files.
 * `fileText` maps a route's file → its full source (so we can check role gates).
 */
export function auditAdminRoutes(
  routes: readonly Route[],
  fileText: Map<string, string>,
): AdminFinding[] {
  const findings: AdminFinding[] = [];
  for (const route of routes) {
    if (!route.isAdmin) continue;
    const text = fileText.get(route.file) ?? "";
    const hasRoleGate = ROLE_GATE_RE.test(text);

    if (route.authStatus !== "enforced") {
      findings.push({
        finding_type: "admin-route-no-auth",
        severity: "critical",
        route: route.path,
        file: route.file,
        line: route.line,
        detail: `Admin route ${route.method} ${route.path} has no detectable auth check. Anyone can reach it. Add authentication AND an admin role gate.`,
      });
    } else if (!hasRoleGate) {
      findings.push({
        finding_type: "admin-route-no-role-gate",
        severity: "high",
        route: route.path,
        file: route.file,
        line: route.line,
        detail: `Admin route ${route.method} ${route.path} is authenticated but has no role gate. Any logged-in user — not just admins — can reach it. Add a role check (e.g. require user.role === 'admin').`,
      });
    }
  }
  return findings;
}
