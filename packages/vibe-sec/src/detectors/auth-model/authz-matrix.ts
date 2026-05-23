// Authorization matrix (Decision 19; spec §4.8, synthesis §3.8).
//
// The signature artifact of the auth-model concern — Vibe Sec's unique
// contribution vs Vibe Test's behavioral tests. A routes-by-authz-dimensions
// table:
//   rows    = routes (from the inventory)
//   columns = { auth-required, role-gated, ownership-enforced, RLS-applicable }
//   cells   = { enforced | absent | unknown | N/A }
//
// Rendered as a markdown table in the primary report, abbreviated in the
// terminal banner, full structure in the JSON sidecar. This module builds the
// structure; the report layer renders it. It's assembled from the route
// inventory plus the per-file presence of role gates, ownership filters, and
// RLS — so it's a projection over the other five probes' inputs, not a sixth
// scan.

import type { Route } from "./route-inventory.js";

export type Cell = "enforced" | "absent" | "unknown" | "n/a";

export const AUTHZ_DIMENSIONS = [
  "auth-required",
  "role-gated",
  "ownership-enforced",
  "rls-applicable",
] as const;

export type AuthzDimension = (typeof AUTHZ_DIMENSIONS)[number];

export interface MatrixRow {
  route: string;
  method: string;
  framework: string;
  file: string;
  cells: Record<AuthzDimension, Cell>;
}

export interface AuthzMatrix {
  rows: MatrixRow[];
  dimensions: readonly AuthzDimension[];
}

export interface MatrixInputs {
  routes: readonly Route[];
  /** Source text per file, to detect role gates / ownership filters / RLS. */
  fileText: Map<string, string>;
  /** Project-wide: does the data layer support RLS (Supabase / Firestore)? */
  rlsApplicable: boolean;
}

const ROLE_GATE_RE =
  /\b(?:role\s*===?\s*["'`]\w+["'`]|isAdmin\b|hasRole\s*\(|requireRole\s*\(|@Roles\s*\(|user\.role|session\.user\.role|roles?\.includes\s*\()/i;
const OWNERSHIP_RE =
  /\b(?:userId|user_id|tenantId|tenant_id|orgId|org_id|ownerId|owner_id|accountId)\b/;
const RLS_USE_RE = /\b(?:enable\s+row\s+level\s+security|auth\.uid\s*\(\)|request\.auth\.uid)\b/i;

/** Build the authorization matrix from the route inventory + per-file evidence. */
export function buildAuthzMatrix(inputs: MatrixInputs): AuthzMatrix {
  const rows: MatrixRow[] = inputs.routes.map((route) => {
    const text = inputs.fileText.get(route.file) ?? "";

    const authCell: Cell =
      route.authStatus === "enforced"
        ? "enforced"
        : route.authStatus === "absent"
          ? "absent"
          : "unknown";

    // Role-gated: only meaningful when the route reads admin/role-scoped.
    const roleCell: Cell = route.isAdmin
      ? ROLE_GATE_RE.test(text)
        ? "enforced"
        : "absent"
      : ROLE_GATE_RE.test(text)
        ? "enforced"
        : "n/a";

    // Ownership-enforced: a tenant/owner filter present in the handler file.
    const ownershipCell: Cell = OWNERSHIP_RE.test(text) ? "enforced" : "unknown";

    // RLS-applicable: N/A when the stack has no RLS; else enforced/absent by use.
    const rlsCell: Cell = inputs.rlsApplicable
      ? RLS_USE_RE.test(text)
        ? "enforced"
        : "absent"
      : "n/a";

    return {
      route: route.path,
      method: route.method,
      framework: route.framework,
      file: route.file,
      cells: {
        "auth-required": authCell,
        "role-gated": roleCell,
        "ownership-enforced": ownershipCell,
        "rls-applicable": rlsCell,
      },
    };
  });

  return { rows, dimensions: AUTHZ_DIMENSIONS };
}

/** Render the matrix as a GitHub-flavored markdown table (primary report). */
export function renderMatrixMarkdown(matrix: AuthzMatrix): string {
  const header = `| Route | Method | ${matrix.dimensions.join(" | ")} |`;
  const sep = `| --- | --- | ${matrix.dimensions.map(() => "---").join(" | ")} |`;
  const lines = matrix.rows.map((r) => {
    const cells = matrix.dimensions.map((d) => cellGlyph(r.cells[d])).join(" | ");
    return `| \`${r.route}\` | ${r.method} | ${cells} |`;
  });
  return [header, sep, ...lines].join("\n");
}

/** Glyph for terminal/markdown compactness — keeps the cell vocabulary explicit. */
export function cellGlyph(cell: Cell): string {
  switch (cell) {
    case "enforced":
      return "enforced";
    case "absent":
      return "ABSENT";
    case "unknown":
      return "unknown";
    case "n/a":
      return "n/a";
  }
}
