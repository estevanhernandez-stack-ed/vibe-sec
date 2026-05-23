// IDOR scoring (spec §4.8 probe 4, Decision 18; synthesis §3.8).
//
// Industry SAST hits 50%+ FP on IDOR. To bring Vibe Sec's contribution to the
// 12% target, IDOR is gated three ways:
//   1. tier ≥ Public-facing (the caller enforces; the mapper drops sub-tier),
//   2. confidence ≥ 0.9, and
//   3. all three high-confidence conditions hold:
//      a. the route accepts an :id-style param (path param or req.params.id),
//      b. the DB query uses that id directly with NO co-located ownership filter
//         (userId / tenantId / orgId / ownerId), and
//      c. NO centralized authz pattern is detected project-wide (Casbin enforcer,
//         a Prisma authz extension, or RLS) — those defend IDOR structurally.
//
// Lower-confidence signals (an :id param but a centralized enforcer exists, or
// an ownership filter is present) become Band-2 "worth reviewing" notes, not
// Band-1 findings. The scorer returns the confidence so the orchestrator can
// route accordingly.

import { lineOf } from "../source-walk.js";

export interface IdorFinding {
  finding_type: "idor-direct-object-reference";
  /** ≥0.9 = Band-1 finding; below = Band-2 "worth reviewing." */
  confidence: number;
  subject: string;
  file: string;
  line: number;
  detail: string;
}

// A handler that pulls an id from the request path/params.
const ID_PARAM_RE =
  /\b(?:req\.params\.(\w*[iI]d)|params\.(\w*[iI]d)|ctx\.params\.(\w*[iI]d)|\bparams\s*:\s*\{\s*(\w*[iI]d))\b/;
// A query that uses that id directly: where: { id } / findUnique({ where: { id }}).
const ID_QUERY_RE =
  /\b(?:findUnique|findFirst|update|delete)\s*\(\s*\{[^}]*\bwhere\s*:\s*\{[^}]*\bid\b/;
// Co-located ownership filter — defeats the IDOR.
const OWNERSHIP_FILTER_RE = /\b(?:userId|user_id|tenantId|tenant_id|orgId|org_id|ownerId|owner_id|accountId)\b/;

// Project-wide centralized authz patterns that structurally defend IDOR.
const CENTRALIZED_AUTHZ_RE =
  /\b(?:casbin|newEnforcer|@casl\/|defineAbility|cerbos|@cerbos\/|OPA|opa\.|prisma\.\$extends|\.\$allTables|rls|rowLevelSecurity)\b/i;

/**
 * Score IDOR risk for a single source file. `hasCentralizedAuthz` is a
 * project-wide signal the orchestrator computes once and passes in.
 */
export function scanIdor(
  text: string,
  filePath: string,
  hasCentralizedAuthz: boolean,
): IdorFinding[] {
  const findings: IdorFinding[] = [];

  const idParamMatch = text.match(ID_PARAM_RE);
  if (!idParamMatch) return findings;

  const usesIdQuery = ID_QUERY_RE.test(text);
  if (!usesIdQuery) return findings;

  const hasOwnership = OWNERSHIP_FILTER_RE.test(text);
  const hasFileAuthz = CENTRALIZED_AUTHZ_RE.test(text);

  // High-confidence IDOR: id param + direct id query + no ownership filter + no
  // centralized authz anywhere.
  let confidence = 0.5;
  if (!hasOwnership) confidence += 0.25;
  if (!hasCentralizedAuthz && !hasFileAuthz) confidence += 0.2;
  // The id param being the SAME field the query keys on tightens it further.
  if (!hasOwnership && !hasCentralizedAuthz && !hasFileAuthz) confidence = 0.92;

  const idx = idParamMatch.index ?? 0;
  findings.push({
    finding_type: "idor-direct-object-reference",
    confidence,
    subject: idParamMatch[1] ?? idParamMatch[2] ?? idParamMatch[3] ?? idParamMatch[4] ?? "id",
    file: filePath,
    line: lineOf(text, idx),
    detail:
      confidence >= 0.9
        ? "Route takes an :id param and queries by it with no ownership filter and no centralized authz. An authenticated user can substitute another user's id to read/modify their object (IDOR). Add an ownership check (where: { id, userId: session.user.id }) or enforce it with RLS."
        : "Route takes an :id param and queries by it — worth confirming the object is scoped to the caller. Lower-confidence: an ownership filter or centralized authz appears present.",
  });

  return findings;
}
