// Fix router — confidence-tier routing + destructive-action overrides (spec §8).
//
// Two layers, in this order:
//
//   1. Destructive-action override (HARD). A fixed set of action kinds is NEVER
//      auto-applied regardless of confidence — secret rotation, auth-logic
//      changes, JWT/session-secret regen, auth-middleware adds, RLS/policy
//      changes, password-hash migration, git-history rewrite. These route to
//      inline (runbook) or stage at most. The litmus review is explicit: do not
//      loosen this under user pressure.
//
//   2. Confidence-tier routing (SOFT, only when no override applies):
//        ≥0.90 → auto · 0.70-0.89 → stage · <0.70 → inline.
//
// The override always wins. A 0.99-confidence secret rotation still routes
// inline. This module is pure + deterministic so the gate/CI can rely on it and
// the routing logic is unit-tested directly.

import { type FixClass } from "../types.js";
import type { Finding } from "../state/findings.js";

// ─── Confidence thresholds (spec §8.1) ───────────────────────────────────────
export const AUTO_CONFIDENCE = 0.9;
export const STAGE_CONFIDENCE = 0.7;

/**
 * The destructive action kinds that NEVER auto-apply (spec §8.2). Keyed by a
 * stable kind so finding_type strings map to a kind once, here. Each carries the
 * floor route it's allowed to take — `inline` (runbook only) or `stage`.
 */
export type DestructiveKind =
  | "secret-rotation"
  | "auth-logic-change"
  | "jwt-session-secret-regen"
  | "auth-middleware-add"
  | "rls-policy-change"
  | "password-hash-migration"
  | "git-history-rewrite";

interface DestructiveRule {
  kind: DestructiveKind;
  /** The most-permissive route this kind may take. Never `auto`. */
  floor: Extract<FixClass, "inline" | "stage">;
  /** Why it's never auto — surfaced in the inline runbook card. */
  rationale: string;
}

const DESTRUCTIVE_RULES: Record<DestructiveKind, DestructiveRule> = {
  "secret-rotation": {
    kind: "secret-rotation",
    floor: "inline",
    rationale:
      "Rotating a secret is a live-credential operation against the provider — we never do it for you. Per-provider runbook card; rotation is step zero, scrubbing history is cosmetic after.",
  },
  "auth-logic-change": {
    kind: "auth-logic-change",
    floor: "inline",
    rationale:
      "Auth-logic edits change who can do what. A wrong auto-fix locks out users or opens a hole. Inline with the rationale; you apply it.",
  },
  "jwt-session-secret-regen": {
    kind: "jwt-session-secret-regen",
    floor: "inline",
    rationale:
      "Regenerating a JWT or session secret invalidates every live session. That's a deploy-coordinated action, never an auto-edit.",
  },
  "auth-middleware-add": {
    kind: "auth-middleware-add",
    floor: "stage",
    rationale:
      "Adding auth middleware to an existing route changes its access contract. Staged as a diff for you to review — never silently applied.",
  },
  "rls-policy-change": {
    kind: "rls-policy-change",
    floor: "stage",
    rationale:
      "RLS / Firestore-rules / policy changes are data-access migrations. Staged as a migration diff; you review and run it.",
  },
  "password-hash-migration": {
    kind: "password-hash-migration",
    floor: "inline",
    rationale:
      "Migrating a password hash (e.g. MD5 → Argon2id) changes stored credentials and needs a dual-read transition. Inline runbook always.",
  },
  "git-history-rewrite": {
    kind: "git-history-rewrite",
    floor: "inline",
    rationale:
      "Rewriting git history (filter-repo / BFG) is destructive and team-coordinated. Inline runbook only — we never execute it. Rotate the secret first; this is cleanup.",
  },
};

/**
 * Map a finding to a destructive kind, or null when it's not destructive.
 * Matches on finding_type substrings + primary_concern so a detector adding a
 * new finding_type in the same family is still caught. Conservative by design:
 * when in doubt, treat as destructive (fail safe, not safe-to-auto).
 */
export function destructiveKindOf(finding: Finding): DestructiveKind | null {
  const ft = finding.finding_type.toLowerCase();
  const concern = finding.primary_concern;

  // Secret findings → rotation is the remediation, always inline.
  if (concern === "secret-detection") return "secret-rotation";
  if (ft.includes("client-bundle") || ft.includes("client-key") || ft.includes("public-env-secret"))
    return "secret-rotation";

  // git history rewrite (inline-runbook-only).
  if (ft.includes("history") && (ft.includes("rewrite") || ft.includes("scrub"))) {
    return "git-history-rewrite";
  }

  // JWT / session secret regen.
  if (ft.includes("jwt") && (ft.includes("secret") || ft.includes("none") || ft.includes("weak"))) {
    return "jwt-session-secret-regen";
  }
  if (ft.includes("session") && ft.includes("secret")) return "jwt-session-secret-regen";

  // Password-hash migration.
  if (ft.includes("password") && (ft.includes("hash") || ft.includes("bcrypt") || ft.includes("plaintext"))) {
    return "password-hash-migration";
  }
  if (concern === "crypto-pii" && (ft.includes("weak-hash") || ft.includes("md5") || ft.includes("sha1"))) {
    return "password-hash-migration";
  }

  // RLS / Firestore-rules / policy changes.
  if (ft.includes("rls") || ft.includes("firestore") || ft.includes("firebase-rule") || ft.includes("permissive-rule") || ft.includes("policy")) {
    return "rls-policy-change";
  }
  if (concern === "config-posture" && ft.includes("rule")) return "rls-policy-change";

  // Auth-middleware adds to existing routes (stage minimum).
  if ((ft.includes("admin-route") || ft.includes("missing-auth") || ft.includes("no-auth") || ft.includes("middleware")) && concern === "auth-model") {
    return "auth-middleware-add";
  }
  if (ft.includes("cve-2025-29927")) return "auth-middleware-add";

  // General auth-logic changes (IDOR ownership inserts, tenant-isolation fixes,
  // role-hardcoding refactors) — never auto.
  if (concern === "auth-model") return "auth-logic-change";

  return null;
}

export interface RouteDecision {
  fixClass: FixClass;
  /** When the route was forced by a destructive override, the kind + rationale. */
  override: DestructiveRule | null;
  /** One-line explanation of why this route was chosen. */
  reason: string;
}

/**
 * Route a finding to a fix class. Destructive override first, then confidence.
 *
 * `inform-only` / `advisory` findings (no actionable fix) pass through unchanged —
 * the router only decides between auto / stage / inline for actionable fixes.
 */
export function routeFix(finding: Finding): RouteDecision {
  // Non-actionable classes pass through — nothing to route.
  if (finding.fix_class === "advisory" || finding.fix_class === "inform-only") {
    return {
      fixClass: finding.fix_class,
      override: null,
      reason: `${finding.fix_class} — no code change to route`,
    };
  }

  // 1. Destructive override (hard). Never auto, regardless of confidence.
  const kind = destructiveKindOf(finding);
  if (kind) {
    const rule = DESTRUCTIVE_RULES[kind];
    return {
      fixClass: rule.floor,
      override: rule,
      reason: `destructive-action override (${kind}) → ${rule.floor}, never auto`,
    };
  }

  // 2. Confidence-tier routing (soft).
  let fixClass: FixClass;
  if (finding.confidence >= AUTO_CONFIDENCE) fixClass = "auto";
  else if (finding.confidence >= STAGE_CONFIDENCE) fixClass = "stage";
  else fixClass = "inline";

  return {
    fixClass,
    override: null,
    reason: `confidence ${finding.confidence.toFixed(2)} → ${fixClass}`,
  };
}

/** True iff this finding is one the destructive overrides forbid auto-applying. */
export function isDestructive(finding: Finding): boolean {
  return destructiveKindOf(finding) !== null;
}

export { DESTRUCTIVE_RULES };
