// Auto-apply engine — the deliberately-small allowed set (spec §8.3).
//
// `/vibe-sec:fix --auto` is allowed to do ONLY these, and nothing else routes
// here even at ≥0.90 confidence:
//
//   - .gitignore additions (+ git rm --cached + the "only prevents FUTURE
//     commits" banner — secrets already committed still need rotation)
//   - additive security headers (missing, never replacing existing)
//   - CSP report-only (enforcing CSP always stages)
//   - in-range SCA patch/minor bumps with lockfile-churn rollback (>50 lines → re-stage)
//   - standardHeaders: true on an existing rateLimit()
//   - algorithms: constraint on jwt.verify
//   - ignore-scripts=true to .npmrc
//   - permissions: contents: read to a workflow
//   - SHA-pin a GitHub Action (only when CI passed in the last 7 days)
//
// Everything else stages or inlines. The allowlist is an explicit enum, not a
// confidence threshold — the small set is the safety contract, by design.
//
// This module is filesystem-touching but each operation is gated + reports what
// it did. The git operations route through an injectable runner so tests stay
// hermetic.

import fs from "node:fs";
import path from "node:path";
import type { Finding } from "../state/findings.js";
import { isDestructive } from "./route.js";
import { LOCKFILE_CHURN_LIMIT } from "../detectors/deps/index.js";

/** The fix kinds `--auto` is allowed to apply. Closed set, by design (spec §8.3). */
export type AutoFixKind =
  | "gitignore-add"
  | "additive-security-header"
  | "csp-report-only"
  | "sca-in-range-bump"
  | "rate-limit-standard-headers"
  | "jwt-algorithms-constraint"
  | "npmrc-ignore-scripts"
  | "workflow-permissions-read"
  | "action-sha-pin";

const AUTO_FIX_KINDS = new Set<AutoFixKind>([
  "gitignore-add",
  "additive-security-header",
  "csp-report-only",
  "sca-in-range-bump",
  "rate-limit-standard-headers",
  "jwt-algorithms-constraint",
  "npmrc-ignore-scripts",
  "workflow-permissions-read",
  "action-sha-pin",
]);

/** The banner secret-related auto-fixes MUST carry (spec §8.3). Non-negotiable. */
export const GITIGNORE_BANNER =
  "Note: adding to .gitignore + `git rm --cached` only prevents FUTURE commits. " +
  "A secret already in your history is still exposed — rotate it now. That's step zero.";

export interface CommandRunner {
  (cmd: string, args: string[], cwd: string): { stdout: string; code: number };
}

export interface AutoApplyContext {
  projectRoot: string;
  /** Injected git/npm runner — defaults to a no-op in this pure-by-default build. */
  runner?: CommandRunner;
  /** For action-sha-pin: did CI pass in the last 7 days? Gate per spec §8.3. */
  ciPassedRecently?: boolean;
  /** For sca-in-range-bump churn rollback: the lockfile diff line count. */
  lockfileChurnLines?: number;
}

export interface AutoApplyResult {
  /** Whether the fix was applied. False when blocked / out of allowlist. */
  applied: boolean;
  kind: AutoFixKind | null;
  /** What changed, or why it didn't. */
  detail: string;
  /** The mandatory banner for secret-adjacent fixes (gitignore). */
  banner?: string;
  /** True when an attempted auto bump rolled back to stage due to churn. */
  rolledBackToStage?: boolean;
}

/** True iff this kind is in the auto allowlist. Anything else is stage/inline. */
export function isAutoApplyable(kind: string): kind is AutoFixKind {
  return AUTO_FIX_KINDS.has(kind as AutoFixKind);
}

/**
 * The guard `--auto` runs before touching anything: a finding is auto-eligible
 * ONLY when it's non-destructive AND its fix maps to an allowlisted kind. This
 * is the single chokepoint — destructive findings can never reach auto-apply.
 */
export function canAutoApply(finding: Finding, kind: string): boolean {
  if (isDestructive(finding)) return false;
  if (finding.fix_class !== "auto") return false;
  return isAutoApplyable(kind);
}

/**
 * Add entries to .gitignore (creating it if absent), run `git rm --cached` for
 * already-tracked matches, and ALWAYS return the future-commits banner.
 * Idempotent — entries already present are not duplicated.
 */
export function applyGitignoreAdd(
  ctx: AutoApplyContext,
  entries: readonly string[],
): AutoApplyResult {
  const file = path.join(ctx.projectRoot, ".gitignore");
  const existing = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines = new Set(
    existing.split("\n").map((l) => l.trim()).filter(Boolean),
  );
  const toAdd = entries.filter((e) => !lines.has(e.trim()));

  if (toAdd.length > 0) {
    const block =
      (existing.endsWith("\n") || existing === "" ? "" : "\n") +
      "\n# Added by vibe-sec — keep secrets out of version control\n" +
      toAdd.join("\n") +
      "\n";
    fs.appendFileSync(file, block, "utf8");
  }

  // git rm --cached for already-tracked matches (only when a runner is wired).
  if (ctx.runner) {
    for (const entry of toAdd) {
      ctx.runner("git", ["rm", "--cached", "-r", "--ignore-unmatch", entry], ctx.projectRoot);
    }
  }

  return {
    applied: toAdd.length > 0,
    kind: "gitignore-add",
    detail:
      toAdd.length > 0
        ? `added ${toAdd.length} entr${toAdd.length === 1 ? "y" : "ies"} to .gitignore: ${toAdd.join(", ")}`
        : "all entries already in .gitignore — nothing to add",
    banner: GITIGNORE_BANNER,
  };
}

/**
 * Decide whether an in-range SCA bump may auto-apply or must roll back to stage.
 * The churn rollback (spec §8.3, Decision 20): a fix churning >50 lockfile lines
 * re-stages instead of auto-applying — a quiet 50-line transitive cascade is
 * exactly where an "auto" patch bump bites.
 */
export function scaBumpDecision(
  ctx: AutoApplyContext,
): AutoApplyResult {
  const churn = ctx.lockfileChurnLines ?? 0;
  if (churn > LOCKFILE_CHURN_LIMIT) {
    return {
      applied: false,
      kind: "sca-in-range-bump",
      rolledBackToStage: true,
      detail: `lockfile churn ${churn} lines > ${LOCKFILE_CHURN_LIMIT} — re-staged for review instead of auto-applying`,
    };
  }
  return {
    applied: true,
    kind: "sca-in-range-bump",
    rolledBackToStage: false,
    detail: `in-range bump with ${churn} lines of lockfile churn (≤${LOCKFILE_CHURN_LIMIT}) — auto-applied`,
  };
}

/**
 * SHA-pin a GitHub Action — allowed only when CI passed in the last 7 days
 * (spec §8.3). Without that signal, pinning to a SHA could pin a broken ref.
 */
export function actionShaPinDecision(ctx: AutoApplyContext): AutoApplyResult {
  if (!ctx.ciPassedRecently) {
    return {
      applied: false,
      kind: "action-sha-pin",
      detail:
        "no green CI run in the last 7 days — SHA-pin staged, not auto-applied (pinning a broken ref is worse than an unpinned tag)",
    };
  }
  return {
    applied: true,
    kind: "action-sha-pin",
    detail: "CI green in the last 7 days — SHA-pin auto-applied",
  };
}
