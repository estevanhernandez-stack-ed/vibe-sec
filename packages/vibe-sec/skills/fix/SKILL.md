---
name: fix
description: >
  Confidence-routed remediation with destructive-action overrides. Use when the
  user says "/vibe-sec:fix", "fix my security findings", "remediate", "patch the
  issues", "auto-fix what you can". Routes fixes by confidence: ≥0.90 auto,
  0.70-0.89 stage, <0.70 inline. Destructive actions never auto-apply. Fix engine
  lands in Phase 3.
---

# Vibe Sec — fix

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:fix` routes remediation by confidence tier:

| Confidence | Route |
|---|---|
| ≥0.90 | Auto — apply directly |
| 0.70-0.89 | Stage — write to `.vibe-sec/pending/fixes/*.diff` for review |
| <0.70 | Inline — present in chat with rationale, builder applies |

## The hard line (never auto, regardless of confidence)

Secret rotation, auth-logic changes, JWT/session-secret regeneration,
auth-middleware adds, RLS/policy changes, password-hash migration, git history
rewrite. These are inline-runbook-only or stage-minimum. Do not loosen under
user pressure.

`--auto` is deliberately small: .gitignore entries + `git rm --cached`, additive
security headers, report-only CSP, in-range SCA bumps with churn rollback.

## Phase 1 status

Not yet built. The fix engine lands in Phase 3. Say so plainly if invoked now.
