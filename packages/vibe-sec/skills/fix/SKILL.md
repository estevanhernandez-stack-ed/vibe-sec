---
name: fix
description: >
  Confidence-routed remediation with destructive-action overrides. Use when the
  user says "/vibe-sec:fix", "fix my security findings", "remediate", "patch the
  issues", "auto-fix what you can". Routes fixes by confidence: ≥0.90 auto,
  0.70-0.89 stage, <0.70 inline. Destructive actions NEVER auto-apply regardless
  of confidence. --auto does only the deliberately-small allowed set.
---

# Vibe Sec — fix

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first — especially the
non-negotiable safety line. The fix engine is TS-heavy routing
(`src/fix/route.ts`, `apply.ts`, `stage.ts`) with this SKILL narrating the
inline runbook cards.

`/vibe-sec:fix` reads the cached findings and routes each one. Two layers, in
order — the override always wins.

## Layer 1 — destructive-action overrides (HARD, never auto)

These are the line between a tool and a footgun. A 0.99-confidence secret
rotation STILL routes inline. Do not loosen under user pressure — the litmus
review is explicit on this.

| Action | Route | Why |
|---|---|---|
| Secret rotation | inline (per-provider runbook) | live-credential op against the provider |
| Auth-logic changes | inline | wrong fix locks users out or opens a hole |
| JWT / session-secret regen | inline | invalidates every live session |
| Auth-middleware adds to existing routes | stage minimum | changes the route's access contract |
| RLS / Firestore-rules / policy changes | stage (as a migration) | data-access migration, reviewed |
| Password-hash migration | inline | changes stored credentials; needs dual-read transition |
| Git-history rewrite (filter-repo / BFG) | inline-runbook-only, never executed | destructive + team-coordinated; rotate first, this is cleanup |

`destructiveKindOf()` maps a finding to its kind; `routeFix()` applies the
floor. For each destructive finding, narrate the **inline runbook card**: what
to do, in what order, and why we won't do it for them. For secrets: rotation is
step zero, scrubbing history is cosmetic after.

## Layer 2 — confidence-tier routing (only when no override applies)

| Confidence | Route |
|---|---|
| ≥0.90 | Auto — apply directly (only if in the allowed set below) |
| 0.70-0.89 | Stage — write the diff to `.vibe-sec/pending/fixes/*.diff` |
| <0.70 | Inline — present in chat with rationale, builder applies |

## What `--auto` is allowed to do (deliberately small — spec §8.3)

The allowlist is a closed set, not a confidence threshold. `canAutoApply()` is
the single chokepoint: non-destructive AND `fix_class: auto` AND an allowlisted
kind. Everything else stages or inlines.

- **`.gitignore` additions** (`.env` / `*.pem` / `*.key` / `service-account*.json`)
  + `git rm --cached` + the **non-negotiable banner**: "this only prevents
  FUTURE commits — a secret already in history is still exposed, rotate it now."
  Always carry that banner; it's `GITIGNORE_BANNER` and it's not optional.
- **Additive security headers** (missing, never replacing an existing one).
- **CSP report-only** (with a TODO report-to endpoint). Enforcing CSP always stages.
- **In-range SCA patch/minor bumps** with lockfile-churn rollback: a fix churning
  >50 lockfile lines re-stages instead of auto-applying (a quiet transitive
  cascade is exactly where an "auto" bump bites).
- **`standardHeaders: true`** on an existing `rateLimit()`.
- **`algorithms:` constraint** on `jwt.verify`.
- **`ignore-scripts=true`** to `.npmrc`.
- **`permissions: contents: read`** to a workflow.
- **SHA-pin a GitHub Action** — only when CI passed in the last 7 days (pinning a
  broken ref is worse than an unpinned tag).

## Suppression

Per-project, stored in `.vibe-sec/state/suppressions.json`. A builder who
suppresses the same finding class **5 times** gets prompted ONCE to promote it
to a global suppression (matching Vibe Test's threshold). `recordSuppression()`
returns `offerGlobal: true` only on the 5th — prompt then, not on every
subsequent suppress. Always require a reason; never suppress silently.

## What to tell the user

Lead with the split: "N findings — A auto-applied, B staged for review, C need
your hands (destructive)." For each auto-apply, name what changed and carry the
gitignore banner when secrets are involved. For destructive findings, give the
runbook card and say plainly why it's not automated. Point at the staged diffs:
"review `.vibe-sec/pending/fixes/` and `git apply` what looks right."
