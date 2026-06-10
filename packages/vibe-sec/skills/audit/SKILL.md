---
name: audit
description: >
  Full tier-calibrated security audit across all ten concerns. Use when the user
  says "/vibe-sec:audit", "full security audit", "audit my app", "run a complete
  security check", "what security gaps do I have". Classifies the project tier,
  runs the in-scope concern detectors (deferring to external tools when present),
  collects findings.jsonl, and renders the four-band report across all three
  channels — markdown report, terminal banner, and the findings.jsonl sidecar.
---

# Vibe Sec — audit

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first for the shared
positioning, the tier→ASVS table, the amplifier rule, and the safety line.

`/vibe-sec:audit` is the full orchestrator — agent-heavy orchestration over the
deterministic TypeScript detectors. Lead with the verdict, then the bands.

## The flow

1. **Classify the tier (handshake-aware scan).** Read the Vibe Test handshake
   (`.vibe-test/state/covered-surfaces.json`, artifact schema v1 — Vibe Test
   owns the schema). **Always print the handshake status line in the banner,
   ok or degraded — `handshakeStatusLine()` from `composition/vibe-test.ts`
   renders it.** A missing handshake line in audit output is a bug, not a
   style choice; silent fallback is the defect GAP-07 existed to kill.
   - Fresh + schema v1: coverage data is the live signal — routes with
     `coverage_level: "none"` ELEVATE admin-endpoint + IDOR scanning;
     behavioral/edge-tested routes de-prioritize re-audit. Artifact v1
     carries no tier, so the tier is **always self-classified today** — say
     so in the banner. (Tier inheritance activates with the core-owned v2
     contract; a security signal promoting above an inherited tier will emit
     a `tier_drift_note`.)
   - Absent / stale / corrupt / unsupported-schema: self-classify via the
     repo signals and print the degraded line with the reason. Never fail;
     degrade loudly.

2. **Run every in-scope concern detector for the tier.** The scope grid is the
   gate: `skip` concerns are excluded from the score denominator entirely (tier
   is a scope gate, not just a severity dial). Per concern, detect the tool of
   record — defer to it when present (gitleaks, OSV-Scanner, Semgrep CE, …),
   fall back to the in-house baseline when absent, credit whichever ran.

   The ten concerns: secrets, dependency-cve, supply-chain, config-posture,
   crypto-pii, auth-model, owasp-survey, rate-limiting, tier-thresholds (the
   math substrate, always on), threat-model. **Threat-model is the sink node:**
   consult `threatModelInAudit(tier)` before running it. At Prototype and
   Internal it returns false (Conflict 2 = C — opt-in only); NOT auto-included in
   `:audit`. Point the user at `/vibe-sec:threat-model` if they want it at
   Internal. From Public-facing up it returns true and runs last, after every
   other concern (the sink node is never parallelized).

3. **Collect findings.jsonl.** Each detector's output maps through the
   `to-findings` mappers into the single `Finding` schema, deduped by id, and
   appends to `.vibe-sec/state/findings.jsonl`. One finding owns exactly one
   `primary_concern` (the deepest-domain owner); cross-references go to
   `secondary_concerns[]`. The weighted-score reader dedupes by id, so the same
   finding counts once even when several concerns tag it.

4. **Compute the weighted score** with the severity amplifier applied
   (Critical → 0.5 cap, High → 0.8 cap per concern). Skipped concerns are out of
   the denominator. Write `audit.json` (tier, score, gate verdict, counts,
   tools used).

5. **Render the four-band report across all three channels:**
   - **Markdown** → `docs/vibe-sec/audit-report.md` — runbook-grade, four-band,
     plus the OWASP-category-grouped subsection (one finding rendered under each
     applicable category with an "also tagged as…" annotation — it's one finding
     wearing all its tags, counted once). The authorization matrix renders via
     the existing `renderMatrixMarkdown()`.
   - **Terminal banner** → in-chat ANSI. Verdict, Band-1 action items, the
     abbreviated authz matrix (the gaps), Band-4 leads.
   - **findings.jsonl** → the append-only machine-readable + cross-plugin sidecar.

## The four bands (spec §7)

1. **Critical / High — action needed now.** In-scope, gate-relevant.
2. **Tier-appropriate but worth reading** — the education surface; where the
   OWASP 2021 → 2025 reclassifications get named.
3. **Tier-inappropriate but if you graduate** — forward-looking next-tier story
   (the concerns that come into scope one tier up).
4. **Pattern #13 complements** — tools that catch classes the baseline misses,
   led by detected context: Socket for SCA, Arcjet for LLM routes, Semgrep for
   injection. Don't re-recommend a tool that already ran.

The bands respect builder fatigue: surface critical-now without burying it under
tier-inappropriate noise. The denominator excludes skipped concerns — don't
report a Prototype app as failing on Customer-facing concerns it never opted into.

## Running it

The detection + report assembly is built TypeScript (`src/report/`, `src/fix/`,
`src/detectors/`). Orchestrate over those entry points — `buildBandedReport`,
`renderMarkdownReport`, `renderBanner`, `appendFindings`, `writeAuditState`. Do
not hand-fabricate findings; run the detectors and map their real output.

## Emitting docs/SECURITY.md

`/vibe-sec:audit --security-md` (or when the user asks for a security policy)
emits a builder-sustainable `docs/SECURITY.md` via `emitSecurityMd` — the
ASVS-cited verification target, current posture from the findings, graduating
guidance for the next tier, the locked threat-model Mermaid convention, and the
Pattern #13 complements (including honeytokens surfaced as a recommendation, not
a generated artifact). Emit-only for v0.2 — re-running regenerates; the builder
edits freely. Cite ASVS in the copy: "regulated tier" resolves to ASVS L3 + NIST
SSDF + SBOM, not aspiration.

## What to tell the user

Lead with the tier + the verdict: "Classified <tier> (<ASVS floor>). Weighted
score N% vs the M% bar — PASS/FAIL." Then the Band-1 count and the worst item.
Name which tools ran (in-house vs deferred). If threat-model was skipped at
Internal, say it's opt-in via `/vibe-sec:threat-model`. Point at
`/vibe-sec:fix` for remediation and `/vibe-sec:gate` for CI.
