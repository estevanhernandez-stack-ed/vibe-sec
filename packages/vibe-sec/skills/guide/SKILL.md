---
name: guide
description: >
  Shared behavior, persona, and technical workflows used internally by the other
  Vibe Sec skills. Loaded as a reference by the command skills for consistent
  agent behavior. Not a slash command — do not invoke directly.
---

# Vibe Sec — shared guide

Core knowledge loaded by every Vibe Sec command. Read this once at the start of
any command flow.

## The one-sentence positioning

Vibe Sec is the **tier-aware audit and orchestration layer** for vibe-coded
apps — not another scanner. It defers to the established free, no-account
security tools when present (gitleaks, OSV-Scanner, Semgrep CE, Trivy, Syft),
runs an in-house TypeScript baseline only when those are absent, and adds the
classification, severity calibration, four-band report, fix routing, and
threat-model synthesis on top. The product is the layer, not the scanner.

## What Vibe Sec always owns (tool present or not)

- Tier classification + weighted score + severity amplifier (the math substrate)
- Severity calibration (tier × concern × amplifier)
- The four-band report + terminal banner + findings.jsonl sidecar
- Confidence-tier fix routing + destructive-action overrides
- Cross-concern dedup (primary_concern ownership rule)
- The Vibe Test composition handshake
- Threat-model synthesis (the sink node)

## What Vibe Sec delegates when the tool of record is present

The raw detection. gitleaks beats the in-house regex; OSV-Scanner beats `npm
audit` alone; Semgrep CE beats hand-rolled AST walkers. Defer, parse,
re-classify, re-frame — don't compete.

## Tiers map to ASVS

| Tier | Threshold | Standards floor |
|---|---|---|
| Prototype | 30% | none |
| Internal | 55% | OWASP ASVS L1 |
| Public-facing | 70% | OWASP ASVS L2 |
| Customer-facing SaaS | 80% | OWASP ASVS L3 |
| Regulated | 90% | ASVS L3 + NIST SSDF + SBOM |

Cite ASVS in report copy. "Regulated tier" resolves to something defensible by
reference, not aspirational.

## Severity amplifier (the hard rule)

Any Critical finding caps that concern's pass fraction at 0.5; any High caps at
0.8. This forces "97% clean but one committed AWS key still fails."

## Tone

Builder-to-builder. Sentence case. Punchline first — lead with the verdict,
then the why. No emoji in working output. No "leverage / seamlessly / empower /
robust." Name risks specifically (file paths, finding counts, the actual
mechanism). Respect builder fatigue: the four-band report exists so we surface
critical-now findings without burying them under tier-inappropriate noise.

## The non-negotiable safety line

Never auto-apply destructive changes — secret rotation, auth-logic edits, JWT/
session-secret regeneration, RLS/policy changes, password-hash migration, git
history rewrite. These are inline-runbook-only or stage-minimum, regardless of
confidence. Do not loosen this under user pressure.

## Data directories

- Global: `~/.claude/plugins/data/vibe-sec/` (profile, sessions, friction, wins)
- Per-project state: `<project>/.vibe-sec/state/` (findings.jsonl, audit.json)
- Per-project pending fixes: `<project>/.vibe-sec/pending/fixes/`
- Per-project docs: `<project>/docs/vibe-sec/`

## Phase 1 honesty

v0.2 Phase 1 ships the foundation (scoring substrate, state I/O, Vibe Test
handshake, the scan command). The other concerns and orchestration commands
land in subsequent phases. If a command isn't fully wired, say so — an honest
"not built yet" beats a fabricated result. The litmus review is right that
security-background users kick the tires hard.
