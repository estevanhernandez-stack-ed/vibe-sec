---
name: research
description: >
  Re-run one concern's domain research to refresh the living briefs. Use when
  the user says "/vibe-sec:research", "refresh the security research", "update
  the secret-detection brief", "re-run research for <concern>", "the threat
  landscape changed". Re-runs a single concern's domain-research agent,
  regenerates its brief under docs/research/, and notes that synthesis should be
  re-derived.
---

# Vibe Sec — research

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:research --concern <name>` re-runs one concern's domain-research agent
and regenerates `docs/research/<brief>.md`. The briefs are living docs — the
security landscape shifts (new CVE classes, new attack patterns, new tooling, new
methodology revisions) and a concern's detection logic is only as good as the
brief behind it.

This is the agent-dispatch command — SKILL-heavy by design. It does NOT change
detector code; it refreshes the research a future build pass would read.

## The flow

1. **Resolve the concern.** Require `--concern <name>`. Valid concerns and the
   brief each maps to:

   | `--concern` | Brief file under `docs/research/` |
   |---|---|
   | `dependency-cve` | `dependency-cve-sca.md` |
   | `secret-detection` | `secret-detection.md` |
   | `owasp-survey` | `owasp-top-10-survey.md` |
   | `crypto-pii` | `crypto-pii-handling.md` |
   | `config-posture` | `config-posture.md` |
   | `supply-chain` | `supply-chain-hardening.md` |
   | `rate-limiting` | `rate-limiting-abuse-protection.md` |
   | `auth-model` | `auth-model-static-analysis.md` |
   | `threat-model` | `threat-model-generation.md` |
   | `tier-thresholds` | `security-tier-thresholds.md` |

   No `--concern`, or an unknown name → list the valid concerns and stop. Don't
   guess which brief to regenerate.

2. **Read the existing brief.** It is the prior state — preserve its structure
   (Framing → Landscape → mechanics → FP risks → remediation → Pattern #13 →
   tier applicability → cross-concern deps → sources). The re-run UPDATES, it
   doesn't reinvent. Note the brief's "Authored" / last-run date.

3. **Dispatch the domain-research agent.** Re-run the concern's domain research:
   web search + the canonical sources already cited in the brief (OWASP, Snyk,
   NIST, the tool changelogs). Seed the agent with the existing sources so quality
   doesn't regress — the litmus review flagged research-swarm brief quality as
   load-bearing. Look specifically for:
   - new tools that change the Pattern #13 landscape,
   - methodology/standard changes (e.g. STRIDE/LINDDUN revisions, OWASP list
     reshuffles, ASVS version bumps),
   - new CVE/attack-pattern classes the detector should learn.

4. **Regenerate the brief.** Write the refreshed `docs/research/<brief>.md`
   in place, keeping the section structure and updating the "Authored" line to
   the re-run date. Preserve the sources list; add new ones.

5. **Note that synthesis should be re-derived.** The per-concern briefs feed
   `docs/research/synthesis.md`, which is the implementation source of truth. A
   re-run of one concern doesn't auto-rewrite synthesis — tell the user the
   synthesis section for this concern may now be stale and that a `/spec`-style
   re-synthesis is the next step if the brief moved materially.

## Cadence (Conflict 8 = A)

Friction-log-driven, no hard schedule. The signal to re-run a concern's research:
its FP rate drifting in the friction log, or a detection gap recurring. Pattern
#14 already provides that signal. (Per-concern scheduled cadence is a v0.3
upgrade if the friction log warrants it.)

## What to tell the user

Lead with what changed: "Re-ran <concern> research — N new sources, the notable
shift is X." If nothing material moved, say so plainly — an honest "the landscape
is stable since the last run" beats padding the brief. Then point at the updated
brief path and flag whether synthesis needs a re-derive.
