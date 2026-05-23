---
name: research
description: >
  Re-run one concern's domain research to refresh the living briefs. Use when
  the user says "/vibe-sec:research", "refresh the security research", "update
  the secret-detection brief", "re-run research for <concern>", "the threat
  landscape changed". Re-runs a single concern's domain-research agent,
  regenerates its brief under docs/research/, and triggers a synthesis re-gen.
---

# Vibe Sec — research

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:research --concern <name>` re-runs one concern's domain-research agent
and updates `docs/research/<concern>.md`. The briefs are living docs — the
security landscape shifts (new CVE classes, new attack patterns, new tooling),
and a concern's detection logic is only as good as the brief behind it.

Cadence is friction-log-driven — no hard schedule. When the friction log shows a
concern's FP rate drifting or a detection gap recurring, that's the signal to
re-run its research.

Valid concerns: dependency-cve, secret-detection, owasp-survey, crypto-pii,
config-posture, supply-chain, rate-limiting, auth-model, threat-model,
tier-thresholds.

## Phase 1 status

Not yet built. The research re-run agent lands in Phase 4. The briefs it would
refresh already exist under `docs/research/`. Say so plainly if invoked now.
