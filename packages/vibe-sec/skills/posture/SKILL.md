---
name: posture
description: >
  Read-only tier-aware summary from cached state. Use when the user says
  "/vibe-sec:posture", "what's my security posture", "where do I stand",
  "show my security status", "summarize my findings". Reads
  .vibe-sec/state/audit.json + findings.jsonl and renders the current tier,
  score, and outstanding findings without re-scanning.
---

# Vibe Sec — posture

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:posture` is the cheap "where do I stand" read. It reads cached state
(`.vibe-sec/state/audit.json` + `findings.jsonl`) and renders:

- the classified tier + confidence
- the weighted score vs the tier threshold
- outstanding findings grouped by severity, deduped by id
- gate pass/fail status

No re-scan. If the cached audit is stale (>24h), say so and point at
`/vibe-sec:audit` for a fresh read.

## Phase 1 status

The state readers (`readAuditState`, `readFindingsDeduped`, `isAuditFresh`) are
built and tested in Phase 1. The posture renderer SKILL wiring lands in Phase 3.
The data layer it reads from is ready.
