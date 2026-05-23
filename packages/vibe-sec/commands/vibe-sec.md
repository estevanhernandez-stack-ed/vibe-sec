---
description: Vibe Sec router — state-aware next-step for your security posture
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/vibe-sec/SKILL.md` and follow its full flow.

The router reads `.vibe-sec/state/audit.json` freshness and recommends the next move:
- no audit yet → suggest `/vibe-sec:audit`
- stale audit (>24h) → suggest a re-run
- fresh + clean → suggest `/vibe-sec:posture`

It frames Vibe Sec as the orchestration layer — it defers to the tools you already
have installed and adds the tier-aware classification, severity, report, and fix
intelligence on top.
