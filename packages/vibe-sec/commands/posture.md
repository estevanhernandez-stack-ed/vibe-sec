---
description: Read-only tier-aware summary from cached state — no re-scan
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/posture/SKILL.md` and follow its flow.

`/vibe-sec:posture` reads `.vibe-sec/state/audit.json` + `findings.jsonl` and renders
the current tier, score, and outstanding findings without re-scanning. The cheap
"where do I stand" read. Lands fully in Phase 3.
