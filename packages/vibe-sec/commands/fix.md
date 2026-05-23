---
description: Confidence-routed remediation with destructive-action overrides
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/fix/SKILL.md` and follow its flow.

`/vibe-sec:fix` routes remediation by confidence: ≥0.90 auto, 0.70-0.89 stage,
<0.70 inline. Destructive actions (secret rotation, auth-logic changes, RLS edits,
history rewrites) never auto-apply regardless of confidence. Fix engine lands in Phase 3.
