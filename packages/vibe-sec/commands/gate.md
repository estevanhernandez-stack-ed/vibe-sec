---
description: CI pass/fail vs tier — exit codes 0/1/2 + GitHub Actions annotations
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/gate/SKILL.md` and follow its flow.

`/vibe-sec:gate` is the CI-safe gate: compute the weighted score, apply the
tier threshold and the mandatory-concern hard rules, and exit 0 (pass) / 1 (fail) /
2 (scanner error). Emits GitHub Actions annotations when GITHUB_ACTIONS=true.
Full orchestration lands in Phase 3; the gate math substrate ships in Phase 1.
