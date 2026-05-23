---
name: gate
description: >
  CI pass/fail vs the project tier. Use when the user says "/vibe-sec:gate",
  "gate my CI", "should this pass the security gate", "block the build if
  insecure", "CI security check". Computes the weighted score, applies the tier
  threshold and mandatory-concern hard rules, and exits 0 (pass) / 1 (fail) /
  2 (scanner error). Emits GitHub Actions annotations when GITHUB_ACTIONS=true.
---

# Vibe Sec — gate

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:gate` is the CI-safe gate. It computes the weighted score, applies the
tier threshold (30/55/70/80/90), and enforces the mandatory-concern hard rules:
no High/Critical in the tier's mandatory concerns. At Regulated, no High anywhere
except the advisory threat-model concern.

Exit codes: `0` pass / `1` fail / `2` scanner error. When `GITHUB_ACTIONS=true`,
emits `::error::` / `::warning::` annotations so findings surface in the PR.

## Phase 1 status

The gate **math substrate** (`evaluateGate` in the scoring module) is built and
tested in Phase 1. The CI-runner SKILL wiring + GitHub Actions annotation
rendering land in Phase 3 alongside the full audit orchestration. The deterministic
pass/fail logic is ready; the command surface that drives it is in progress.
