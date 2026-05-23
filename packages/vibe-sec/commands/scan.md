---
description: Fast secret scan — defers to gitleaks/trufflehog, in-house Layer A fallback
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/scan/SKILL.md` and follow its flow.

`/vibe-sec:scan` is the fast-path affordance: secret detection over the working tree.
It detects the tool of record (gitleaks, then trufflehog) and defers to it when present,
falling back to the in-house Layer A regex baseline when absent. Findings are
re-classified, masked, and written to `.vibe-sec/state/findings.jsonl` regardless of source.
