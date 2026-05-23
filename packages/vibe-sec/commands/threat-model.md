---
description: STRIDE/DREAD threat-model synthesis — Mermaid + Threat Dragon JSON
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/threat-model/SKILL.md` and follow its flow.

`/vibe-sec:threat-model` is the synthesis sink node: it consumes all other concerns'
findings plus Vibe Test covered-surfaces and emits a STRIDE/DREAD threat model as
Mermaid-in-markdown with a Threat-Dragon-compatible JSON sidecar. Lands in Phase 4.
