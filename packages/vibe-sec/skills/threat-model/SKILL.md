---
name: threat-model
description: >
  STRIDE/DREAD threat-model synthesis. Use when the user says
  "/vibe-sec:threat-model", "generate a threat model", "STRIDE analysis",
  "what could go wrong with my app", "model the attack surface", "threat
  modeling". Consumes all other concerns' findings plus Vibe Test
  covered-surfaces and emits a STRIDE/DREAD model as Mermaid-in-markdown with a
  Threat-Dragon-compatible JSON sidecar. The synthesis sink node — runs last.
---

# Vibe Sec — threat-model

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:threat-model` is the synthesis sink node. It runs last, never
parallelized, consuming classification + all nine other concerns' outputs +
Vibe Test covered-surfaces. It emits:

- STRIDE (builder-facing) + DREAD (prioritization) + LINDDUN (Customer-facing+)
- Mermaid DFD in markdown → `docs/vibe-sec/threat-model.md`
- Threat-Dragon-compatible JSON → `.vibe-sec/state/threat-model.json`

Mermaid convention is locked: stadiums = external entities, rectangles =
processes, cylinders = data stores, hexagons = third-parties, subgraphs = trust
boundaries. Inventory-completeness check fires a banner when route coverage <90%.
Opt-in at Internal tier; not auto-included in `/vibe-sec:audit` there.

## Phase 1 status

Not yet built. The threat-model synthesis lands in Phase 4 — it depends on all
prior concerns. Say so plainly if invoked now.
