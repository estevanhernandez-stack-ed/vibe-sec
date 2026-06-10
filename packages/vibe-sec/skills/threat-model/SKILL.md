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

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first for the positioning,
the tier→ASVS table, and the safety line.

`/vibe-sec:threat-model` is the synthesis sink node — pure synthesis, no
detection. It runs last, never parallelized, consuming the tier classification +
all eleven other concerns' findings + Vibe Test covered-surfaces. It does not
re-scan; it reads what the detectors already produced.

## The flow

1. **Classify the tier (inherit-or-scan).** Same as `:audit` — read the Vibe
   Test handshake when present + fresh, else self-classify. The tier drives which
   methodology overlays apply.

2. **Assemble the inventory.** Route inventory (auth-model #8 — the deepest
   input), PII fields (crypto-pii #4 — drives the data stores + the LINDDUN
   overlay), integrations (Vibe Test `detected_stack` + dependency fingerprints),
   and the deduped `findings.jsonl`. The TS entry point `runThreatModel` does this
   assembly over the real detectors — orchestrate over it, don't fabricate threats.

3. **Run the inventory-completeness check before synthesis.** If route coverage
   is below 90%, fire the banner: _"Inventory completeness: N% — threat model may
   be missing surfaces."_ Silent undergeneration is the failure mode to avoid at
   all costs — a model that looks complete but isn't is worse than an honest gap.

4. **Synthesize.** STRIDE-per-element (builder-facing) + DREAD (prioritization)
   over each trust boundary. The three canonical boundaries: external-user
   (always), admin/elevated-role (when the role matrix has >1 role),
   service-to-service (when integrations exist). Realized threats — backed by a
   real finding — reference it by id and score higher on DREAD. At Customer-facing+
   add the LINDDUN privacy overlay; at Public-facing+ add attack-trees for the
   top-3 (top-5 at Regulated).

5. **Emit both channels:**
   - **Primary:** Mermaid-in-markdown → `docs/vibe-sec/threat-model.md`.
   - **Sidecar:** Threat-Dragon-v2.5.0-compatible JSON →
     `.vibe-sec/state/threat-model.json` (one-click import into the GUI).

## Locked Mermaid convention

Do not drift the shapes — successive runs must produce diff-friendly diagrams:

- **stadiums** (`id(["label"])`) = external entities
- **rectangles** (`id["label"]`) = processes
- **cylinders** (`id[("label")]`) = data stores
- **hexagons** (`id{{"label"}}`) = third-parties
- **subgraphs** = trust boundaries

The convention is documented inline in the generated markdown and in the
`docs/SECURITY.md` template so it stays a contract.

## Tier applicability (Conflict 2 = C)

| Tier | Threat model |
|---|---|
| Prototype | **Stub** — "not recommended at this tier, re-run when you graduate." No synthesis, no JSON sidecar. |
| Internal | **Lightweight — OPT-IN ONLY.** Not auto-included in `/vibe-sec:audit`. Direct `/vibe-sec:threat-model` runs it. |
| Public-facing | **Full** STRIDE + DREAD + attack-trees-top-3. Auto-runs as part of `:audit`. |
| Customer-facing SaaS | **+ LINDDUN** privacy overlay + tenant boundary. |
| Regulated | **+ attack-trees-top-5 + pytm stub.** Hand to an external auditor as a starting point. |

The `:audit` orchestrator MUST consult `threatModelInAudit(tier)` before running
the sink node. At Internal it returns false — point the user at
`/vibe-sec:threat-model` if they want it there. A direct invocation always runs
(the user explicitly asked).

## FP target

"Threat relevance," not accuracy. Every enumerated threat is a real class in
principle — the question is whether it applies to _this app at this tier_.
Tier-appropriate filtering is the final pass: at Internal, drop Elevation threats
when there's no admin surface to escalate across. Target 12% on enumeration,
<5% on the top-10 prioritized (a fake threat in the top-10 is embarrassing).

## Defer to the GUI

Vibe Sec generates the initial model; OWASP Threat Dragon (GUI) and pytm
(threat-model-as-code) own ongoing maintenance. Surface them in Band 4 — the
sidecar exists so a builder who wants the GUI imports it and continues there.

## What to tell the user

Lead with the verdict: "Generated a <tier> threat model — N threats across the
STRIDE categories, top-K prioritized by DREAD." Name the completeness number if
it's below 90%. Point at `docs/vibe-sec/threat-model.md` for the Mermaid view and
the JSON sidecar for Threat Dragon. Threat-model output is advisory/inline —
fixes require architectural judgment, so the model documents the _why_ in
adversary terms and maps each threat to its remediation owner.
