---
name: audit
description: >
  Full tier-calibrated security audit across all ten concerns. Use when the user
  says "/vibe-sec:audit", "full security audit", "audit my app", "run a complete
  security check", "what security gaps do I have". Classifies the project tier,
  runs the in-scope concerns (deferring to external tools when present), and
  renders the four-band report. Phase 1 ships the foundation; full ten-concern
  orchestration lands in subsequent phases.
---

# Vibe Sec — audit

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:audit` is the full orchestrator. The flow:

1. Read the Vibe Test handshake (`.vibe-test/state/covered-surfaces.json`) and
   classify the tier — inherit when fresh, self-scan otherwise.
2. Run each in-scope concern at the current tier (skip concerns are excluded
   from the score denominator). Defer to the tool of record per concern.
3. Compute the weighted score with the severity amplifier applied.
4. Render the four-band report: critical-now / tier-appropriate-education /
   graduating-guidance / Pattern #13 complements. Write findings.jsonl + audit.json.

## Phase 1 status

The scoring substrate, classifier, state I/O, and the secret-detection concern
are built. The remaining nine concerns and the four-band report renderer land in
Phases 2-4. For now, `/vibe-sec:audit` can classify the tier and run the secret
scan; tell the user plainly that the full ten-concern orchestration is in
progress rather than fabricating findings for unbuilt concerns.
