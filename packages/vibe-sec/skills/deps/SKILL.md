---
name: deps
description: >
  Fast dependency CVE + supply-chain subset check. Use when the user says
  "/vibe-sec:deps", "check my dependencies", "any vulnerable packages", "scan my
  lockfile", "are my deps safe", "dependency audit". Runs CVE detection plus
  lockfile-integrity and pinning checks; defers to OSV-Scanner/Trivy when
  present. Detector lands in Phase 2.
---

# Vibe Sec — deps

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:deps` is the fast SCA affordance: dependency CVEs plus the
lockfile-integrity and pinning subset of supply-chain hardening. It defers to
OSV-Scanner (primary) and confirms fix-availability with `npm audit`, deduping
by CVE/GHSA ID. Skips SBOM, typosquat round-trips, and threat-model — those
belong to the full audit.

## Phase 1 status

Not yet built. The dependency-CVE and supply-chain detectors land in Phase 2,
following the deferral contract established by `/vibe-sec:scan`. Say so plainly
if invoked now.
