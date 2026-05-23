---
description: Fast dependency + supply-chain check (CVE + lockfile + pinning)
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/deps/SKILL.md` and follow its flow.

`/vibe-sec:deps` is the fast SCA affordance: dependency CVEs plus the lockfile-integrity
and pinning subset of supply-chain hardening. Defers to OSV-Scanner/Trivy when present.
Detector lands in Phase 2.
