---
description: Fast dependency + supply-chain check (CVE + lockfile + pinning)
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/deps/SKILL.md` and follow its flow.

`/vibe-sec:deps` is the fast SCA affordance: dependency CVEs plus the
lockfile-integrity and pinning subset of supply-chain hardening. It classifies
the project app-vs-lib (applications get `--omit=dev`), defers to OSV-Scanner
when present, confirms fix-availability with `npm audit`, and dedupes by
CVE/GHSA id. Floating pins (`latest` / `*`) are flagged. It deliberately skips
SBOM, typosquat round-trips, postinstall inspection, and threat-model — those
belong to `/vibe-sec:audit`. Findings are written to
`.vibe-sec/state/findings.jsonl`.
