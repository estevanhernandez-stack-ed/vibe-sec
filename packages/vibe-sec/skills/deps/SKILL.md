---
name: deps
description: >
  Fast dependency CVE + supply-chain subset check. Use when the user says
  "/vibe-sec:deps", "check my dependencies", "any vulnerable packages", "scan my
  lockfile", "are my deps safe", "dependency audit". Runs CVE detection plus
  lockfile-integrity and pinning classification; defers to OSV-Scanner when
  present, confirms with npm audit. The fast SCA affordance — skips SBOM,
  typosquat round-trips, and threat-model (those belong to /vibe-sec:audit).
---

# Vibe Sec — deps

Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md` first.

`/vibe-sec:deps` is the fast SCA affordance — `npm audit`-style muscle memory,
not the full audit. It runs the dependency-CVE concern plus the
lockfile-integrity + pinning subset of supply-chain hardening, and nothing else
(Decision 1: it's a UX split, not duplicated logic — `:audit` runs the full
orchestration over the same primitives).

## What it runs

**Dependency CVE (#1):**

1. **Classify app-vs-lib.** Application projects get `--omit=dev` (Decision 11)
   — dev-dep CVEs are ~30% of raw npm-audit noise and a vulnerable test runner
   that never ships isn't a runtime risk. Libraries keep the full prod tree.
2. **OSV first.** Defer to `osv-scanner` on PATH (the 2026 SCA primary — schema-
   mature, cross-ecosystem, no-account). Parse `--format json`.
3. **npm audit confirms.** OSV wins on "does this CVE exist"; npm audit wins on
   "is there a fix and is it breaking." Run both, **dedupe by CVE/GHSA id**
   (Decision 12) — one finding per vulnerability even when both report it.
4. **Fix routing via isSemVerMajor.** Patch/minor in range → Auto (with
   lockfile-churn rollback: a fix churning >50 lines re-stages, Decision 20).
   Minor needing a range bump → Stage. Semver-major → Inline. No fix → inform-only.

**Supply-chain subset (the fast slice of #6):**

5. **Lockfile integrity + pinning.** Lockfile present? Integrity hashes? Floating
   pins (`latest` / `*` / `x.y.x`) flagged — they drift the resolved version
   between installs.

## What it deliberately skips (that's `:audit`'s job)

- **SBOM detection/generation** — Regulated-tier supply-chain concern.
- **Typosquat round-trips** (Levenshtein vs the popular list) + dependency-
  confusion — full supply-chain pass.
- **GitHub Actions SHA-pinning + permissions** — full supply-chain pass.
- **Postinstall inspection** — full supply-chain pass.
- **Threat-model** — the sink node, `:audit` / `:threat-model` only.

Say so if a user asks why a typosquat or SBOM finding didn't surface here:
"`:deps` is the fast path — run `/vibe-sec:audit` for the full supply-chain pass."

## EPSS / KEV

The findings schema carries `epss_score` + `kev_listed` hooks, but they're
**not wired to scoring in v0.2** (Decision 13). Hook now, score later, no
migration needed.

## Output

- **Terminal banner** — CVE counts by severity, fix-availability summary, which
  scanner produced what (osv-scanner / npm-audit / both).
- **findings.jsonl** — append-only, one finding per deduped vulnerability, with
  `fix_class` set per the isSemVerMajor routing.

## What to tell the user

Lead with the count: N vulnerabilities, M with fixes available, K requiring a
major bump (those need your review). Name whether OSV ran (deferred) or npm
audit carried it alone. If a fix is a breaking change, never auto-apply it —
route to Inline and explain why.
