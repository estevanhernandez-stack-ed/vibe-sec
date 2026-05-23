# Vibe Sec Plugin — Changelog

Plugin releases. The CLI has its own changelog at `../vibe-sec-cli/CHANGELOG.md`.
Tag convention: `vibe-sec-vX.Y.Z`.

## [0.3.0] — 2026-05-23 — Phase 2: signal-independent detectors

The four signal-independent detectors land, and `/vibe-sec:scan` + `/vibe-sec:deps` become real commands. Each detector follows the orchestration-layer contract: defer to the tool of record when present, in-house TypeScript baseline when absent.

- **Secrets — full stack.** Layer B entropy (Shannon ≥4.5 base64 / ≥3.0 hex), Layer C AST (`@babel/parser`), full git-history scan (full first run, incremental cache), ~40 provider patterns, `--verify` deferring to trufflehog.
- **Dependency CVE.** OSV-Scanner deferral + `npm audit` confirmer, dedup by CVE/GHSA, app-vs-lib `--omit=dev`, major-bump routing to Inline, lockfile-churn rollback.
- **Supply-chain.** Lockfile integrity + pinning, GitHub Actions ref-style + permissions parse, typosquat (Levenshtein ≤2), dep-confusion, postinstall inspection, SBOM detection-only.
- **Config posture.** Security headers (Next/Vite/Express/vercel/_headers/nginx), CORS (origin-reflection-with-credentials = Critical), cookie flags, Firebase `if true` rules, the CVE-2025-29927 baked-in rule.
- `/vibe-sec:scan` runs the full secret stack; `/vibe-sec:deps` runs fast SCA + the supply-chain subset. Both write `findings.jsonl`.

147 tests green. Canary / early-access.

## [0.2.0] — 2026-05-23 — Phase 1: foundation + orchestration pivot

First real plugin release. Repositioned from "another scanner" to the tier-aware audit + orchestration layer — defer to the free scanners when present, in-house baseline when absent.

- Scoring substrate: ASVS-mapped tier classifier, weighted score, severity amplifier.
- `findings.jsonl` schema + state I/O; Vibe Test composition handshake.
- 9-command scaffold; `/vibe-sec` router; `/vibe-sec:scan` Layer A with gitleaks deferral.
- CLI secret scanner promoted into TypeScript.

72 tests green. Canary / early-access; stable pin held until the command surface is complete.
