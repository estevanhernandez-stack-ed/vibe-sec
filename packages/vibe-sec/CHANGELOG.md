# Vibe Sec Plugin — Changelog

Plugin releases. The CLI has its own changelog at `../vibe-sec-cli/CHANGELOG.md`.
Tag convention: `vibe-sec-vX.Y.Z`.

## [0.6.0] — 2026-05-23 — Tier calibration (data-sensitivity promotion)

The tier classifier now weights data-sensitivity per spec §2.3. An app that is deployed AND stores real user PII AND has admin roles (or multi-tenancy) promotes to `customer-facing-saas` — three *distinct* signal dimensions required, which is the over-promotion guard (a bare prototype, internal tool, or public marketing site stays put). A `tier_drift_note` logs the promotion when security signals lift the tier above the deploy-detected baseline.

Validated on WeSeeYouAtTheMovies: reclassified public-facing → customer-facing-saas, crypto-pii correctly became gate-mandatory at the L3 (80%) bar, the unauthenticated-Gemini-endpoint catch held, no auth FP regression, zero crashes. 347 tests green.

Known follow-up (v0.7): the self-scan signal-gathering on the fallback path is currently SKILL-guided (agent-interpreted); the inherit-from-Vibe-Test path is deterministic. Hardening the self-scan gather to deterministic TS is scoped next.

## [0.5.1] — 2026-05-23 — Dogfood fixes (real-app validation)

Fixes from the WeSeeYouAtTheMovies acceptance run. FP rate dropped from ~16-25% (concentrated in auth-model, the signature concern) to near-zero, real catches retained, zero crashes across 184 real files.

- **auth-model:** recognize Firebase auth patterns (`verifyIdToken`/`verifyAuthToken`/`checkAdminRole` + Bearer extraction); scope auth to the handler block (not the whole file) so genuinely-unprotected handlers stay flagged while inline-protected ones clear; widen the Express detection window.
- **secrets:** Firebase web API keys (`AIza…`, public by design) are informational + single-tagged — server keys + service-account keys stay high/critical.
- **deps:** surface a coverage advisory when the CVE scan is a no-op (no osv-scanner / network) — an unchecked concern no longer reads as clean.
- **state:** path-normalize + de-dupe findings across multiple package roots (monorepo walk).

339 tests green (315 + 24 regression).

## [0.5.0] — 2026-05-23 — Phase 4: threat-model sink + research + SECURITY.md (full surface)

The synthesis sink and the last commands land. All nine commands are now real over the ten-concern stack.

- **Threat-model synthesis (the sink).** STRIDE + DREAD + LINDDUN (Customer-facing+) + attack-trees, consuming all nine other concerns + Vibe Test covered-surfaces. Mermaid DFD (locked shape convention) + Threat-Dragon-v2.5.0-compatible JSON sidecar. Inventory-completeness banner when route coverage <90%. Internal-tier opt-in (not auto-included in `:audit`).
- **`/vibe-sec:research`** — re-run one concern's domain research (living docs), `--concern <name>`.
- **`SECURITY.md` generation** — ASVS-cited graduating guidance; honeytokens surfaced as a Pattern #13 recommendation (emit-only, no token values).

315 tests green. Canary / early-access; real-app dogfood + stable promotion next.

## [0.4.0] — 2026-05-23 — Phase 3: structural detectors + audit orchestration

The four structural detectors land and the orchestration commands wire all ten concerns into a real audit. `/vibe-sec:audit`, `:gate`, `:posture`, and `:fix` go live.

- **Crypto / PII.** Deprecated-primitive call sites, bcrypt-cost / Argon2 checks, JWT-algorithm audit (`none`/short-secret = Critical), PII schema inventory + in-logs scan, client-side key leakage.
- **Auth model (the signature concern).** Six probes — route inventory, admin gating, tenant-isolation (the Supabase-without-RLS finding), IDOR (gated to Public-facing+ at ≥0.9 confidence), session classification, role-hardcoding — plus the authorization matrix artifact (routes × {auth-required, role-gated, ownership-enforced, RLS-applicable}).
- **OWASP survey.** Dual 2021/2025 tagging on every finding, shallow SSRF, dynamic-code sinks (review-required, never auto).
- **Rate limiting.** Middleware + LLM-endpoint detection; unauthenticated LLM-backed endpoint = Critical at every tier.
- **`/vibe-sec:audit`** runs every in-scope concern into a four-band report across markdown + banner + findings.jsonl. **`:gate`** is CI-safe (exit 0/1/2 + GitHub Actions annotations). **`:fix`** routes by confidence with destructive-action overrides (secret rotation, auth-logic, JWT/session regen, auth-middleware adds, RLS/policy changes never auto). **`:posture`** reads cached state without re-scanning.
- Fixed a gate-scoping bug: config-posture was silently dropped from the Public-facing mandatory set (the SCOPE_GRID `mandatory`/`full` labels are about denominator scope, not gate-blocking). Spec §2.4's hard-gate table is now encoded directly.

290 tests green. Canary / early-access.

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
