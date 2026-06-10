# Vibe Sec Plugin — Changelog

Plugin releases. The CLI has its own changelog at `../vibe-sec-cli/CHANGELOG.md`.
Tag convention: `vibe-sec-vX.Y.Z`.

## [0.9.0] — 2026-06-09 — data-posture: concern #12 (GAP-09, static half)

The migration class nothing audited: Celestia3's PersistenceService lazily migrates real user data on read, 626Labs-1 runs an in-flight Firestore→Data-Connect migration — both hand-rolled, neither checked by anything. From the quality-net gap analysis, GAP-09; the runtime half (does a restore actually work, live shape correspondence) is explicitly reserved for vibe-ops.

- **feat(data-posture):** new detector family `src/detectors/data-posture/` — persistence applicability gate (dep table + file hints, with a firebase disambiguation: the SDK alone isn't persistence until rules files or firestore imports corroborate), backup-posture check across five discoverable surfaces (scripts, CI, script files, export-shaped scheduled functions, restore runbooks), and the migration-discipline lint (machinery, schema-version stamps, write-stamps, backfill/completion paths, gating, lazy-read co-location).
- **Conservative by design:** `lazy-migration-without-backfill` (MEDIUM) only fires when NO completion path exists anywhere — 626Labs-1's six lazy-shaped sites stay quiet because `migrateUserData()` exists. Backup *presence* is a score-neutral note, not a finding; the honesty cap ("config ≠ verified restore") rides the notes.
- **Not-applicable is a third state:** `audit.json` gains optional `not_applicable_concerns[]`; the gate drops those concerns from the denominator. No persistence ≠ a hollow pass.
- **Ground-truthed on the named patients:** Celestia3 → backup MEDIUM + no-schema-versioning LOW + lazy-without-backfill MEDIUM citing `PersistenceService.ts:58` **plus two real lazy migrations the spec didn't know about** (`GrimoireService.ts:54`, `UserProfileService.ts:85`, both hand-verified); 626Labs-1 → `migrationService.ts:33` completion path found verbatim, lazy finding correctly suppressed.
- Scope grid: prototype/internal skip, public-facing lightweight, customer-facing-saas/regulated full.

486 tests green (436 + 50 new). The audit is twelve concerns now.

## [0.8.0] — 2026-06-09 — license-compliance: concern #11 (GAP-26)

The Celestia3 GPL engine forced the question: a commercial app distributing an Android binary shipped a GPL-3.0 core dependency and nothing in the net asked. From the quality-net gap analysis (vibe-plugins `docs/quality-net-gap-analysis-2026-06-09.md`, GAP-26).

- **feat(license):** new detector family `src/detectors/license/` — SPDX expression parser (correct precedence, `WITH` exceptions, legacy `licenses` arrays; the dual-license OR-trap `(BSD-3-Clause OR GPL-2.0)` classifies permissive and must not flag), node_modules inventory (scoped packages, lockfile dev-flags, absent-tree advisory instead of false-clean), distribution-model detection (distributed-binary / saas / unknown), and the policy matrix keyed to it: strong copyleft in a conveyed binary is HIGH; AGPL user-reachable is HIGH; server-side GPL in SaaS is a MEDIUM document-your-position advisory; weak copyleft and missing-license batch LOW (don't cry wolf); devDependencies cap at INFO.
- **Scope grid:** prototype/internal skip, public-facing lightweight, customer-facing-saas/regulated full. **License findings are never gate-mandatory at any tier** — remediation is a business decision (purchase / swap / open / document); they weigh in the score, they don't hard-fail `:gate`.
- **Ground-truthed on real installed trees, not fixtures:** Celestia3 (1,370 packages, distributed-binary via Capacitor) → `swisseph-wasm@0.0.2 [GPL-3.0-or-later]` HIGH, the finding that motivated the concern; Project-626Labs-1 (1,533 packages, saas) → `node-forge [(BSD-3-Clause OR GPL-2.0)]` correctly NOT flagged.
- Known soft spot (named in the audit SKILL): pnpm strict layouts under-inventory transitives (top-level node_modules only) — v0.8.x widening. NuGet/.nuspec (the Sanduhr leg) is explicitly out of v1 scope.

436 tests green (352 + 84 new). The audit is eleven concerns now.

## [0.7.1] — 2026-06-09 — handshake repair: read what Vibe Test actually emits

GAP-07 of the quality-net gap analysis (vibe-plugins docs/quality-net-gap-analysis-2026-06-09.md). The Vibe Test handshake was false-green by construction: the reader consumed a shape (`classification.tier`, `covered_surfaces.endpoints_*`, `detected_stack`) that Vibe Test's published schema forbids (`additionalProperties: false`) and never emitted. A real artifact parsed, passed freshness, reported `ok` — and extracted zero data, silently, since the day both shipped.

- **fix(composition):** the reader now consumes artifact schema v1 verbatim (`surfaces[]` + `coverage_level`): routes at `none` elevate admin/IDOR scanning, behavioral/edge routes de-prioritize re-audit. `schema_version !== 1` (including the old imaginary shape) degrades loudly as `unsupported-schema` — a regression tripwire test pins this.
- **honesty:** artifact v1 carries no tier/modifiers/stack — `inheritedTier` is structurally null today; the classifier always self-scans and says so. Inheritance re-activates when the core-owned v2 contract adds a classification block (spec-bank: plugin-core-phase2).
- **feat(composition):** `handshakeStatusLine()` — the one-line ok/degraded status the audit banner must always print. Silent fallback is now a documented defect, in code and in the `:audit` SKILL.
- **tests:** composition suite rewritten against a fixture hand-synced to Vibe Test v0.2.5's real emitter output.
- **fix(tests):** the CLI exit-code parity suite had been red since the v0.7.0 tag — it still spawned the pre-0.7.0 `vibe-sec-cli/src/index.js`, deleted in the d69d7cb restructure (no pre-tag gate caught it; GAP-04's case in miniature). It now targets the standalone CLI's build, strips PATH in the spawned env so the comparison is deterministically in-house (no gitleaks variance), and skips loudly when the sibling isn't built. 352 tests green.

## [0.7.0] — 2026-06-09 — vibe-sec-cli full tier-aware audit

- **feat(cli):** `vibe-sec-cli` ships the full tier-aware audit — the standalone CLI now runs the complete ten-concern, tier-calibrated audit surface outside a Claude Code session.
- **docs:** Vibe family cohesion standard applied to the README; license footer normalized to canonical; count-agnostic ecosystem footer (no hard-coded plugin count).

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
