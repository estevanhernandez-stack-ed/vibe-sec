# Vibe Sec v0.2 — Build Checklist

> *"Ship the diagnostic, the transplant can wait."*

**Authored:** 2026-05-23 during the `/checklist` phase of Vibe Cartographer
**Persona:** Architect
**Mode:** Builder
**Reads:** `docs/spec.md`, `docs/research/synthesis.md` (§8 priority order is the spine), `docs/research/conflicts.md`
**Writes:** this file

This is the sequenced, dependency-aware build plan. It follows synthesis §8's four-phase order: foundation first (nothing consumes anything yet), then signal-independent detectors, then structural detectors, then the threat-model sink. Concerns that other concerns depend on land first.

**Convention per item:** **what** · **where** (file path) · **verify** · **deps**.

**Tag naming:** `vibe-sec-vX.Y.Z` (rooted in the `git-filter-repo` extraction lineage — same as the npm CLI's `0.1.x` history). Do NOT normalize to plain `vX.Y.Z`.

**Stack:** TypeScript in `packages/vibe-sec/src/`, **tsup** build, **vitest** tests. Node ≥20.

---

## Phase 1 — Foundation (deterministic TS) — **TODAY's target**

The handoff spine + the math substrate + the plugin skeleton + the CLI promotion. Nothing here depends on detectors; everything downstream depends on this. Ship all of Phase 1 today.

### 1.1 Tier classifier + weighted-score + severity amplifier — **TODAY**
- **What:** the math substrate (concern #10). Tier classifier (inherit-from-Vibe-Test-or-self-scan), weighted-score calculator (Σ over in-scope concerns, skipped excluded from denominator), severity amplifier (Critical caps concern_pass_fraction at 0.5, High at 0.8). ASVS-mapped tier curve 30/55/70/80/90.
- **Where:** `src/scoring/weighted-score.ts`, `src/scoring/severity-amplifier.ts`, `src/scanner/classify-tier.ts`.
- **Verify:** vitest — (a) amplifier caps a 0.97-clean concern with one Critical at 0.5; (b) skipped concern excluded from denominator; (c) Public-facing gate fails on High in mandatory concern even at ≥70%; (d) tier curve maps to ASVS L1/L2/L3 labels.
- **Deps:** none. Ship first — every other concern consumes tier as input.

### 1.2 findings.jsonl schema + state I/O — **TODAY**
- **What:** the handoff spine. Append-only `findings.jsonl` writer + reader conforming to spec §6 schema (incl. `tool_of_record` field). audit.json read/write. Data-dir resolution (global `~/.claude/plugins/data/vibe-sec/` + per-project `<project>/.vibe-sec/state/`).
- **Where:** `src/state/findings.ts`, `src/state/audit-state.ts`, `src/state/paths.ts`.
- **Verify:** vitest — (a) append two findings, read back both, line-count = 2; (b) schema-validate a finding round-trip; (c) ownership dedup by `id` (same id appended twice counts once in score); (d) paths resolve correctly on win32 + posix.
- **Deps:** 1.1 (severity types). Ship before any detector that writes findings.

### 1.3 Vibe Test handshake reader/writer — **TODAY**
- **What:** the composition contract. Reader for `.vibe-test/state/covered-surfaces.json` (freshness ≤24h gate, field extraction per spec §9.1), writer is the findings.jsonl writer from 1.2. Graceful fallback when absent → self-classify.
- **Where:** `src/composition/vibe-test.ts`.
- **Verify:** vitest — (a) present + fresh → inherits tier + modifiers; (b) absent → falls back to self-classify, never throws; (c) stale (>24h) → ignored, self-classify; (d) `uncovered_surfaces.endpoints` elevate audit priority.
- **Deps:** 1.1 (classifier), 1.2 (findings writer).

### 1.4 plugin.json scaffold + all command stubs — **TODAY**
- **What:** the plugin manifest bumped to `0.2.0` with all 9 commands registered, plus stub SKILL dirs for each (router + scan + audit + deps + fix + gate + posture + threat-model + research) and the shared `guide/` SKILL.
- **Where:** `packages/vibe-sec/.claude-plugin/plugin.json`, `packages/vibe-sec/skills/{vibe-sec,scan,audit,deps,fix,gate,posture,threat-model,research,guide}/SKILL.md`.
- **Verify:** plugin.json parses; all 9 command names present; each SKILL dir has a SKILL.md with frontmatter; `plugin-validate` (or manual JSON-schema check) passes.
- **Deps:** none structurally, but pairs with 1.5 (router) + 1.6 (scan promotion).

### 1.5 /vibe-sec router SKILL — **TODAY**
- **What:** the bare-router entry point. State-aware: reads `.vibe-sec/state/audit.json` freshness, recommends the next command (no audit yet → suggest `:audit`; stale → suggest re-run; clean → suggest `:posture`). Frames the orchestration positioning. SKILL-heavy, conversational.
- **Where:** `packages/vibe-sec/skills/vibe-sec/SKILL.md`.
- **Verify:** invoking `/vibe-sec` with no prior state produces the intro + `:audit` recommendation; with fresh state produces the posture summary pointer. Manual smoke.
- **Deps:** 1.2 (reads state), 1.4 (registered).

### 1.6 Promote CLI secret scanner into /vibe-sec:scan — **TODAY**
- **What:** lift the 404-line regex baseline from `packages/vibe-sec-cli/src/index.js` into `src/detectors/secrets/` as TypeScript primitives (Layer A regex only for Phase 1 — Layers B entropy + C AST land in Phase 2). Wire `/vibe-sec:scan` to the gitleaks/trufflehog deferral contract (which-probe → defer + parse JSON when present; in-house Layer A fallback when absent). CLI becomes a thin re-export (`src/cli.ts`) for headless CI.
- **Where:** `src/detectors/secrets/patterns.ts` (the promoted catalog), `src/detectors/secrets/scan-tree.ts`, `src/orchestration/tool-registry.ts` + `src/orchestration/defer.ts` (gitleaks/trufflehog adapters), `src/cli.ts`, `packages/vibe-sec/skills/scan/SKILL.md`.
- **Verify:** vitest — (a) Layer A catches the existing CLI's AWS/GitHub/Stripe/OpenAI patterns on a fixture; (b) `example|sample|mock` path downgrade preserved; (c) when gitleaks detected on PATH, deferral path is taken (mock the which-probe); (d) CLI re-export produces identical exit codes (0/1/2) to the legacy CLI on a fixture. De-risk the CLI→plugin rewire here — synthesis §9 flags this as the Phase 2 cascade risk.
- **Deps:** 1.2 (writes findings), 1.4 (registered). This is the orchestration-layer pattern's first concrete instance — get the deferral contract right here, the other concerns copy it.

**Phase 1 exit criteria:** classifier + score + amplifier green in vitest; findings.jsonl round-trips; Vibe Test handshake degrades gracefully; plugin.json registers 9 commands; `/vibe-sec` router responds; `/vibe-sec:scan` runs Layer A in-house and defers to gitleaks when present, CLI re-export parity confirmed.

---

## Phase 2 — Signal-independent detectors (subsequent)

Run in parallel with each other once Phase 1 lands. Each follows the deferral contract established in 1.6.

### 2.1 Secret detection — full stack (concern #2)
- **What:** extend 1.6 with Layer B entropy (Shannon ≥4.5 b64 / ≥3.0 hex, 20-char min), Layer C AST (`@babel/parser` — Conflict 4 = A), full git-history scan (Decision 9 — first run full, incremental after, `history-scan.json` cache), 40-50 provider patterns, Firebase web-key informational + rules-audit companion (Decision 21), `--verify` opt-in (Conflict 5 = A).
- **Where:** `src/detectors/secrets/{entropy.ts,ast-walk.ts,history-scan.ts,verify.ts}`, `src/state/history-scan.ts`.
- **Verify:** vitest — AST catches JSX-prop + `process.env.X=` overwrite leaks regex misses; history scan finds a secret in a prior commit on a fixture repo; shallow-clone emits the banner note; FP budget 0.7% holds on fixture corpus.
- **Deps:** Phase 1 complete.

### 2.2 Dependency CVE (concern #1)
- **What:** OSV-Scanner deferral (primary) + `npm audit` confirmer, dedupe by CVE/GHSA ID (Decision 12), `--omit=dev` on application projects (Decision 11, app-vs-lib classifier), `isSemVerMajor` fix-routing, lockfile-churn rollback >50 lines (Decision 20), EPSS/KEV schema hooks unwired (Decision 13).
- **Where:** `src/detectors/deps/{osv-client.ts,npm-audit.ts,app-lib-classifier.ts,dedupe.ts}`.
- **Verify:** vitest — OSV + npm audit dedup to one finding per CVE; app project gets `--omit=dev`; major bump routes to Inline; churn >50 lines re-stages.
- **Deps:** Phase 1; shares lockfile parsing with 2.3.

### 2.3 Supply-chain hardening (concern #6)
- **What:** lockfile integrity + pinning classification, GitHub Actions ref-style + permissions parse (SHA-pin third-party at Public-facing+, first-party at Regulated — Decision 24), typosquat (Levenshtein ≤2 vs top-500), dep-confusion, postinstall inspection, SBOM detection-only (Decision 25), Socket deferral in Band 4 (Decision 14).
- **Where:** `src/detectors/supply-chain/{lockfile.ts,actions-parse.ts,typosquat.ts,postinstall.ts,sbom-detect.ts}`.
- **Verify:** vitest — `latest`/`*` floating pin flagged; unpinned third-party Action flagged at Public-facing+; typosquat fixture (`expres` vs `express`) flagged; SBOM presence detected when `bom.json` exists.
- **Deps:** Phase 1; shares lockfile parsing with 2.2.

### 2.4 Config posture (concern #5)
- **What:** framework-config parsing (Next.js `headers()`, Vite, Express/Fastify chain, Firebase rules, vercel.json, _headers, nginx.conf), cookie-flag inspection, CORS detection, CVE-2025-29927 baked-in rule (Decision 6 — joint with auth-model), CSP report-only auto / enforcing staged (Decision 15), Firebase `if true` Critical above Prototype.
- **Where:** `src/detectors/config-posture/{headers.ts,cors.ts,cookies.ts,firebase-rules.ts,cve-2025-29927.ts}`.
- **Verify:** vitest — `origin: true, credentials: true` flagged Critical; Firebase `allow read, write: if true` flagged; CVE-2025-29927 fires on vulnerable `next` version in package.json; missing-header fix routes to Auto.
- **Deps:** Phase 1.

### 2.5 Commands: /vibe-sec:scan (complete), /vibe-sec:deps
- **What:** `:scan` finalized (Phase 1 stub → full secret orchestration). `:deps` = fast SCA + supply-chain subset (CVE + lockfile-integrity + pinning; skips SBOM/typosquat-round-trips/threat-model — Decision 1).
- **Where:** `packages/vibe-sec/skills/{scan,deps}/SKILL.md`.
- **Verify:** `/vibe-sec:deps` runs CVE + lockfile pass only; `/vibe-sec:scan` runs full secret stack; both write findings.jsonl.
- **Deps:** 2.1, 2.2, 2.3.

---

## Phase 3 — Structural detectors + orchestration commands (subsequent)

Depend on Phase 1-2 primitives (framework detection, schema parsing).

### 3.1 Crypto / PII (concern #4)
- **What:** deprecated-primitive call sites, bcrypt-cost/Argon2-param checks, JWT-algorithm audit, PII schema inventory (Prisma/Drizzle/Zod/Yup parse), PII-in-logs call-site scan (shared schema with rate-limiting), client-side key leakage, legacy-hash-migration = informational-not-finding.
- **Where:** `src/detectors/crypto-pii/{primitives.ts,password-hashing.ts,jwt-audit.ts,pii-inventory.ts,pii-in-logs.ts}`.
- **Verify:** vitest — `bcrypt.hash(pw, 10)` flagged High at Public-facing+; JWT `none`/missing-`algorithms:` flagged Critical; PII schema inventory artifact emitted; dual-path migration NOT flagged.
- **Deps:** Phase 1-2; schema-parse shared with 3.2.

### 3.2 Auth model (concern #8) — the signature concern
- **What:** six probes (route inventory, admin gating, tenant-isolation scan, IDOR gated Public-facing+ high-confidence per Decision 18, session-pattern classification, role-hardcoding), authorization matrix artifact (Decision 19), CVE-2025-29927 joint with 2.4, platform fingerprint priors (Decision 10).
- **Where:** `src/detectors/auth-model/{route-inventory.ts,admin-audit.ts,tenant-isolation.ts,idor.ts,session.ts,role-hardcoding.ts,authz-matrix.ts}`, `src/scanner/platform-fingerprint.ts`.
- **Verify:** vitest — Supabase table without RLS flagged Critical at Customer-facing+; IDOR only fires at ≥0.9 confidence + Public-facing+; authorization matrix renders rows=routes × columns=authz-dimensions; v0 fingerprint elevates Server-Action-missing-auth detection.
- **Deps:** Phase 1-2; framework detection + schema parsing from 3.1.

### 3.3 OWASP Top 10 survey (concern #3)
- **What:** breadth layer + dual 2021/2025 tagging (Decision 3), survey-level A03 (Decision 4, Semgrep CE deferral for deep), A09 silent-catch + advisory, A10 shallow SSRF pattern-match, dynamic-code-loading sinks = review-required-never-auto. Consumes other concerns' outputs for primary-concern assignment.
- **Where:** `src/detectors/owasp-survey/{survey-rules.ts,dual-tag.ts,ssrf-shallow.ts,dynamic-code-sinks.ts}`.
- **Verify:** vitest — every finding carries owasp_2021 + owasp_2025; SSRF-A10-2021 annotated as A01-2025; dynamic-code sink routes to Inline; A03 deep deferred to Semgrep when present.
- **Deps:** Phase 1-2; consumes 3.1, 3.2 for tagging.

### 3.4 Rate limiting (concern #7)
- **What:** middleware-registration inspection, LLM-endpoint detection (SDK import + handler + auth + per-user budget), **unauthenticated LLM-burn = Critical at every tier** (Decision 5; authenticated stays tier-gated per Conflict 1 = A), platform-vs-framework recommendation order (Decision 16), Arcjet-leads-when-LLM (Decision 17), dual A04+A09 tagging.
- **Where:** `src/detectors/rate-limiting/{middleware.ts,llm-endpoint.ts,platform-config.ts,abuse-monitoring.ts}`.
- **Verify:** vitest — unauth route importing `openai` → Critical even at Prototype; authenticated unbounded LLM → tier-gated; platform-native recommended first at Public-facing+; Arcjet leads Band 4 when LLM detected.
- **Deps:** Phase 1-2; integrates with 3.2 route inventory.

### 3.5 Orchestration commands: /vibe-sec:audit, /vibe-sec:gate, /vibe-sec:posture, /vibe-sec:fix
- **What:** `:audit` (full 10-concern orchestrator, four-band report, three channels), `:gate` (exit codes 0/1/2 + GH Actions annotations, tier gate rules spec §2.4), `:posture` (read-only cached summary), `:fix` (confidence-tier routing + destructive overrides spec §8, `--auto` deliberately small).
- **Where:** `packages/vibe-sec/skills/{audit,gate,posture,fix}/SKILL.md`, `src/fix/{route.ts,apply.ts,stage.ts}`, `src/report/{bands.ts,banner.ts,markdown.ts}`.
- **Verify:** `/vibe-sec:audit` against a fixture produces four-band markdown + banner + findings.jsonl; `/vibe-sec:gate` exits 1 on High in mandatory concern; `:fix --auto` adds .gitignore but refuses secret rotation; `:posture` reads cached state without re-scanning.
- **Deps:** all Phase 2 + 3.1-3.4.

---

## Phase 4 — Synthesis sink + research (subsequent)

### 4.1 Threat model generation (concern #9) — the sink node
- **What:** runs last, never parallelized (Decision 8), consumes all 9 concerns + Vibe Test covered-surfaces. STRIDE + DREAD + LINDDUN (Customer-facing+) + attack-trees, Mermaid-in-markdown + Threat Dragon JSON sidecar (Decision 26), inventory-completeness check (<90% route coverage → banner), Internal-tier opt-in only (Conflict 2 = C).
- **Where:** `src/threat-model/synthesize.ts`, `packages/vibe-sec/skills/threat-model/SKILL.md`.
- **Verify:** `/vibe-sec:threat-model` emits `docs/vibe-sec/threat-model.md` with valid Mermaid + `.vibe-sec/state/threat-model.json` Threat-Dragon-compatible; locked Mermaid shape convention; <90%-coverage banner fires; not auto-included in `:audit` at Internal.
- **Deps:** all prior phases.

### 4.2 /vibe-sec:research (any phase, infrastructural)
- **What:** re-run one concern's domain-research agent (living docs), friction-log-driven cadence (Conflict 8 = A), regenerates the brief + triggers synthesis re-gen.
- **Where:** `packages/vibe-sec/skills/research/SKILL.md`.
- **Verify:** `/vibe-sec:research --concern secret-detection` re-runs the agent and updates `docs/research/secret-detection.md`.
- **Deps:** none structurally; can land any time.

### 4.3 docs/SECURITY.md handoff + WSYATM dogfood
- **What:** builder-sustainable `docs/SECURITY.md` generation (emit-only for v0.2, ASVS-cited, honeytokens surfaced as Pattern #13 recommendation per Conflict 6 = A). Run full `/vibe-sec:audit` against `C:\Users\estev\Projects\WeSeeYouAtTheMovies\` — the acceptance test.
- **Where:** `src/state/security-md.ts`, dogfood is a run not a file.
- **Verify:** WSYATM classifies Public-facing (or Customer-facing SaaS); all 10 concerns surface findings-or-honest-absence; FP rate ≤12%; produces real pre-launch hardening guidance.
- **Deps:** all phases.

---

## Cross-phase risk register (from synthesis §9)

- **CLI→plugin rewire (de-risked in Phase 1.6, not Phase 2).** Synthesis §9 warns the secret-scan promotion cascades through Phase 2/3 if late. Pulled into Phase 1 deliberately — get the deferral contract right on the smallest, most-credible artifact first.
- **Research-swarm brief quality is load-bearing.** The litmus review's pressure-test (2-concern micro-swarm on A03 + A07 before committing the full ten) already happened — briefs + synthesis exist. If `/vibe-sec:research` re-runs regress, seed agents with OWASP/Snyk canonical material.
- **FP-budget measurement needs a builder-adjudication hook.** Open (synthesis §9.9): suppress-with-reason during WSYATM dogfood. Wire into `:posture` or a future `:feedback` — not Phase 1.
- **Threat-model re-render on fix-loop.** Default (synthesis §9.2): threat-model renders on `:audit` only; fix-loop regenerates findings.jsonl but doesn't re-render the model until explicit `:threat-model`.

---

*End of checklist. Next: `/build` — Phase 1 is TODAY's target; Phases 2-4 are subsequent. Build foundation-first, the rest copies the orchestration-layer pattern Phase 1 establishes.*
