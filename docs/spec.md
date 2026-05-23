# Vibe Sec v0.2 — Technical Spec

> *"Everything is in scope at 626Labs LLC."*
> *"Work from the future. We are already behind."*

**Authored:** 2026-05-23 during the `/spec` phase of Vibe Cartographer
**Persona:** Architect
**Mode:** Builder
**Reads:** `docs/scope.md`, `docs/prd.md`, `packages/vibe-sec/framework.md`, `packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`, `docs/research/synthesis.md` (implementation source of truth), `docs/research/conflicts.md`, `docs/reviews/2026-05-22-external-litmus-review.md`
**Writes:** this file + `docs/checklist.md`

---

## 0. The one-sentence pivot

Vibe Sec is **the tier-aware audit and orchestration layer for vibe-coded apps — not another scanner.** It defers to the established free, no-account security tools when they're present (OSV-Scanner, Semgrep CE, gitleaks, Trivy, Syft), runs an in-house TypeScript baseline only when those tools are absent, and adds the classification, severity calibration, four-band report, fix routing, and threat-model synthesis intelligence on top of whatever's underneath. The product is the layer, not the scanner.

This spec encodes that pivot. Everywhere the prior corpus said "we built X scanner," read "we orchestrate X scanner when present, fall back to a baseline when absent." The synthesis (`docs/research/synthesis.md`) is the implementation source of truth for *what* each concern detects; this spec adds the *orchestration contract* — who owns each concern when an external tool is on the system, and what the in-house fallback covers when it isn't.

---

## 1. Architecture overview

### 1.1 The four load-bearing moves (from synthesis §1)

1. **Classification-first routing.** The tier classifier runs before any detection, produces a tier (Prototype → Regulated) plus context modifiers, and everything downstream calibrates to it. Tier is a *scope gate*, not just a severity dial: at Prototype, rate-limiting is dropped from the denominator entirely; at Regulated, LINDDUN privacy walks and SBOM recommendation become mandatory.
2. **The four-band report** (Critical-now / tier-appropriate-education / graduating-guidance / Pattern #13 complements) — the UX device that respects builder fatigue while still teaching.
3. **Hybrid severity** — 4-level Vibe-Sec-native (Critical/High/Medium/Low) for own findings + CVSS passthrough for CVE findings; tier × concern drives the final calibration.
4. **Single `findings.jsonl` schema** with dual OWASP 2021/2025 tagging, `primary_concern` + `secondary_concerns`, and Vibe Test handoff hooks — the connective tissue that makes cross-concern dedup work.

### 1.2 The orchestration-layer model (the pivot, made concrete)

Vibe Sec sits **above** the security-tool stack, not beside it. The runtime decision tree, per concern:

```
for each concern:
  external_tool = detect_tool_of_record(concern)   # which-style probe + version
  if external_tool.present:
    findings = run_external(external_tool)          # shell-out, parse JSON
    credit_tool_in_report(external_tool)
  else:
    findings = run_inhouse_baseline(concern)        # TS regex / AST / config parse
    surface_complement_in_band_4(concern)           # "install X to catch what we miss"
  findings = classify_severity(findings, tier)      # Vibe Sec owns this regardless
  findings = route_fix(findings)                    # Vibe Sec owns this regardless
  emit(findings → findings.jsonl + report + banner) # Vibe Sec owns this regardless
```

What Vibe Sec **always** owns, present-tool-or-not:
- Tier classification + weighted score + severity amplifier (concern #10 — the math substrate)
- Severity calibration (tier × concern × amplifier)
- The four-band report structure + terminal banner + `findings.jsonl` sidecar
- Confidence-tier fix routing + destructive-action overrides
- Cross-concern dedup (`primary_concern` ownership rule)
- Vibe Test composition handshake
- Threat-model synthesis (the sink node)
- The `docs/SECURITY.md` builder-sustainable handoff

What Vibe Sec **delegates** when the tool of record is present: the raw detection. gitleaks beats the in-house regex; OSV-Scanner beats `npm audit` alone; Semgrep CE beats hand-rolled AST walkers. Defer, parse, re-classify, re-frame — don't compete.

### 1.3 Component layout (`packages/vibe-sec/`)

```
packages/vibe-sec/
  .claude-plugin/plugin.json          # manifest: 9 commands, version 0.2.0
  src/
    scoring/
      weighted-score.ts               # SHARED — consumed by classifier/audit/gate/posture
      severity-amplifier.ts           # Critical caps pass_fraction 0.5, High 0.8
    scanner/
      classify-tier.ts                # tier classifier (inherit-or-scan)
      detect-app-roots.ts             # monorepo --app flag support (Conflict 9 = C)
      platform-fingerprint.ts         # v0/Lovable/Bolt priors (Decision 10)
    state/
      findings.ts                     # findings.jsonl append-only writer + reader
      audit-state.ts                  # audit.json read/write
      paths.ts                        # data-dir resolution (global + per-project)
    orchestration/
      tool-registry.ts                # tool-of-record detection (which-probe + version)
      defer.ts                        # shell-out + JSON-parse adapters per external tool
    detectors/                        # in-house fallback baselines, one per concern
      secrets/                        # promoted from CLI (Layer A/B/C)
      deps/                           # OSV client + npm audit shell-out
      supply-chain/
      config-posture/
      crypto-pii/
      auth-model/
      owasp-survey/
      rate-limiting/
    fix/
      route.ts                        # confidence-tier routing + destructive overrides
      apply.ts                        # auto-apply (gitignore, additive headers only)
      stage.ts                        # pending/ staging
    report/
      bands.ts                        # four-band structure
      banner.ts                       # ANSI terminal channel
      markdown.ts                     # docs/vibe-sec/ artifact channel
    composition/
      vibe-test.ts                    # covered-surfaces.json reader, findings.jsonl writer
    threat-model/
      synthesize.ts                   # sink node — STRIDE/DREAD/Mermaid/Threat Dragon
    cli.ts                            # thin wrapper re-export for headless CI
  skills/                             # agent-SKILL surface, one dir per command
    vibe-sec/                         # router
    scan/ audit/ deps/ fix/ gate/ posture/ threat-model/ research/
    guide/                            # shared persona + behavior (loaded by all)
  plays-well-with.md                  # the deferral contract table (also in §3 here)
```

**Stack + conventions:** TypeScript in `src/`, **tsup** build, **vitest** tests. Matches Vibe Test. Node ≥20. No paid-API dependencies in v0.2 runtime.

### 1.4 Data directories (locked)

| Path | Owner | Contents |
|---|---|---|
| `~/.claude/plugins/data/vibe-sec/` | global | `profile.json`, `sessions/<date>.jsonl`, `friction.jsonl`, `wins.jsonl` |
| `<project>/.vibe-sec/state/` | per-project | `findings.jsonl` (append-only), `audit.json`, `history-scan.json`, `osv-cache.json` |
| `<project>/.vibe-sec/pending/` | per-project | staged fixes awaiting builder review (`fixes/*.diff`) |
| `<project>/docs/vibe-sec/` | per-project | markdown reports, `threat-model.md`, `SECURITY.md` |
| `<project>/.vibe-sec/state/threat-model.json` | per-project | Threat Dragon v2.5.0-compatible sidecar |

Monorepo (Conflict 9 = Option C): explicit `--app <path>` flag scopes per-app state to `.vibe-sec/apps/<app>/state/`. No first-class auto-discovery in v0.2.

---

## 2. Tier / scoring engine (concern #10)

### 2.1 Tier model maps to OWASP ASVS

The 30/55/70/80/90 curve is no longer "numbers we picked." It maps to an external standards body:

| Tier | Threshold | ASVS / standards floor |
|---|---|---|
| Prototype / hackathon | 30% | No formal verification target |
| Internal tool | 55% | OWASP **ASVS L1** |
| Public-facing | 70% | OWASP **ASVS L2** |
| Customer-facing SaaS | 80% | OWASP **ASVS L3** |
| Regulated / enterprise | 90% | OWASP **ASVS L3** + **NIST SSDF** practices (PO, PS, PW, RV) + **SBOM** (Syft passthrough) |

Cite ASVS explicitly in report copy and `docs/SECURITY.md`. This removes the "where did these numbers come from" objection and gives builders a known-quantity verification target they can hand to auditors and customers. The numeric curve stays at Vibe Test parity (synthesis Decision 2) for cross-plugin composition; the ASVS mapping is the *external justification* the litmus review demanded.

### 2.2 Weighted score + severity amplifier (synthesis Decision 2, §3.10)

- Weighted score = Σ(concern_pass_fraction × concern_weight) over **in-scope concerns at the current tier** (skipped concerns are excluded from the denominator — tier is a scope gate).
- **Severity amplifier (hard rule):** any **Critical** finding caps that concern's `concern_pass_fraction` at **0.5**; any **High** caps at **0.8**. This forces the "97% clean but one committed AWS key still fails" behavior without diverging the curve.
- Shared implementation: `src/scoring/weighted-score.ts`, consumed by classifier, audit, gate, and posture.

### 2.3 Classifier — inherit-first

- Read `.vibe-test/state/covered-surfaces.json` when present and fresh (≤24h) → inherit `classification.tier` + `modifiers[]`.
- Security-specific promotion is **explicit, logged, builder-visible** via a `tier_drift_note` beacon when Vibe Sec promotes above the inherited tier.
- Promotion signal classes: deployment-detection (→ Public-facing), payment/PII integration (→ Customer-facing SaaS), multi-tenant signals (confirmatory), compliance markers (→ Regulated — but HIPAA/PCI marketing text is Medium-strength, not Strong).
- **Fallback when absent/stale:** run own classifier via `src/scanner/classify-tier.ts`. Never fail; degrade gracefully.
- Tier-override decay: **90 days uniform** for v0.2 (Conflict 7 = Option A; revisit at v0.3 with Regulated dogfood data).

### 2.4 Gate decision rules (synthesis §6)

| Tier | Pass condition |
|---|---|
| Prototype | weighted ≥30%. No concern individually mandatory; Critical in concerns 1, 2, 7(LLM-burn) fails regardless |
| Internal | weighted ≥55%. No concern individually mandatory |
| Public-facing | weighted ≥70% **and** no High/Critical in mandatory concerns (3, 5, 7, 8) |
| Customer-facing SaaS | weighted ≥80% **and** no High/Critical in mandatory concerns (1, 3, 4, 5, 6, 7, 8). Tenant isolation is a hard binary — any Supabase table without RLS / Firestore permissive = fail |
| Regulated | weighted ≥90% **and** no High/Critical in **any** concern except #9 (threat-model is advisory). This "no High anywhere" hard gate is the de-facto resolution of Conflict 3 (Option C — does the work 95% wanted, no curve divergence) |

`/vibe-sec:gate` exit codes: `0` pass / `1` fail (findings at/above tier bar) / `2` scanner error. Emits GitHub Actions annotations when `GITHUB_ACTIONS=true`.

---

## 3. The orchestration-layer model — per-concern deferral table

This is the `plays-well-with.md` table, inlined. For each concern: the **external tool of record** (used when present), the **detection mechanism** (how Vibe Sec finds it on the system), and the **in-house fallback scope** (what the baseline covers when the tool is absent). Findings are re-classified, re-severitied, and re-framed by Vibe Sec regardless of source.

| Concern | External tool of record (v0.2 first-class anchored) | Detection mechanism | In-house fallback scope (tool absent) |
|---|---|---|---|
| #1 Dependency CVE / SCA | **OSV-Scanner** (primary), `npm audit` (fix-availability confirmer) | `which osv-scanner`; `npm audit` is always-present built-in | OSV.dev direct batch query (24h cache) + `npm audit` shell-out, dedupe by CVE/GHSA ID. OSV wins on existence, npm audit wins on fix-availability (Decision 12) |
| #2 Secret detection | **gitleaks** (working tree + history), **trufflehog** (history, prefer its verifier when `--verify`) | `which gitleaks` / `which trufflehog`; parse `--report-format json` | Promoted CLI: Layer A regex (40-50 provider patterns), Layer B entropy (Shannon ≥4.5 b64 / ≥3.0 hex), Layer C AST (`@babel/parser`). Full git-history scan via `git` substrate (Decision 9, Conflict 4 = A) |
| #3 OWASP Top 10 survey | **Semgrep CE** (2000+ community rules, esp. A03), **CodeQL** (public repos) | `which semgrep`; parse `--json`; consume rule output | Survey-level in-house: A02 algorithm smells, A04 absence-of-control proxies, A05 headline config, A08 SRI + dynamic-code sinks, A09 silent-catch, A10 shallow SSRF pattern-match. Deep injection deferred to Semgrep / v0.3 (Decision 4) |
| #4 Crypto / PII | **Semgrep CE** (crypto rules), **Microsoft Presidio** (free-text PII) | `which semgrep` | In-house: deprecated-primitive call sites, bcrypt-cost / Argon2-param checks, JWT-algorithm audit, PII schema inventory (Prisma/Drizzle/Zod/Yup parse), PII-in-logs call-site scan |
| #5 Config posture | **Mozilla Observatory** / **securityheaders.com** (post-deploy runtime complement) | runtime tools are advisory links, not shell-outs | In-house always: framework-config parse (Next.js `headers()`, Vite, Express/Fastify chain, Firebase rules, vercel.json, _headers, nginx.conf), cookie-flag inspection, CORS detection, CVE-2025-29927 baked-in rule (Decision 6) |
| #6 Supply-chain hardening | **Socket.dev (Firewall Free)** (attack-window novelty), **OpenSSF Scorecard**, **Syft** (SBOM gen, Regulated) | `which syft` for SBOM gen; Socket/Scorecard surfaced in Band 4 | In-house: lockfile integrity + pinning classification, GitHub Actions ref-style + permissions parse, typosquat (Levenshtein ≤2 vs top-500), dep-confusion, postinstall inspection, SBOM **detection only** (gen deferred — Decision 25) |
| #7 Rate limiting / abuse | platform-native (**Vercel Firewall / Cloudflare Rulesets / API Gateway**), **Arcjet** (LLM routes), **Upstash Ratelimit** (generic) | deploy-platform config detection; all recommended in Band 4 | In-house always: middleware-registration inspection (Express/Fastify/Next/NestJS/Hono/tRPC), LLM-endpoint detection (SDK import + handler proximity + auth check + per-user budget), abuse-monitoring presence |
| #8 Auth model | **Semgrep CE** (authz rules), **CodeQL** (A01) | `which semgrep` | In-house always (the signature concern): route inventory per framework, admin role-gate audit, tenant-isolation query scan (Supabase/Firestore/Prisma/Drizzle), IDOR scoring (gated Public-facing+ high-confidence — Decision 18), session-pattern classification, role-hardcoding, authorization matrix artifact (Decision 19), CVE-2025-29927 |
| #9 Threat model | **OWASP Threat Dragon** (GUI maintenance, JSON-compatible sidecar), **pytm** (Python teams) | Threat Dragon surfaced in Band 4; sidecar is Threat-Dragon-schema-compatible | In-house always (synthesis sink): STRIDE + DREAD + LINDDUN (Customer-facing+) + Mermaid DFD + Threat Dragon JSON. Consumes all 9 other concerns (Decision 8) |
| #10 Tier thresholds | **OWASP ASVS** (requirements), **NIST SSDF / OWASP SAMM** (maturity model), **Drata/Vanta/Secureframe** (compliance, Regulated) | standards are reference mappings, not tools to shell out to | In-house always: the math substrate — classifier + weighted score + amplifier + gate. Owns no detectors |

**Day-one ambient compose (use when installed, credit the tool):** gitleaks, trufflehog, git, npm audit, helmet/@fastify/helmet, Semgrep, ESLint + `eslint-plugin-no-unsanitized`, OSV-Scanner, Trivy (container — surfaced when Dockerfile present), Syft.

**Commercial Pattern #13 complements (Band 4, "future runs" when not mid-fatigue):** Snyk, Socket.dev, GitGuardian, Semgrep commercial, Dependabot, Renovate, GitHub Secret Scanning + Push Protection, Casbin/Cerbos/OPA, Clerk/Auth0, Arcjet, Cloudflare WAF + Turnstile, SonarQube, IriusRisk/ThreatModeler, Drata/Vanta/Secureframe.

**Categorically out of scope (name only, never recommend first):** OWASP ZAP / Burp (runtime pentest — v0.3+), Datadog Security / Panther (runtime observability), SIEM platforms, binary-authorization CI gating.

---

## 4. The ten concerns

Each: detection surface · external tool of record · in-house fallback · tier applicability. Detection mechanics are the synthesis §3 digests; this section frames each through the orchestration lens. The synthesis is authoritative for *what* each detects; this is authoritative for *who detects it and at which tiers*.

### 4.1 Concern #1 — Dependency CVE / SCA
- **Detection surface:** known CVEs in direct + transitive deps, dev-vs-prod classification (Decision 11 — `--omit=dev` on application projects), fix-availability routing via `isSemVerMajor`, lockfile-churn rollback (>50 lines → re-stage, Decision 20).
- **Tool of record:** OSV-Scanner primary; `npm audit` confirmer.
- **In-house fallback:** OSV.dev batch API + `npm audit` shell-out, dedupe by ID.
- **Tier applicability:** lightweight (Critical only) at Prototype → full by Public-facing → mandatory at Customer-facing+ → +SBOM recommendation at Regulated.

### 4.2 Concern #2 — Secret detection
- **Detection surface:** working tree + **full git history by default** (Decision 9), 40-50 provider patterns, three-layer stack (regex / entropy / AST — Conflict 4 = A, ship AST in v0.2), Firebase web key = informational + rules-audit companion (Decision 21), git-history-rewrite is inline-runbook-only (Decision 22).
- **Tool of record:** gitleaks (tree + history), trufflehog (history; prefer its verifier when `--verify` — Conflict 5 = A, opt-in for v0.2).
- **In-house fallback:** the promoted CLI (404-line regex baseline) extended to Layers B + C, + git-history scan via the `git` substrate.
- **Tier applicability:** **full scan at every tier** — secret leaks scale with credential value, not tier. Severity of non-catastrophic findings (missing `.env.example`) scales with tier; AWS root key is Critical everywhere.

### 4.3 Concern #3 — OWASP Top 10 survey (the category glue)
- **Detection surface:** survey-level breadth (A02/A04/A06/A08/A09/A10), dual 2021/2025 tagging (Decision 3), A03 stays survey-level for v0.2 (Decision 4). Deep dives delegate to dedicated concerns.
- **Tool of record:** Semgrep CE for deep A03 injection + crypto; CodeQL for A01/A03 on public repos.
- **In-house fallback:** survey rules only — high-signal vibe-coded patterns (template-literal SQL, React dangerous-HTML prop from user input, prototype-pollution sinks, the shell-exec sink family). See §10 for the OWASP coverage-honesty reframe.
- **Tier applicability:** skip at Prototype (except secrets bleed-through) → lightweight at Internal → mandatory Public-facing+.

### 4.4 Concern #4 — Crypto / PII handling
- **Detection surface:** Argon2id ceiling / bcrypt-cost-12 floor, AEAD-or-bust, JWT `none`/short-secret/missing-`algorithms:` = Critical, PII inventory artifact (schema parse), PII-in-third-party-tracker = Critical at Public-facing+ (GDPR Art. 44), legacy-hash-migration is NOT a finding (informational).
- **Tool of record:** Semgrep CE (crypto rules), Microsoft Presidio (free-text PII).
- **In-house fallback:** deprecated-primitive call sites, password-handling patterns, hardcoded-key + env-var + `||`-fallback traps, client-side key leakage (`NEXT_PUBLIC_*`/`VITE_*`), PII schema inventory + in-logs audit.
- **Tier applicability:** skip at Prototype (except hardcoded secrets) → crypto from Internal, PII from Public-facing → mandatory Customer-facing+ (+NIST FIPS check at Regulated).

### 4.5 Concern #5 — Config-level security posture
- **Detection surface:** OWASP Secure Headers 2026 baseline, X-XSS-Protection deprecated (don't recommend), CSP report-only = auto-apply / enforcing = always staged (Decision 15), CORS origin-reflection-with-credentials = Critical, Firebase `allow read, write: if true` = Critical above Prototype, CVE-2025-29927 baked-in (Decision 6).
- **Tool of record:** Mozilla Observatory / securityheaders.com (post-deploy runtime advisory links — not shell-outs).
- **In-house fallback:** always in-house — framework-config-file parsing across the stack, cookie-setting inspection, CORS detection, default-credential patterns, the CVE rule.
- **Tier applicability:** Firebase `if true` warning only at Prototype → nosniff/X-Frame/HttpOnly at Internal → full + CSP at Public-facing → enforcing strict CSP + COOP/COEP at Customer-facing → HSTS preload + cookie prefixes + SRI at Regulated.

### 4.6 Concern #6 — Supply-chain hardening
- **Detection surface:** post-XZ/Shai-Hulud/tj-actions reframe, artifact-vs-repo integrity, typosquat (load-bearing), SHA-pin third-party Actions at Public-facing+ / first-party only at Regulated (Decision 24), `ignore-scripts` default at Public-facing+, SBOM detection-only (gen → v0.3, Decision 25), compromised-window curation deferred to Socket (Decision 14).
- **Tool of record:** Socket.dev Firewall Free (novelty), OpenSSF Scorecard, Syft (SBOM gen at Regulated).
- **In-house fallback:** lockfile integrity + pinning, Actions ref-style + permissions parse, typosquat/dep-confusion/slopsquat, postinstall inspection, SBOM presence detection.
- **Tier applicability:** informational at Prototype → lockfile presence + `latest` detection at Internal → integrity + SHA-pin + permissions at Public-facing → +typosquat/dep-confusion at Customer-facing → +SBOM/provenance at Regulated.

### 4.7 Concern #7 — Rate limiting / abuse protection
- **Detection surface:** authenticated-abuse > anonymous (95% of API attacks), **unauthenticated LLM-backed endpoint = Critical at every tier** (Decision 5, the one tier-override; Conflict 1 = A: authenticated-but-unbounded LLM stays tier-gated), platform-vs-framework recommendation order (Decision 16), Arcjet leads when LLM routes detected (Decision 17), dual A04+A09 tagging, CAPTCHA reduces severity one band, custom Redis-INCR = "detected, not verified."
- **Tool of record:** platform-native first at Public-facing+ (Vercel Firewall / Cloudflare / API Gateway), Arcjet (LLM), Upstash Ratelimit (generic).
- **In-house fallback:** always in-house — middleware-registration inspection, LLM-endpoint detection, deploy-platform config detection, abuse-monitoring presence.
- **Tier applicability:** skip at Prototype (EXCEPT LLM-burn override) → library-absence signal at Internal → mandatory (auth routes) at Public-facing → +per-tenant + LLM budgets at Customer-facing → +anomaly detection + SIEM at Regulated.

### 4.8 Concern #8 — Auth model static analysis (the signature concern)
- **Detection surface:** six probes — route inventory + middleware attachment, admin role-gating, tenant-isolation query patterns (the Lovable/Supabase finding no other plugin catches), IDOR scoring (gated Public-facing+ high-confidence ≥0.9 — Decision 18), session-pattern classification, role-hardcoding. **Authorization matrix is the signature artifact** (Decision 19 — rows=routes, columns={auth-required, role-gated, ownership-enforced, RLS-applicable}, cells={enforced/absent/unknown/N/A}). CVE-2025-29927 baked-in. Multi-tenant isolation is Customer-facing-SaaS-critical.
- **Tool of record:** Semgrep CE (authz rules), CodeQL (A01).
- **In-house fallback:** always in-house — this is Vibe Sec's unique contribution vs Vibe Test's behavioral tests. Route inventory per framework, admin audit, tenant scan, IDOR, session, role-hardcoding, matrix.
- **Tier applicability:** lightweight at Prototype (committed secret → Critical, rest informational) → full route inventory + admin check at Internal → mandatory + basic IDOR at Public-facing → +**mandatory tenant isolation** + role matrix + refresh rotation + MFA option at Customer-facing → +policy-as-code + audit log + SAML/SSO at Regulated.

### 4.9 Concern #9 — Threat model generation (the sink node)
- **Detection surface:** none — pure synthesis. Runs **last**, never parallelized at runtime (Decision 8). Consumes classification + all 9 concerns' outputs + Vibe Test covered-surfaces. STRIDE (builder-facing) + DREAD (prioritization) + LINDDUN (Customer-facing+) + attack-trees-top-3 (Public-facing+). Inventory-completeness check before synthesis (banner if route coverage <90%). FP target is "threat relevance" not accuracy: 12% on enumeration, <5% on top-10-prioritized.
- **Tool of record:** OWASP Threat Dragon (GUI maintenance), pytm (Python teams).
- **In-house fallback:** always in-house — Mermaid-in-markdown primary + Threat Dragon v2.5.0-compatible JSON sidecar (Decision 26). Mermaid convention locked: stadiums=external entities, rectangles=processes, cylinders=data stores, hexagons=third-parties, subgraphs=trust boundaries.
- **Tier applicability:** stub at Prototype → lightweight (external + admin boundary) at Internal **opt-in only** (Conflict 2 = C: not auto-included in `/vibe-sec:audit` at Internal) → full STRIDE+DREAD+attack-trees-top-3 at Public-facing → +LINDDUN+tenant boundary at Customer-facing → +attack-trees-top-5 + pytm stub at Regulated.

### 4.10 Concern #10 — Security-tier thresholds (the math substrate)
Covered in full at §2. Owns no detectors; owns the classifier + weighted score + amplifier + gate contract + `docs/SECURITY.md` graduating-guidance generation. Runs at every tier (meta). See §2.

---

## 5. Severity model

- **Hybrid:** 4-level Vibe-Sec-native (Critical / High / Medium / Low) for own findings + **CVSS passthrough** for CVE findings (don't reinvent the industry standard).
- **Tier × concern drives final severity** (`severity_base` → `severity_tier_adjusted` in the schema). Example: committed AWS key is Critical at Public-facing, High at Prototype.
- **The amplifier** (§2.2) sits on top: Critical caps concern_pass_fraction at 0.5, High at 0.8.
- **The one override:** unauthenticated LLM-backed endpoint is Critical at every tier regardless of the matrix (Decision 5).
- **EPSS / KEV hooks** exist in the schema but are **not wired to scoring in v0.2** (Decision 13) — hook now, score later, no migration needed.
- **FP commitment: 12% global**, distributed per-concern (synthesis §7 budgets, summarized §8 here). Per-concern budgets are enforcement *targets*, not gate-failing ceilings (Decision 27).

---

## 6. `findings.jsonl` schema

`<project>/.vibe-sec/state/findings.jsonl` — append-only, one JSON object per line (synthesis §4.1, locked):

```json
{
  "schema_version": 1,
  "id": "sec-042",
  "created_at": "2026-04-20T14:00:00Z",
  "primary_concern": "auth-model",
  "secondary_concerns": ["owasp-survey", "config-posture"],
  "owasp_2021": "A01",
  "owasp_2025": "A01",
  "cwe": "CWE-862",
  "severity_base": "high",
  "severity_tier_adjusted": "critical",
  "confidence": 0.92,
  "surface": "/api/admin/users",
  "finding_type": "missing-auth-middleware",
  "title": "Unauthenticated admin route",
  "description": "Route /api/admin/users accepts requests without auth() invocation; no middleware covers this path.",
  "file": "app/api/admin/users/route.ts",
  "line": 12,
  "tier": "public-facing",
  "tier_scaling_at_current_tier": 1.0,
  "fix_class": "stage",
  "fix_ref": ".vibe-sec/pending/fixes/sec-042-add-auth-middleware.diff",
  "test_recommendation": "behavioral test: unauthorized access returns 401",
  "priority_elevation": "critical",
  "expected_behavior": "401 for unauthenticated request",
  "epss_score": null,
  "kev_listed": false,
  "suppressed": false,
  "suppressed_reason": null,
  "tool_of_record": "in-house",
  "references": ["OWASP-A01-2021", "CWE-862"]
}
```

**Field contract:**
- `primary_concern` ∈ {`dependency-cve`, `secret-detection`, `owasp-survey`, `crypto-pii`, `config-posture`, `supply-chain`, `rate-limiting`, `auth-model`, `threat-model`, `tier-thresholds`}. Exactly one concern owns a finding (the deepest-domain owner). `secondary_concerns[]` is a subset excluding the primary.
- `severity_base` = intrinsic class severity (e.g. the CVE's CVSS base). `severity_tier_adjusted` = what the report shows, post tier × concern × amplifier.
- `confidence ∈ [0,1]`: <0.5 → Band 2 "worth reviewing," ≥0.9 → auto-fix eligible (subject to destructive overrides).
- `fix_class` ∈ {`auto`, `stage`, `inline`, `advisory`, `inform-only`}.
- `test_recommendation` + `priority_elevation` populate iff Vibe Test should elevate the corresponding test priority.
- `epss_score` + `kev_listed` optional — populated when available (mostly SCA), null otherwise; not scored in v0.2.
- `tool_of_record` (added for the orchestration pivot) ∈ {`in-house`, `gitleaks`, `trufflehog`, `osv-scanner`, `npm-audit`, `semgrep`, `codeql`, `syft`, …} — records which detector produced the raw finding, so reports can credit the tool and friction-log can compare in-house-vs-external FP rates.

**Ownership matrix** (prevents double-counting; synthesis §4.3 — load-bearing for the weighted score, which dedupes by `id`). The full table is in the synthesis; the rule: deepest-domain owner is `primary_concern`, cross-references go to `secondary_concerns[]`. CVE-2025-29927 fires once: primary=auth-model, secondaries=[dependency-cve, config-posture, owasp-survey].

---

## 7. The three output channels

Consistency across the marketplace matters — same three-render pattern as Vibe Test.

1. **Markdown report** → `<project>/docs/vibe-sec/<command>-report.md`. Runbook-grade, durable. Four-band structure. OWASP-category-grouped subsection renders a finding under each applicable category with an "also tagged as…" annotation (Conflict 10 = A: one finding, all tags rendered — Option B's UX with Option A's dedup semantics).
2. **Terminal banner** → in-chat ANSI. Live curation + education surface. Abbreviated authorization matrix; first-run scan names the operation explicitly ("first run — scanning full git history, this takes a minute" — Decision 9 UX safeguard).
3. **`findings.jsonl` sidecar** → `<project>/.vibe-sec/state/findings.jsonl`. Machine-readable, append-only. The cross-plugin + CI consumption surface.

**Four-band report structure** (the UX differentiator):
1. **Critical / High — action needed now.**
2. **Tier-appropriate but worth reading** — educational surface about security classes at this tier; where 2021→2025 OWASP reclassifications get named (Decision 3).
3. **Tier-inappropriate but if you graduate** — forward-looking guidance for the next-tier story.
4. **Pattern #13 complements** — tools that catch classes the in-house baseline misses; leads with the right tool per detected context (Socket for SCA, Arcjet for LLM routes, Semgrep for injection).

---

## 8. Fix engine + confidence routing + destructive overrides

### 8.1 Confidence-tier routing (synthesis, scope locked)

| Confidence | Route |
|---|---|
| ≥0.90 | **Auto** — apply directly |
| 0.70–0.89 | **Stage** — write to `.vibe-sec/pending/fixes/*.diff`, builder reviews |
| <0.70 | **Inline** — present in-chat with rationale, builder applies manually |

### 8.2 Destructive-action overrides (NEVER auto, regardless of confidence)

These are the line between a tool and a footgun. The litmus review says explicitly: do not loosen under user pressure.

- **Secret rotation** — inline, per-provider runbook card.
- **Auth-logic changes** (any kind) — inline, detailed rationale.
- **JWT / session-secret regeneration** — inline (invalidates live sessions).
- **Auth-middleware adds** to existing routes — stage minimum, never auto.
- **RLS / Firestore-rules / policy changes** — stage as migration, never auto.
- **Password-hash migration** (e.g. MD5 → Argon2id) — inline always.
- **Git history rewrite** (`git filter-repo` / BFG) — inline-runbook-only, never executed (Decision 22). "Rotation is step zero; this is cosmetic."

### 8.3 What `/vibe-sec:fix --auto` is allowed to do (deliberately small)

- Add `.gitignore` entries (`.env`/`*.pem`/`*.key`/`service-account*.json`) + run `git rm --cached` + the non-negotiable "this only prevents *future* commits" banner.
- Additive security headers (missing, not replacing).
- CSP **report-only** (with TODO report-to endpoint — Decision 15). Enforcing CSP is always staged.
- SCA patch/minor-in-range bumps **with lockfile-churn rollback** (>50-line diff → re-stage, Decision 20).
- Add `standardHeaders: true` to existing `rateLimit()`, `trust proxy` when reverse proxy detected, `algorithms:` constraint on `jwt.verify`, `ignore-scripts=true` to `.npmrc`, `permissions: contents: read` to workflows, SHA-pin GitHub Action (when CI passed in last 7 days).

Everything else stages or inlines. Suppression: per-project; after **5** repetitions (matching Vibe Test), prompt once for global.

---

## 9. Vibe Test composition contracts

Additive enhancement, never a dependency. Both directions degrade gracefully when the sibling is absent.

### 9.1 Read: `.vibe-test/state/covered-surfaces.json` (when present + ≤24h)
- `classification.tier` → primary classifier input (inherit unless security-promotion fires; log drift).
- `classification.modifiers[]` → passed through as context modifiers.
- `covered_surfaces.endpoints_with_behavioral_tests[]` → de-prioritize re-audit (doesn't skip — tested ≠ auto-safe).
- `covered_surfaces.endpoints_with_edge_case_tests[]` → stronger de-prioritization.
- `uncovered_surfaces.endpoints[]` → **elevate** admin-endpoint detection + IDOR scanning.
- `detected_stack.{frontend,backend,auth,integrations}[]` → picks CVE feeds, auth pattern libraries, framework OWASP rules; cross-references the platform fingerprint (Decision 10).

### 9.2 Write: `.vibe-sec/state/findings.jsonl`
Append-only, schema §6. Vibe Test reads this at `/vibe-test:generate` time and elevates behavioral/edge-case test priority on findings carrying `test_recommendation` + `priority_elevation`.

### 9.3 Fallback when Vibe Test absent
Run own classifier (`src/scanner/classify-tier.ts`) via the same inventory patterns. Never fail; degrade gracefully.

---

## 10. OWASP Top 10 coverage-honesty section

Ship all 10 concerns, reset the coverage claims to what static analysis can actually deliver. State this plainly in README + report copy — the litmus review is right that security-background users kick the tires hard.

| OWASP category | Vibe Sec v0.2 coverage |
|---|---|
| A01 Broken Access Control | **Static-analysis depth** (auth-model: route inventory, admin gating, tenant isolation, IDOR gated) |
| A02 Cryptographic Failures | **Static-analysis depth** (crypto-pii) |
| A03 Injection | **Static-analysis depth** (survey-level in-house; deep taint-tracking deferred to Semgrep CE / v0.3 — Decision 4) |
| A04 Insecure Design | **Surfaced via threat-model (Layer 3), not statically detected.** Requires human adversarial reasoning |
| A05 Security Misconfiguration | **Static-analysis depth** (config-posture) |
| A06 Vulnerable Components | **Static-analysis depth** (dependency-cve / supply-chain) |
| A07 Auth Failures | **Static-analysis depth** (auth-model) |
| A08 Software/Data Integrity | **Static-analysis depth** (supply-chain + SRI) |
| A09 Logging Failures | **Advisory + PII-in-logs detection only.** No runtime instrumentation |
| A10 SSRF | **Shallow pattern-match for known APIs.** Deep flow-analysis deferred to v0.3 (needs CodeQL-grade tooling) |

Honest headline claim for marketing surfaces: *"Covers A01–A03 / A05–A08 with static-analysis depth. A04 (Insecure Design), A09 (Logging Failures), and A10 (SSRF) require Layer 3 human judgment; the plugin facilitates threat modeling and surfaces hot spots rather than claiming autonomous detection."*

---

## 11. Command surface

9 commands (synthesis Decision 1: `:deps` stays separate, `:scan` not folded into `:audit`). Each labeled deterministic-TS-heavy vs agent-SKILL-heavy.

| Command | Role | TS-heavy vs SKILL-heavy |
|---|---|---|
| `/vibe-sec` | Router — intro + state-aware next-step prompt | **SKILL-heavy** (conversational entry) |
| `/vibe-sec:scan` | Secrets + fast feedback. Defers to gitleaks/trufflehog when present; in-house Layer A/B/C fallback. The promoted CLI lives here | **TS-heavy** (deterministic scan; thin SKILL wrapper) |
| `/vibe-sec:audit` | Full 10-concern tier-calibrated orchestration, four-band report | **SKILL-heavy** orchestration over **TS-heavy** detectors |
| `/vibe-sec:deps` | Fast SCA + supply-chain subset (CVE + lockfile-integrity + pinning; skips SBOM/typosquat-round-trips/threat-model). Defers to OSV-Scanner/Trivy | **TS-heavy** |
| `/vibe-sec:fix` | Confidence-tier-routed remediation + destructive-action overrides | **TS-heavy** routing, **SKILL** for inline-card narration |
| `/vibe-sec:gate` | CI pass/fail vs tier; exit codes 0/1/2 + GH Actions annotations | **TS-heavy** (deterministic, CI-safe) |
| `/vibe-sec:posture` | Read-only tier-aware summary (reads cached state) | **TS-heavy** read + **SKILL** narration |
| `/vibe-sec:threat-model` | STRIDE/DREAD synthesis sink-node; Mermaid + Threat Dragon JSON | **SKILL-heavy** (synthesis) over TS inventory |
| `/vibe-sec:research` | Re-run one concern's domain research (living docs) | **SKILL-heavy** (agent dispatch) |

**Justification for keeping `:scan` distinct from `:audit`** (synthesis Decision 1): builder muscle memory. `npm audit`-style quick checks are a daily workflow; full audits are an occasional event. `:scan` and `:deps` are the fast-path affordances; `:audit` is the full orchestrator. All three share the same underlying detection primitives — the split is UX, not duplicated logic.

---

## 12. Resolved conflicts

The six rulings to encode (the rest of the ten conflicts in `conflicts.md` stay with the synthesis recommendation or are deferred to v0.3).

| # | Conflict | Ruling | One-line rationale |
|---|---|---|---|
| **1** | Authenticated LLM-burn rate-limit severity | **Option A** — authenticated-but-unbounded LLM stays tier-gated (Critical at Customer-facing+, High at Public-facing, informational below) | Only the *unauthenticated* case is everyone-on-the-internet blast radius; authenticated abuse still costs the attacker account creation |
| **2** | Threat-model at Internal tier | **Option C** — opt-in via `/vibe-sec:threat-model`, not auto-included in `:audit` at Internal | Respects "minimize infrastructure lag" + "builder reaches security tired"; keeps the capability accessible without forcing it |
| **4** | AST-aware secret detection in v0.2 | **Option A** — include (Layer C ships) | The 12% FP target is unreachable without AST context for generic-secret-assign patterns; +2MB is acceptable |
| **5** | Secret verification | **Option A** — opt-in via `--verify` flag for v0.2 | Respects no-network-by-default baseline; promote to default-on-top-5 in v0.3 with dogfood data |
| **8** | Research-agent re-run cadence | **Option A** — friction-log-driven, no hard schedule | Pattern #14 already provides the signal; upgrade to per-concern cadence (Option C) in v0.3 if friction-log warrants |
| **9** | Monorepo support | **Option C** — explicit `--app <path>` flag | Meets the minimal monorepo need without first-class auto-discovery cost; WSYATM is single-app so v0.2 dogfood doesn't exercise it |

Carried-from-synthesis (no re-litigation needed): Conflict 3 = Option C (the "no High anywhere at Regulated" hard gate, already in §2.4), Conflict 6 = Option A (honeytokens permanently out-of-scope, surfaced in SECURITY.md), Conflict 7 = Option A (uniform 90-day decay), Conflict 10 = Option A (one finding, all tags rendered — §7).

---

## 13. ASVS / standards mapping

See §2.1 for the tier curve. Additional standards anchoring for the regulated tier:
- **OWASP ASVS L1/L2/L3** — the per-tier requirements floor (Internal/Public-facing/Customer-facing+).
- **NIST SSDF** practices (PO Prepare-the-Organization, PS Protect-the-Software, PW Produce-Well-Secured-Software, RV Respond-to-Vulnerabilities) — the Regulated maturity floor.
- **SBOM** (Syft passthrough, CycloneDX/SPDX) — Regulated, signaled because US EO 14028 + EU Cyber Resilience Act push SBOM down to anyone shipping software meaningfully.
- **OWASP SAMM / NIST SSDF** named as the maturity-model frame the tier ladder implicitly is.

Cite ASVS in report copy and `docs/SECURITY.md`. The point: "regulated tier" resolves to something defensible-by-reference, not aspirational.

---

## 14. Non-goals / deferred to v0.3

| Capability | Status | Why |
|---|---|---|
| Deep A03 injection taint-tracking (dedicated 11th agent) | v0.3 | Inside Semgrep's lane; survey-level + Semgrep CE covers v0.2 |
| Deep A10 SSRF flow-analysis | v0.3 | Needs CodeQL-grade tooling |
| SBOM **generation** (gen, not detection) | v0.3 (`--generate-sbom`) | New emitter with its own correctness bar; Syft passthrough |
| EPSS/KEV wired into severity scoring | v0.3 | Hook exists in schema; scoring-now invites calibration drift |
| Secret verification default-on (top-5 providers) | v0.3 | Opt-in `--verify` in v0.2 |
| Honeytoken / canary generation | **Permanently out** (Conflict 6 = A) | Crosses from audit into active security ops; surface as SECURITY.md recommendation |
| First-class monorepo auto-discovery | v0.3 | Explicit `--app` flag in v0.2 (Conflict 9 = C) |
| Co-author `docs/SECURITY.md` with Vibe Doc | v0.3 | Emit-only for v0.2; co-author when composition contracts stabilize |
| Per-concern research re-run cadence | v0.3 | Friction-log-driven in v0.2 (Conflict 8 = A) |
| Container/IaC scanning (Trivy/Checkov/tfsec deep) | v0.3+ | Trivy surfaced when Dockerfile present; deep IaC is its own discipline |
| License compliance | v0.3+ | Adjacent concern; separate audit |
| Runtime pentest / WAF / observability | Not our category | ZAP/Burp/Datadog/Panther are specialists |
| Python/Go/Rust support | v0.3+ | JS/TS focus for v0.2, matches Vibe Test |
| Autonomous destructive fix application | **Never** | The hard line — propose, never auto-apply destructive changes |

---

## Positioning delta for framework.md (apply by hand — do NOT auto-edit)

The thesis (`packages/vibe-sec/framework.md`) still reads as "we built a security scanner." The pivot needs three edits to land. Summarized here so the human can apply them; this spec deliberately does **not** touch framework.md.

1. **Reframe the Core Claim + Part II Scanner Taxonomy as orchestration, not scanning.** The thesis currently says "an AI plugin that understands those patterns can close most of them faster than a human security review." Add: *the plugin doesn't out-scan gitleaks/Semgrep/OSV-Scanner — it orchestrates them when present and adds the tier-aware classification/severity/report/fix layer on top, falling back to an in-house baseline only when those free tools are absent.* The differentiator is the layer, not the detector.

2. **Add the ASVS/SSDF/SBOM standards anchoring to "What 'Secure Enough' Means" (§Part I) and the tier table.** Map Prototype/Internal/Public-facing/Customer-facing/Regulated to no-floor / ASVS L1 / ASVS L2 / ASVS L3 / ASVS L3 + NIST SSDF + SBOM. The thesis currently picks tier numbers with no external justification; cite ASVS so "regulated tier" stops being aspirational.

3. **Soften the OWASP Top 10 coverage claim (Part II + Part VI) to the honesty reframe in §10.** Replace "Full coverage by category" framing with: A01-A03/A05-A08 static-analysis depth; A04 via threat-model (Layer 3, not statically detected); A09 advisory + PII-in-logs only; A10 shallow pattern-match, deep flow-analysis deferred. The thesis already says "Layer 3 needs the human" for threat modeling — make the Top 10 bullet list match that care.

---

*End of spec. Next: `docs/checklist.md` — sequenced, dependency-aware build plan following synthesis §8's 4-phase order. Phase 1 is TODAY's target.*
