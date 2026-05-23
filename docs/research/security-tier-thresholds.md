# Security-Tier Thresholds + Gating — Research Brief

**Concern #10 of 10 · Vibe Sec v0.2 · Domain-research swarm output**
**Written:** 2026-04-20
**Persona:** Architect — security governance + compliance-tier expert
**Status:** Durable brief; feeds `/spec` synthesis. Living doc — re-runnable via `/vibe-sec:research --concern tier-thresholds`.

> *"The plugin tells you which tier your app needs and what's missing for that tier. Not what's missing for perfection — what's missing for your situation."* — `framework.md`

This concern is not a detector. It is the **meta-concern** — the scoring substrate that turns the other nine concerns into a single, tier-calibrated verdict. Every other research brief ends with a "tier applicability" section. This brief owns the table those sections point at.

---

## Landscape

Compliance and security-maturity frameworks in 2025–2026 converged on a shared structural pattern, then diverged sharply on the **shape** of the tiers. Vibe Sec is designing inside that divergence.

**NIST CSF 2.0 — four Implementation Tiers.** Partial (Tier 1), Risk Informed (Tier 2), Repeatable (Tier 3), Adaptive (Tier 4). NIST is explicit that tiers are *context*, not *rank* — a small nonprofit is correct to stop at Tier 2. CSF 2.0's 2024 refresh added the sixth "Govern" function and pushed maturity descriptions toward outcomes rather than control-counts. The useful thing Vibe Sec inherits: **tiers are a communication artifact, not a pass/fail axis.** Not every org should reach the top. Same applies to apps.

**ISO 27001:2022 — Statement of Applicability as the tier.** ISO doesn't hand you tiers; it hands you 93 Annex A controls and tells you to justify which you implement based on risk assessment. The SoA *is* the per-org applicability matrix. Vibe Sec's concern-applicability matrix is philosophically the same move: here are 10 concerns, here's which ones the tier obliges.

**SOC 2 — scope is the tier.** Security is the only mandatory Trust Service Criterion; Availability / Confidentiality / Processing Integrity / Privacy are add-ons the service org elects based on what it sells. Type I tests design at a point in time; Type II tests operation over 6–12 months. The Type I → Type II transition is effectively a maturity jump — from "the controls exist" to "the controls demonstrably ran." Vibe Sec's Public-facing → Customer-facing SaaS transition mirrors this: from "hardening exists" to "hardening provably applied across the surface."

**CMMC 2.0 — three levels, binary within each.** Level 1 (FAR 52.204-21, 15 requirements, self-attest annually), Level 2 (NIST SP 800-171, ~110 controls, C3PAO assessed every 3 years for most CUI), Level 3 (800-171 + subset of 800-172 APT-focused controls). Mandatory for DoD contracts as of Nov 10, 2025. CMMC is the **"you don't get to negotiate your tier"** model — contract requirements select it. Analog in Vibe Sec: regulated deployment context *forces* the top tier; the builder doesn't pick.

**PCI DSS v4.0 / 4.0.1 — transaction-volume tiers.** Level 1 (>6M/yr, external QSA audit), Level 2 (1–6M), Level 3 (20K–1M), Level 4 (<20K). SAQ type (A, A-EP, D, etc.) is orthogonal and based on payment architecture, not volume — an e-commerce merchant using a hosted iframe completes SAQ A, while one accepting card data in their own DOM completes SAQ D. v4.0's March 31, 2025 hard cutoff made "best practices" mandatory; continuous compliance is now the explicit framing. **Two useful transfers:** (1) tier-by-usage-metric (transactions for PCI, deployment context for Vibe Sec), and (2) architecture-type-as-scoping-modifier (SAQ A vs D, SPA vs full-stack for Vibe Sec).

**How other security tools tier their recommendations.** Snyk combines CVSS base score + Exploit Maturity + Reachability into a Priority Score — severity is the input, not the answer. Semgrep's tiering is *product-structural* (Code / Supply Chain / Secrets) with a CE/Pro split inside each. The industry trend is clear: **raw CVSS is table stakes; the differentiator is context-weighted composition.** Vibe Sec's weighted-score formula needs to live on the context side, not just sum CVSS numbers.

The 2025 vulnerability-prioritization vocabulary also gave us **EPSS** (exploitation probability), **KEV** (CISA's known-exploited list), and as of March 2025 **LEV** (likely-exploited, NIST's probabilistic extension). Vibe Sec v0.2 should not implement EPSS/LEV math — but it should leave a hook for CVE findings to carry EPSS in `findings.jsonl` so future consumers can re-rank. That's a one-field contract decision, cheap to make now.

---

## Detection mechanics

Tier classification is not a detector in the OWASP sense — it's a **signals-fusion** step. Inputs come from the repo, the dependency graph, and ambient deployment evidence. Output is a tier label with a confidence score.

### Inheritance first, scan second

**The primary signal is Vibe Test's `audit.json`**, if present and fresh (≤24h). Per `gap-analysis-as-of-vibe-test-v0.2.md`, the schema at `.vibe-test/state/covered-surfaces.json` exposes `classification.tier` and `classification.modifiers`. When those fields are present, Vibe Sec inherits — the two plugins must not disagree on classification within the same repo. The rule: **if Vibe Test classified, Vibe Sec uses the same tier unless a security-specific signal promotes it.** Promotion is explicit and logged (`"tier_promoted_from": "public-facing", "tier_promoted_to": "customer-facing-saas", "promoted_by": "pii-fields-detected + stripe-integration"`).

When Vibe Test's state is absent or stale, Vibe Sec runs its own scan using the same inventory patterns. The classifier lives at `src/scanner/classify-tier.ts` and consumes the signals below.

### Deployment detection → Public-facing promotion

| Signal | Weight | Signal source |
|---|---|---|
| `vercel.json` present | Strong | Root-level config |
| `netlify.toml` or `netlify.yml` | Strong | Root-level config |
| `.github/workflows/deploy.yml` with production environment | Strong | CI config scan |
| `wrangler.toml` (Cloudflare Workers) with `env.production` block | Strong | Root-level config |
| Fly.io `fly.toml` with non-preview app name | Medium | Root-level config |
| Firebase `.firebaserc` with `production` project alias | Medium | Root-level config |
| Domain in `README.md` referencing a non-`.local`/non-`.dev`/non-`.localhost` URL | Weak | Readme grep |
| Environment variables referencing `NEXT_PUBLIC_*` | Weak | `.env.example` parse |

**Promotion rule:** ≥1 Strong OR ≥2 Medium → promote tier ceiling to at least Public-facing. Weak signals only nudge confidence, never promote alone.

### Payment/PII integration → Customer-facing SaaS promotion

| Signal | Weight |
|---|---|
| `stripe` or `@stripe/stripe-js` in dependencies + `STRIPE_SECRET_KEY` referenced | Strong |
| `braintree`, `paypal-rest-sdk`, `square-connect` | Strong |
| Prisma/Drizzle/TypeORM schema with fields matching `email`, `phone`, `address`, `ssn`, `dob`, `tax_id` (2+) | Strong |
| `@clerk/*`, `@auth0/*`, `next-auth` with database session storage | Medium |
| `mailgun-js`, `@sendgrid/mail`, transactional email SDK | Medium |
| Hashed password columns (`password_hash`, `bcrypt` usage) | Medium |

**Promotion rule:** Stripe/Braintree/Square + PII schema fields → promote to Customer-facing SaaS. Either alone doesn't get you there — a newsletter app with an email field is Public-facing, not Customer-facing SaaS.

### Multi-tenant signals → Customer-facing SaaS confirmation

| Signal | Weight |
|---|---|
| Schema fields: `organization_id`, `tenant_id`, `workspace_id`, `team_id` as FK on user-scoped tables | Strong |
| Middleware named `*tenant*`, `*org*`, `*workspace*` enforcing request-scoping | Strong |
| Clerk's `organizations` feature enabled, Auth0's Organizations feature, WorkOS SDK | Strong |
| Row-level security policies in Postgres / Supabase RLS | Strong |
| Multi-db-per-tenant patterns (database name includes tenant slug) | Medium |

Multi-tenant without Stripe is still SaaS — team/org collaboration apps without payment still warrant the tier. Payment without multi-tenant is typically still Customer-facing SaaS (e-commerce, B2C). Either signal alone, combined with Public-facing promotion, is sufficient.

### Compliance markers → Regulated promotion

| Signal | Weight | Target framework |
|---|---|---|
| HIPAA/PHI comments in schema or routes | Strong | HIPAA |
| `hipaa`, `phi`, `baa` in repo-root README or SECURITY.md | Strong | HIPAA |
| Stripe Connect patterns (`account_id`, marketplace flows) | Medium | PCI-Level-1-adjacent |
| Audit-log tables/schemas (`audit_log`, `event_log` with `actor_id` + `action` + `timestamp`) | Medium | SOC 2 CC7 |
| SOC 2 references in README or package description | Strong | SOC 2 |
| PCI-SAQ-D-level card field handling (not a hosted iframe) | Strong | PCI Level 1/2 |
| Field-level encryption libs (`@aws-crypto/client-node`, Vault SDK) | Medium | HIPAA / PCI / SOX |
| FedRAMP/FISMA mentions, ITAR comments | Strong | Federal |
| GDPR/CCPA consent-management SDK (OneTrust, Cookiebot, Iubenda) | Medium | GDPR / Regulated-lite |

**Promotion rule:** ≥1 Strong OR ≥2 Medium compliance markers → promote to Regulated/Enterprise tier. Otherwise the signal is advisory (adds to `modifiers[]` but doesn't promote).

### Prototype-floor signals (demote or confirm)

These keep the classifier honest in the other direction:
- No `README.md` or README under 500 chars → leans Prototype
- No test files anywhere → leans Prototype
- No deploy config present (nothing from the deployment table above) → Prototype ceiling
- Repo age (first-commit) < 14 days AND < 20 commits total → leans Prototype
- `package.json` description contains "prototype", "demo", "poc", "scratch", "wip" → Internal tool ceiling

### Confidence scoring

Each tier classification emits `confidence ∈ [0,1]`. Low confidence (<0.7) triggers a builder-confirmation prompt in interactive mode; in CI mode, low confidence downgrades to the lower of the two candidate tiers (fail-safe).

---

## False-positive risks

Tier classification errors are **high-blast-radius** because every downstream weight depends on them. Two directions of error, each with different consequences.

**Over-classifying prototype apps as Public-facing.** The most common failure mode. A hackathon app with a `vercel.json` because the builder deployed once to show a friend triggers Public-facing. The consequences: Vibe Sec demands CSP, CORS lockdown, dep audit, auth posture audit, and the report nags the builder about concerns they correctly don't care about yet. Trust erodes. **Mitigations:** (1) require ≥2 Strong signals OR 1 Strong + 2 Medium before promotion; (2) respect explicit builder override in `profile.json` (`shared.deployment_context = "prototype"` hard-caps the tier); (3) surface a "why did I land at this tier?" explanation in the banner — the builder can read the signal list and correct the override.

**Under-classifying staging envs as prototype.** A staging environment for a serious app may genuinely look prototype-ish: no production domain in README, `.env.example` with dummy values, `NODE_ENV=staging` in deploy config. But the code path running in staging is the same path that will run in prod, so security posture needs to be prod-grade now. **Mitigations:** (1) `.env.example` referencing any third-party API keys (Stripe, Firebase, AWS) bumps the confidence threshold; (2) presence of `DATABASE_URL` referencing any non-localhost host promotes to at least Internal; (3) Vibe Test's `audit.json` wins when present — if the sibling plugin says Public-facing, don't second-guess it.

**Regulated-tier false promotion.** A README that mentions "HIPAA" in a "we plan to be HIPAA-ready someday" aspirational sentence triggers Regulated. That's wrong and expensive. **Mitigation:** HIPAA/PCI/SOC2 markers in README are *Medium*, not Strong, unless paired with a schema-level or dependency-level signal. A `baa` directory in the repo, a `@aws-crypto/client-node` import, an actual audit-log table — these are Strong. Marketing copy is Medium at best.

**Multi-tenant misread.** A user-settings page that has a `team_id` field because the builder scaffolded it from a template but never uses it is not a multi-tenant app. **Mitigation:** require 2+ tenant-scoped tables AND middleware/RLS evidence, not just a schema field.

**Drift between Vibe Test and Vibe Sec.** The two plugins disagreeing on tier is the worst UX outcome — the builder gets contradictory posture reports. **Rule:** Vibe Sec always reads Vibe Test's classification first. When they differ, Vibe Sec emits a `tier_drift_note` finding explaining why it promoted or demoted. The builder sees one voice with one footnote, not two arguments.

**Commitment:** tier-classification false-positive rate ≤12% (matches the scope.md cross-board commitment). Over-promotion errors are counted; under-promotion errors are counted; both count equally against the 12%.

---

## Remediation patterns

Tier-threshold findings split into two categorically different shapes.

**Tier-mismatch findings (architectural, inline).** When the classifier says "you're Public-facing but these signals say Customer-facing SaaS," the finding is *about classification itself*. These are always routed **inline** per the confidence-tier matrix in `scope.md`. No auto-fix ever. The remediation is a conversation:

> **Vibe Sec:** Detected Stripe integration + PII schema fields (email, phone, billing_address). This promotes you from Public-facing to Customer-facing SaaS. Your current weighted score (68%) clears Public-facing (70%) but misses Customer-facing SaaS (80%) by 12 points. Three options:
>
> 1. **Accept promotion** — we re-rank your findings at the new tier; you'll see new concerns elevated (PII handling, multi-tenant isolation checks even if single-tenant for now).
> 2. **Reject promotion** — tell us why (e.g., "payment is sandbox only, production launch is 6 weeks out"). We honor the override in `profile.json` and the promotion won't re-fire without explicit re-audit.
> 3. **Dual-render** — show me both tier reports side-by-side so I can plan the graduation.

The output of this conversation is a durable decision in `profile.json` under `plugins.vibe-sec.tier_override` plus a dated rationale. Future `/vibe-sec:audit` runs respect it until expiry or explicit builder revisit (Pattern #4 memory decay applies — tier overrides decay at 90 days and re-prompt).

**Threshold-miss findings (concern-specific, routed normally).** When the classifier is correct but the weighted score falls short, the finding decomposes into per-concern failures. Remediation here routes through the concern-specific fix pipelines from the other nine briefs. The gate output lists: *"to clear the Public-facing threshold (70%), you need to close X concern-1 findings, Y concern-5 findings, Z concern-6 findings — here's the minimum-effort path."* This mirrors Vibe Test's "what would it take to pass" language from their gate skill.

**No auto-fix ever on tier promotion decisions.** Same hard line Vibe Test drew on destructive changes, same rationale: the builder owns strategic calls. The plugin proposes, never imposes.

---

## Pattern #13 complements

Compliance-focused tooling in 2025–2026 is a large, well-capitalized market segment — and it sells something Vibe Sec explicitly does not sell. The distinction matters for the four-band report's *"tools that belong in your toolbelt"* section.

**Drata** — Compliance automation built for teams that demand more precision + DevOps integration. Supports 20+ frameworks including SOC 2, ISO 27001, HIPAA, PCI. Strong for tech-savvy teams with complex environments. Price-point: mid-market upward.

**Vanta** — 35+ frameworks. Known for ease of use and faster onboarding. Often the first-time-compliance choice for startups. Cross-mapped templates + built-in gap analysis.

**Secureframe** — 35+ frameworks including FedRAMP and NIST. Leads in breadth of integrations, adds AI tools for complex environments.

**Key framing for Vibe Sec's report:** these tools sell **compliance CERTIFICATION** — they collect evidence, run continuous monitoring, generate audit packages auditors consume. Vibe Sec surfaces **security GAPS** at the repo level. These are complementary, not competitive. The four-band report's Band 4 ("tools that belong in your toolbelt") cites them as the natural next purchase once the app graduates to Customer-facing SaaS or Regulated tier. Vibe Sec is the builder-sustainable pre-requisite; Drata/Vanta/Secureframe are the auditor-facing deliverable.

Specifically, when Vibe Sec classifies an app as Customer-facing SaaS with SOC 2 aspirations, Band 4 reads something like: *"Once you've closed the Critical/High findings above and you're ready to start evidence collection for an auditor, consider Drata (strong DevOps integration), Vanta (fastest onboarding), or Secureframe (broadest framework coverage). We'll stay in the repo. They'll run in your cloud + HR + IT surface."*

Other complements worth naming for the tier-threshold concern specifically:
- **CISA KEV feed** — for CVE findings, cross-reference known-exploited; elevates severity regardless of CVSS base score
- **FIRST.org EPSS API** — for CVE findings, attach exploit-probability; future consumers can re-rank
- **Aikido / Jit / Arnica** — "compliance-lite" SaaS that targets the same post-scope pre-enterprise band; worth naming but lower priority than the Big Three above

---

## Tier applicability

This concern IS the tier model itself. It is **meta-applicable across all five tiers** — at every tier, tier-classification and weighted-score gating run. The depth varies:

| Tier | Tier-concern depth |
|---|---|
| Prototype / hackathon | Lightweight: classify, check floor, report. No weighted-score failure ever — exit 0 is structural at this tier. |
| Internal tool | Classify, compute weighted score, gate on 55% threshold. Single-signal promotions warned but honored with confirmation. |
| Public-facing | Classify, compute weighted score, gate on 70% threshold. Signal disagreements trigger inline conversation. |
| Customer-facing SaaS | Classify, compute weighted score, gate on 80%. Tier-drift between runs is logged as a beacon event. |
| Regulated / enterprise | Classify, compute weighted score, gate on 90%. Tier promotion/demotion is a logged decision requiring builder confirmation. Pattern #12 beacon emitted on every run. |

The meta-nature means this concern is also the **consolidation point** for all other concern research briefs. Every brief's "tier applicability" section terminates in a row of this matrix. The synthesis agent's first job is normalizing those per-concern matrices against the master tier ladder defined here.

---

## Cross-concern dependencies

Tier thresholds consume **weighted inputs from every other concern.** This is the math substrate of the plugin.

**Per-concern weights (proposed, subject to `/spec` synthesis-round refinement):**

| # | Concern | Weight | Tier-scaling factor |
|---|---|---:|---|
| 1 | Dependency CVE audit (SCA) | 1.0 | Constant across tiers — CVEs matter everywhere |
| 2 | Secret detection | 1.0 | Constant — leaked secret = leaked secret |
| 3 | OWASP Top 10 categorical | 0.9 | Scales: 0.5 Prototype → 1.0 Public-facing+ |
| 4 | Crypto / PII handling | 0.9 | Scales: 0.0 Prototype → 1.0 Customer-facing SaaS+ |
| 5 | Config-level posture (CSP/CORS/headers) | 0.7 | Scales: 0.2 Prototype → 1.0 Public-facing+ |
| 6 | Supply chain hardening | 0.6 | Scales: 0.1 Prototype → 1.0 Regulated |
| 7 | Rate limiting + abuse protection | 0.7 | Scales: 0.0 Prototype → 1.0 Customer-facing SaaS+ |
| 8 | Auth model static analysis | 0.9 | Scales: 0.3 Prototype → 1.0 Public-facing+ |
| 9 | Threat model generation | 0.5 | Scales: 0.0 Prototype → 1.0 Regulated |
| 10 | Tier thresholds (this concern) | — | Meta — it IS the denominator |

**Formula (proposed, matching Vibe Test's shape):**

```
raw_score = Σ(concern_weight × tier_scaling × concern_pass_fraction)  for concerns 1..9
max_score = Σ(concern_weight × tier_scaling × 1.0)                   for concerns 1..9 at this tier
weighted_score = (raw_score / max_score) × 100
```

Where `concern_pass_fraction ∈ [0, 1]` is the per-concern plugin's honest self-report (concern-5 might say "you have 4 of 7 required headers present" = 0.571).

**Applicability gates** (mirrors Vibe Test): at Prototype tier, concerns 4/7/9 scale to 0.0 and literally do not appear in either numerator or denominator. This keeps the math clean — a Prototype app can score 100% while genuinely having no rate-limiting and no threat model.

**Input contract:** each concern's skill emits `concern_pass_fraction` + `raw_findings_by_severity` + `confidence` into `.vibe-sec/state/concern-<N>.json`. The weighted-score calculator at `src/scoring/weighted-score.ts` is the **single shared implementation** consumed by classifier + `/audit` + `/gate` + `/posture`. Same pattern as Vibe Test — one pure function, many callers, no drift.

**Severity amplifier.** A concern with one Critical finding cannot score 100% even if its numeric pass fraction is high. Proposed rule: any Critical finding hard-caps concern_pass_fraction at 0.5, High caps at 0.8. This prevents the "97% clean, but one committed AWS root key" pathology from producing a passing score.

---

## Open questions for synthesis

### The load-bearing question: does Vibe Test's 30/55/70/80/90 curve transfer?

**My position: No. Security needs a different curve.** Specifically: **30 / 50 / 75 / 85 / 95.**

Argument:

**1. The Prototype floor should be low and permissive (30% holds).** At the hackathon tier, the only real failure modes are "committed secrets" and "critical CVE in direct deps." Everything else is genuinely fine to defer. 30% is a generous floor and it should stay — matching Vibe Test here is correct because at this tier the two plugins are measuring similar things (smoke tests ≈ basic secret scan, both low-bar).

**2. Internal tool drops from 55 → 50.** Security for internal tools is fundamentally different from testing for them. An internal tool can skip performance tests and still be trustworthy; an internal tool with weak auth is a pivot point for an attacker who compromises a single employee laptop. The relevant security concerns at Internal are fewer (2, part of 3, part of 8) but each weighs heavily. Lowering the threshold acknowledges that the denominator is smaller — fewer concerns apply — so the *per-concern* bar needs to be higher to feel meaningful. 50% against a narrow denominator is a stricter bar than 55% against a wide one.

**3. Public-facing jumps from 70 → 75.** This is the **threshold-boundary-of-truth**. It's the tier where an app is genuinely exposed to the internet, where an OWASP Top 10 failure is reachable by unauthenticated strangers. Vibe Test at 70% for Public-facing is a reasonable bar because missing a few edge-case tests at this tier is recoverable. Missing rate-limiting, CSP, or an auth check at this tier is *not* recoverable — those are exploitable on day one. Security needs to bite harder. 75% forces the builder to close the categorical gaps (you can't just have partial coverage of OWASP A01 — either you enforce authz consistently or you don't).

**4. Customer-facing SaaS rises from 80 → 85.** Testing can reasonably accept 80% for SaaS because the remaining 20% is usually edge-case polish. Security at SaaS has a harder floor: once you're handling PII and payment, there's no "edge-case polish" in crypto-at-rest or multi-tenant isolation. You either have RLS or you don't. You either encrypt PII columns or you don't. 85% pushes the builder to close the binary-pass/fail concerns (4, 7) almost completely before shipping.

**5. Regulated rises from 90 → 95.** This is where Vibe Sec most needs to diverge. At regulated tier, the compliance industry sells 100% — Drata and Vanta don't let you ship "90% HIPAA-compliant." The reason Vibe Sec isn't 100% is we're not a certification tool (see framework.md scope: "Not a compliance certification tool"). But we should be *closer* to the certification bar than testing's 90%, because the concerns at this tier are regulatory obligations, not quality improvements. 95% acknowledges: at this tier, there are no optional concerns, and near-complete pass-rate is the honest bar.

**Summary of the argument:** testing's tier curve assumes concerns scale roughly linearly with tier — more tests at higher tiers, all more important. Security's tier curve assumes concerns scale **non-linearly** — the concerns that *apply* narrow and deepen, and the penalty for partial coverage steepens at each tier because security partial-coverage is often exploitable binary-pass/fail. A steeper curve matches the problem shape.

### Secondary open questions for `/spec`

1. **Should the tier-scaling factors in the weights table be research-synthesized from the other 9 briefs, or stated prescriptively here?** Leaning: stated here as a starting point, with per-concern briefs allowed to propose corrections in synthesis.
2. **Severity amplifier exact math** — is the 0.5-cap-on-Critical proposed above too harsh? Too lenient? One committed AWS root key = 0.5 ceiling feels right; one Critical CVE in a dev-only dep feels harsh. Maybe the amplifier takes dev-vs-prod dep status as input.
3. **EPSS / LEV integration timing** — v0.2 leaves the hook in `findings.jsonl` only, or wires through to scoring? Leaning: hook only. Scoring-time EPSS weighting is v0.3.
4. **Tier-override decay period** — 90 days proposed above, matching Pattern #4 default. Should regulated-tier overrides decay faster (30 days)? The cost of a stale regulated-tier override is high.
5. **Dual-render output** — when the builder rejects tier promotion, should the audit show both tiers' posture, or only the active tier's? Leaning: only active, with a `--dual` flag for exploration.

---

## Gate exit-code contract

The `/vibe-sec:gate` contract mirrors Vibe Test's gate with security-specific additions:

```
Exit 0 — PASS: weighted_score ≥ tier_threshold AND no Critical findings unresolved
Exit 1 — FAIL: weighted_score < tier_threshold OR any Critical finding unresolved (threshold breach)
Exit 2 — TOOL ERROR: scanner failed, deps missing, state corrupt, classifier confidence <0.5 in CI mode
```

**Key differences from Vibe Test's gate:**
- Vibe Test exit 1 is purely threshold-based. Vibe Sec exit 1 has an **unconditional override on Critical findings** — a committed AWS key fails the gate even at Prototype tier with exit 1, not 0. The floor concerns (1, 2) have hard severity gates that bypass the weighted score.
- Vibe Sec exit 2 includes classifier low-confidence as a tool-error condition in CI, because silent misclassification in CI is worse than a loud failure the builder can investigate.

**Auto-detection of CI mode** — `GITHUB_ACTIONS=true` OR `--ci` flag, matching Vibe Test. Emits `::error::` / `::warning::` annotations and writes summary markdown to `$GITHUB_STEP_SUMMARY`. Annotations include:
- `::error::` for any Critical finding (always fatal)
- `::error::` for threshold breach at Public-facing or higher
- `::warning::` for threshold breach at Internal tier (non-fatal for exit code if no Criticals)
- `::warning::` for tier-drift-since-last-run (surfaces classification changes as a signal)

**Local mode banner** — includes the "what would it take to pass" section, enumerating the minimum closures by concern to clear the threshold. Builder-facing language, curated, no stack traces.

**Co-invocation:** same Pattern #13 pairing as Vibe Test — if `superpowers:verification-before-completion` is present, `/vibe-sec:gate` owns the tier-threshold decision and defers per-task completion verification to that skill.

---

## Graduating to next tier — guidance format

Mirror of Vibe Test's "graduating to next tier" section with security-specific content. Lives in `docs/SECURITY.md` (the builder-sustainable runbook) and regenerates on `/vibe-sec:audit` when tier transitions are detected.

Structure (fixed sections, content auto-generated per tier pair):

1. **You're at X, heading toward Y.** One paragraph naming the current tier + the next tier + the typical signal that triggers the graduation (e.g., "you're planning to open the app beyond the internal team").
2. **New concerns that activate at Y.** Enumerated list of concerns whose tier-scaling factor jumps from <0.5 to ≥0.7 at Y. Each with a one-sentence "why now."
3. **Existing concerns that deepen at Y.** Concerns already applicable but with elevated bar (e.g., OWASP at Public-facing is "categorical audit"; at Customer-facing SaaS it's "categorical audit + multi-tenant authz matrix").
4. **Minimum viable closures.** Ranked list of the smallest set of findings to close that will clear the Y threshold, sorted by effort.
5. **Tools to consider adding.** Band-4-style recommendation list calibrated to Y — at Customer-facing SaaS introduce Drata/Vanta/Secureframe options; at Regulated also introduce specialized SCA (Snyk paid), runtime WAF, and third-party pen-test cadence.
6. **When to re-audit.** Cadence recommendation — Customer-facing SaaS recommends weekly `/vibe-sec:audit` + CI gate; Regulated recommends daily CI gate + monthly deep `/audit` + quarterly `/threat-model` refresh.

This content auto-updates — the graduating guidance is a living artifact, not a one-shot generation. Pattern #14 wins logging captures "builder graduated successfully from X to Y" as a signal that the guidance worked.

---

## Tier-transition detection logic

Beyond the static classification at audit time, Vibe Sec needs to detect when an app is **in motion** between tiers. This is a cross-run comparison against beacon history.

**Detection signals (cross-run):**
- Deployment config added or materially changed since last audit (`vercel.json` appeared, Netlify env changed from preview to production)
- Dependency addition in one of the high-signal categories (Stripe SDK appeared, Clerk with organizations enabled)
- Schema migration adding PII fields or tenant-scope fields
- README update referencing compliance frameworks not previously mentioned
- First occurrence of `NODE_ENV === 'production'` gating in code

**Detection signals (single-run, ambient):**
- Classifier confidence of tier X, but 2+ signals supporting tier X+1 present
- Comments or TODOs in code referencing the next tier ("// TODO: add rate limiting before going public")
- PR or branch name containing "launch", "public", "open-beta", "ga"

**Transition output:** when a transition is detected, Vibe Sec emits a `tier_transition_detected` beacon + a top-of-banner callout + an auto-opened "graduating to next tier" section of `SECURITY.md`. The gate does not fail on in-transit state — the transition is informational until the signals consolidate enough for full promotion (typically the next full audit after the deployment config actually ships).

---

## Summary — what `/spec` consumes from this brief

1. **Threshold curve proposal:** 30 / 50 / 75 / 85 / 95 (vs. Vibe Test's 30 / 55 / 70 / 80 / 90).
2. **Weighted-score formula:** Σ(weight × tier-scaling × pass-fraction) / Σ(weight × tier-scaling), with severity amplifier caps.
3. **Per-concern weights + tier-scaling table** (proposed starting point; synthesis refines).
4. **Signal-to-tier promotion rules** for classifier detection mechanics.
5. **Gate exit-code contract** (0/1/2) with Critical-finding override at Prototype.
6. **Tier-override decay policy** — 90-day default, 30-day for Regulated (open question).
7. **`findings.jsonl` field additions** — `tier_scaling_at_current_tier`, optional `epss_score`, optional `kev_listed`.
8. **Graduating-guidance auto-generation structure** — six fixed sections, content tier-aware.
9. **Tier-transition detection** — cross-run + ambient signals, informational until consolidation.
10. **False-positive commitment** — ≤12% on tier-classification, counted both directions.

This brief's synthesis bullets should dominate the resolution round — every other concern's research outcome eventually rides on the weights + curve locked here.

---

## Sources

- [NIST CSF 2.0 (CSWP 29)](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [NIST CSF Implementation Tiers (ManageEngine)](https://www.manageengine.com/log-management/compliance/nist-csf-tiers.html)
- [NIST CSF 2.0 Complete Guide 2026 (Isora GRC)](https://www.saltycloud.com/blog/nist-csf-2-0-complete-guide-2026/)
- [2025 Trust Services Criteria for SOC 2 (Secureframe)](https://secureframe.com/hub/soc-2/trust-services-criteria)
- [SOC 2 Compliance 2025 Guide (ComplyJet)](https://www.complyjet.com/blog/soc-2-compliance-guide)
- [SOC 2 Type 2 Overview (Drata)](https://drata.com/learn/soc-2/type-2-overview)
- [CMMC 2.0 Final Rule (Davis Wright Tremaine)](https://www.dwt.com/blogs/privacy--security-law-blog/2025/09/defense-department-cybersecurity-cmmc-final-rule)
- [CMMC 2.0 Three Levels (ISI Security)](https://isidefense.com/blog/understanding-the-3-levels-of-cmmc-2-0)
- [PCI DSS Compliance Levels 2025 (VistaInfosec)](https://vistainfosec.com/blog/pci-compliance-levels-for-merchants-service-providers/)
- [PCI Compliance Checklist 2026 DSS 4.0.1 (Strictly)](https://strictlyzero.com/announcements/payments-announcements/pci-compliance-checklist-2026-the-merchants-guide-to-dss-4-0-1/)
- [ISO 27001 Controls 2025 Guide (Thoropass)](https://www.thoropass.com/blog/mastering-iso-27001-controls-your-2025-guide-to-information-security)
- [ISO 27001:2022 Explained 2025 (Teleport)](https://goteleport.com/blog/iso-iec-27001-2022-explained/)
- [Drata vs Vanta vs Secureframe (Drata)](https://drata.com/blog/secureframe-vs-vanta-vs-drata)
- [SOC 2 Tools Vanta/Drata/Secureframe 2025 (SecureLeap)](https://www.secureleap.tech/blog/soc-2-tools-vanta-drata-secureframe-guide-2025)
- [Snyk Severity Levels](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/severity-levels)
- [Semgrep vs Snyk Technical Comparison 2026 (Konvu)](https://konvu.com/compare/snyk-vs-semgrep)
- [CVSS vs EPSS vs KEV vs SSVC vs LEV (Picus Security)](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof)
- [CVSS and EPSS for Prioritization (SecOps Solution)](https://www.secopsolution.com/blog/combining-cvss-and-epss-to-prioritize-vulnerability)
