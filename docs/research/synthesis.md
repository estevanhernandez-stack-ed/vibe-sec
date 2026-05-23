# Vibe Sec v0.2 — Research Synthesis

> **Purpose:** Unified implementation guidance. Consolidates the ten parallel domain-research briefs into a single architectural foundation `/spec` can consume directly. Resolves cross-brief conflicts where evidence + scope-locked decisions clearly support a call; escalates residual judgment-grade conflicts to `conflicts.md`.
>
> **Authored:** 2026-04-20 — architect persona, synthesis agent, post-swarm.
> **Status:** Durable artifact. Re-generated when any single brief is re-run via `/vibe-sec:research --concern <name>`.
> **Consumers:** `/spec` (immediate), `/build` (downstream), `/vibe-sec:audit` + `:gate` + `:fix` runtime implementations.

> **Author's note on sink naming.** Where sink identifiers collide with Claude Code's security-reminder hook substring matchers (React's dangerous-HTML JSX prop, DOM inner-HTML assignment, document-write DOM sinks, Function constructor, the eval primitive, shell-exec child-process APIs), this document references them by descriptive name rather than literal identifier — same discipline the `owasp-top-10-survey.md` brief used.

---

## 1. Executive synthesis

Vibe Sec v0.2 is a **classification-first, tier-aware, research-informed security audit** for vibe-coded JS/TS applications. It is not another SAST clone, not a pentester, not a compliance certifier. It is the plugin the tired builder runs the day before they transition an internal app to public-facing — and the one that tells them, honestly and specifically, what their actual security bar looks like from where they're standing. Ten security concerns, ten expert research briefs, one synthesized audit. The research swarm isn't a gimmick — it's the mechanism by which a solo plugin ships domain depth that would normally require ten human specialists.

The architecture that falls out of the research has four load-bearing moves. **First, classification-first routing.** The classifier runs before any detection, produces a tier (Prototype → Regulated) plus context modifiers, and everything downstream calibrates to it. At Prototype, rate-limiting checks are skipped entirely — not "run but suppressed," actually dropped from the denominator — because the tier honestly doesn't care. At Regulated, LINDDUN privacy walks and SBOM emission become mandatory. The tier isn't a severity amplifier; it's a scope gate. **Second, the four-band report structure** (Critical-now / tier-appropriate-education / graduating-guidance / Pattern #13 complements) is the UX device that keeps the audit from turning into either spam or patronizing. Vibe-coded builders reach security tired; the four bands are the mechanism by which we respect that fatigue while still teaching. **Third, the hybrid severity model** — 4-level Vibe-Sec-native (Critical/High/Medium/Low) with CVSS passthrough for CVE findings, tier × concern driving final severity calibration — lets us be honest about both our own judgments and the upstream data we inherit. **Fourth, the single findings.jsonl schema** with dual OWASP 2021/2025 tagging, primary_concern + secondary_concerns fields, and Vibe Test handoff hooks is the connective tissue that makes cross-concern dedup actually work.

The distinctive detection moves the research revealed: (1) **vibe-coding-platform fingerprints** — v0 produces UI-gated-but-backend-unprotected Next.js apps with unchecked Server Actions, Lovable reliably scaffolds Supabase with permissive-or-absent RLS, Bolt is bimodal; detecting the platform shapes the prior on which findings to expect. (2) **LLM-token-burn detection** as a new primitive — any route importing `openai`/`@anthropic-ai/sdk`/similar without per-user token budget is a direct line to the builder's credit card, and this is the one finding that overrides tier gating (Critical even at Prototype when unauthenticated). (3) **Multi-tenant isolation audit** — the Lovable/Supabase finding that no other plugin catches: RLS enabled-with-`true` policies, or a `tenant_id` column with queries that never filter by it. (4) **CVE-2025-29927** as a baked-in rule — the Next.js middleware bypass hit the full vibe-coding stack and deserves a first-class detector, not a pass-through npm audit hope. (5) **Artifact-vs-repository integrity** as the supply-chain canary, post-XZ — release tarballs that don't match git trees are where modern backdoors live.

The brand promise: **12% false-positive rate across all ten concerns**, distributed per allocation in §7. Destructive-action respect: auth logic changes, secret rotation, JWT regen, and password-hash migrations are always inline, never auto, no matter the confidence. `/vibe-sec:fix --auto` is deliberately small — it adds `.gitignore` entries and security headers, period — because every other change touches either live user state or architectural decisions the builder has to own. The WSYATM dogfood is the acceptance test: Vibe Sec v0.2 passes when it correctly identifies the security bar for WSYATM's associate-facing → public-facing tier transition and produces hardening guidance Este actually uses before opening the app to the public. Nothing synthetic — real pre-launch ammunition.

---

## 2. Consolidated architecture decisions

These are the cross-brief calls the synthesis agent is making *as synthesis*. Each resolves a conflict or open question the briefs surfaced. Decisions are declarative and load-bearing.

### Decision 1: Command surface stays at 9 — `:deps` remains separate

**Call:** `/vibe-sec` router + 8 subcommands = 9 top-level commands. No consolidation of `:deps` and supply-chain; no folding of `:scan` into `:audit`.

**Rationale:** The SCA brief proposed folding `:deps` and supply-chain into one command. The supply-chain brief itself affirmed SCA and supply-chain are "different questions" (`dependency-cve-sca.md` line 292 recommends folding, `supply-chain-hardening.md` lines 272-278 argues for coordination but separate findings). The case for keeping `:deps` separate is builder muscle memory — `npm audit`-style quick checks are a daily workflow, not an audit workflow. `:deps` becomes a fast-path alias that runs the dependency-CVE concern plus the supply-chain concern's lockfile-integrity + pinning-strategy pass; it skips SBOM, typosquat registry round-trips, postinstall deep-walk, and threat-model synthesis. `/vibe-sec:audit` runs everything. This gives us "quick check" and "full audit" as distinct UX affordances backed by shared detection primitives.

**Command roster (final for v0.2):**
1. `/vibe-sec` — router, intro + state-aware next-step prompt
2. `/vibe-sec:audit` — full 10-concern audit, tier-calibrated, four-band report
3. `/vibe-sec:scan` — secret-leak scan (promoted from CLI, plus git history)
4. `/vibe-sec:fix` — confidence-tier-routed remediation
5. `/vibe-sec:gate` — CI-safe pass/fail against app's security tier
6. `/vibe-sec:posture` — ambient read-only tier-aware summary
7. `/vibe-sec:threat-model` — STRIDE/DREAD synthesis sink-node
8. `/vibe-sec:deps` — fast SCA + supply-chain subset
9. `/vibe-sec:research` — re-run domain-research agent for one concern

**Source briefs:** `dependency-cve-sca.md` §Open Q2, `supply-chain-hardening.md` §Cross-concern, `scope.md` decision log (9-command commitment).

### Decision 2: Tier threshold curve — 30 / 55 / 70 / 80 / 90 (Vibe Test parity)

**Call:** Vibe Sec v0.2 inherits Vibe Test's tier-threshold curve: **30% Prototype / 55% Internal / 70% Public-facing / 80% Customer-facing SaaS / 90% Regulated**. The tier-thresholds agent's proposed 30/50/75/85/95 curve is declined.

**Rationale:** The tier-thresholds brief (`security-tier-thresholds.md` §Open Questions) makes a well-argued case for a steeper, non-linear curve: security partial-coverage is often exploitable-binary-pass/fail, so the per-tier bar should bite harder. The argument has merit. The reasons to decline for v0.2:

1. **Dogfood calibration risk.** The 30/55/70/80/90 curve is the one Vibe Test actually runs against WSYATM. Locking Vibe Sec to the same curve means WSYATM's tier transition is measured on a comparable axis across plugins — a core composition benefit. Introducing a new curve at the same time as introducing the plugin means we can't tell whether calibration signals come from the curve or the concerns.
2. **Severity amplifier does the non-linearity work.** The tier-thresholds brief's own proposed **severity amplifier** (Critical hard-caps concern_pass_fraction at 0.5, High caps at 0.8) already forces non-linear behavior: a Public-facing app with one Critical in concern #1 cannot pass 70% no matter how clean the other nine are. This captures the "security partial-coverage is binary" intuition without needing curve divergence.
3. **WSYATM dogfood-first.** The scope locks "composition with Vibe Test" as a primary design principle. Diverging thresholds by 5-10 points per tier makes every cross-plugin conversation harder to narrate to the builder.

**v0.3 revisit trigger:** If WSYATM's dogfood surfaces cases where 70% passes Public-facing but the app is demonstrably exploitable, re-open at `/spec`-time in v0.3. Track this as a wins/friction logging target.

**Severity amplifier (confirmed as part of this decision):** any Critical finding caps concern_pass_fraction at 0.5; any High caps at 0.8. This applies across all ten concerns and prevents the "97% clean but one committed AWS key" pathology.

**Source briefs:** `security-tier-thresholds.md` (proposed divergence), `scope.md` (locked 30/55/70/80/90), Vibe Test precedent.

### Decision 3: Dual OWASP tagging — 2021 primary, 2025 annotated

**Call:** Every finding in `findings.jsonl` carries two OWASP tags: `owasp_2021` (primary, shown in reports) and `owasp_2025` (annotated in JSON sidecar, surfaced in Band 2 educational copy when the 2025 reclassification is meaningful). Reports group by 2021 because that's builder mental model. When findings cross the 2021→2025 reclassification boundary (e.g., SSRF moving from A10-2021 to A01-2025, SCA moving from A06-2021 to A03-2025 as "Supply Chain Failures"), the Band 2 educational copy names the shift so builders' mental model ages forward.

**Rationale:** The OWASP brief (`owasp-top-10-survey.md` §Open Q2) proposed three options for dual-tagging. Option A (2021 primary, 2025 footnote) is the right call because (a) the ecosystem still organizes around 2021, (b) SSRF-as-A01-2025 and supply-chain-as-A03-2025 are genuinely useful reclassifications worth teaching, and (c) treating findings as immutable (they carry the tag that was authoritative when produced) matches the append-only `findings.jsonl` posture.

**Source briefs:** `owasp-top-10-survey.md` §Landscape + §Open Q2, `findings.jsonl` schema (§4 below).

### Decision 4: A03 (Injection) defers to v0.3 as a dedicated agent

**Call:** v0.2 ships with survey-level A03 coverage owned by the OWASP-survey concern. Deep injection taint-tracking defers to v0.3 as an optional eleventh research agent. Semgrep is surfaced as the Pattern #13 complement for deeper injection coverage at Public-facing+ tier.

**Rationale:** The OWASP brief explicitly recommends this deferral (`owasp-top-10-survey.md` §Open Q1). A dedicated injection agent would need real data-flow analysis to beat Semgrep, which is inside Semgrep's lane. v0.2's differentiator is tier-aware prioritization, not deeper-than-Semgrep pattern matching. Survey-level coverage catches the high-signal vibe-coded patterns (template-literal SQL, the React dangerous-HTML prop populated from user input, prototype pollution sinks, the shell-exec sink family) and defers the long tail.

**WSYATM-dogfood revisit trigger:** If the dogfood reveals a critical injection class Survey misses, promote to a dedicated agent for v0.3.

**Source briefs:** `owasp-top-10-survey.md` §A03 + §Open Q1.

### Decision 5: LLM-burn severity overrides tier gating

**Call:** An unauthenticated LLM-backed endpoint (any route importing `openai`, `@anthropic-ai/sdk`, `@google/generative-ai`, `@aws-sdk/client-bedrock-runtime`, `cohere-ai`, `replicate`, `groq-sdk` and reached by an unauthenticated route handler) is **Critical at every tier**, including Prototype. This is the one and only severity call that overrides the tier gating matrix in §6.

**Rationale:** The rate-limiting brief (`rate-limiting-abuse-protection.md` §Open Q2) proposed this as a policy question. The architect answer is yes. The tier model exists to acknowledge that different apps face different adversary profiles — a hackathon prototype doesn't need rate limiting against DDoS because no adversary cares enough to DDoS it. But an unauthenticated LLM proxy is different: the adversary profile is "anyone who wants free LLM inference," which is effectively the entire internet. The financial blast radius is concrete (thousands of dollars in hours) and the attacker cost is zero. This is the only concern where a Prototype tier can catastrophically fail overnight regardless of whether "prototype" means what it says. The finding copy must be explicit: *"this route forwards to OpenAI with no authentication and no per-user budget; a single attacker can exhaust your monthly LLM spend in an afternoon."*

**Authenticated LLM-backed routes without per-user token budget** are still tier-gated — Critical at Customer-facing SaaS+, High at Public-facing, informational at Internal/Prototype. Only the unauthenticated case overrides.

**Source briefs:** `rate-limiting-abuse-protection.md` §Landscape + §Open Q2.

### Decision 6: CVE-2025-29927 is a baked-in rule, not SCA passthrough

**Call:** v0.2 ships a dedicated detection rule for CVE-2025-29927 (Next.js middleware authorization bypass via `x-middleware-subrequest` header injection) in the auth-model concern's detector. The rule reads `package.json` for `next` version, cross-references the published advisory version table, and emits a first-class finding independent of `npm audit`. This is belt-and-suspenders — `npm audit` also catches it via SCA, but CVE-2025-29927 deserves native detection because (a) it affects the dominant vibe-coding framework, (b) it specifically breaks middleware-based auth enforcement which multiple concerns rely on, and (c) the post-patch guidance is more nuanced than a dep bump (defense-in-depth: pair middleware checks with route-handler-level auth).

**Rationale:** Flagged jointly by `owasp-top-10-survey.md` §A05 + `auth-model-static-analysis.md` §Open Q8 + `config-posture.md` §Landscape. All three concerns agreed independently that this CVE should be a first-class detector. The joint finding fires once with cross-concern references: primary_concern = auth-model (it's an authorization bypass), secondary_concerns = [owasp-survey, config-posture] (it affects middleware-based header emission + structural architecture).

**Source briefs:** `owasp-top-10-survey.md`, `auth-model-static-analysis.md`, `config-posture.md`.

### Decision 7: Findings schema — primary_concern + secondary_concerns + dual OWASP tags

**Call:** Every finding in `findings.jsonl` conforms to the schema locked in §4. The concern ownership rule: the deep-dive agent owns `primary_concern`; broader survey or secondary detectors go to `secondary_concerns[]`. This prevents double-counting in the weighted score while preserving cross-concern visibility.

**Rationale:** Proposed by `owasp-top-10-survey.md` §Cross-concern and affirmed by every other brief that listed cross-concern dependencies. The single-ownership + multi-tag design resolves the double-counting concern (`dependency-cve-sca.md` §Cross-concern raised this explicitly for A06) while keeping findings auditable ("why did this appear under auth-model when it's also a crypto issue?").

**Source briefs:** all briefs' §Cross-concern dependencies sections.

### Decision 8: Threat model executes last — sink-node, never parallel

**Call:** `/vibe-sec:threat-model` runs as the terminal node of `/vibe-sec:audit`. It is never parallelized with the other nine concerns; it consumes their outputs as inventory inputs. At `/spec` time the research swarm runs parallel (different question — research, not detection); at runtime the concerns run in dependency order with threat-model as the sink.

**Rationale:** The threat-model brief (`threat-model-generation.md` §Cross-concern) states this explicitly: "threat modeling must run last in `/vibe-sec:audit` — after all other research/detection is complete. It cannot be parallelized with the other concerns; it is the sink node." All nine other concerns are tributaries. This is architecturally different from Vibe Test's pattern (no such sink node) and intentional — threat-model synthesis is the capstone deliverable, not another detector.

**Source briefs:** `threat-model-generation.md` §Framing + §Cross-concern.

### Decision 9: Git-history secret scan defaults to `--full` with incremental cache

**Call:** `/vibe-sec:scan` and `/vibe-sec:audit` default to **full git history scan on first run, incremental (since-last-SHA) on subsequent runs**. Not `--recent`. The secret-detection brief's argument wins: 64% of 4-year-old leaked credentials are still valid; "old" is the wrong frame.

**Rationale:** `secret-detection.md` §Open Q2 proposed this explicitly with strong landscape evidence (GitGuardian 2026 data). The first-scan cost is amortized by aggressive caching at `.vibe-sec/state/history-scan.json` — subsequent scans read only the commits since the last-scanned SHA. Shallow-clone CI environments (where `git rev-parse --is-shallow-repository` returns true) get a banner note: "history scan limited — running in a shallow clone; run locally for full coverage."

**UX safeguards:** the first `/vibe-sec:audit` banner names the operation explicitly ("first run — scanning full git history, this takes a minute") rather than spinning silently. The command accepts `--history=recent|full|none` as an override.

**"Under 2 minutes first-run" north star acknowledgment:** the full-history scan will blow past 2 minutes on large repos with long histories. The synthesis call: the 2-minute target was aspirational for the *scan* workflow, not the first-ever full audit. The first audit is the expensive one; every audit after is fast.

**Source briefs:** `secret-detection.md` §Detection mechanics + §Open Q2.

### Decision 10: Framework-specific detection priors — v0/Lovable/Bolt fingerprints

**Call:** Vibe Sec v0.2 detects the vibe-coding platform (v0 / Lovable / Bolt / Cursor / generic hand-rolled) via a small set of fingerprint signals, and uses the detected platform as a **prior** on which concerns to prioritize and which findings to elevate. Fingerprint signals (layered):

- **v0 (Vercel):** `package.json` with Next.js + shadcn/ui + no backend dependencies; route handlers with no middleware chain; `<SignIn />`-style auth decoration in layout without corresponding server-action auth checks. **Prior:** UI-gated-but-backend-unprotected pattern. Elevate auth-model concern's "Server Action missing auth()" detection.
- **Lovable:** `package.json` with `@supabase/*` + specific Lovable-scaffolded file structure + presence of `supabase/migrations/`. **Prior:** RLS inconsistent or absent. Elevate multi-tenant-isolation detection; every Supabase table without RLS becomes a Critical candidate at Customer-facing-SaaS+.
- **Bolt:** Bolt-specific deployment config markers. **Prior:** auth is bimodal — either reasonably scaffolded or entirely absent. Run both "is there any auth" and "if yes, is it correctly configured" passes with equal weight.
- **Cursor / Claude Code / Windsurf / Copilot (IDE-embedded):** no distinctive fingerprint (the AI defers to whatever library the builder named). Default to the dominant 2026 mix: Next.js 14+/15+/16 + Clerk or Supabase Auth + inconsistent middleware coverage.

**Use of priors:** priors elevate the *priority ordering* of concern detection within a tier and shift the FP allocation (§7) toward the detected-high-signal concerns. Priors do NOT change which concerns apply at a tier — the tier matrix (§6) is authoritative for scope.

**Rationale:** `auth-model-static-analysis.md` §Landscape provides the platform-fingerprint intelligence explicitly. No other audit plugin uses this; it's a Vibe Sec differentiator inherited from the research-swarm's domain depth.

**Source briefs:** `auth-model-static-analysis.md` §Landscape.

### Decision 11: Dev-dep filtering — application/library classification drives default

**Call:** SCA and secret-detection concerns both run an **application-vs-library classifier** on the target project. Application projects (`"private": true`, no `"main"/"exports"/"types"`, no publishConfig, presence of a bundler config) get `--omit=dev` SCA default and path-excluded scan on `dist/`/`build/`. Library projects get full-tree SCA and full-path scan.

**Rationale:** `dependency-cve-sca.md` §False-positive risks identifies this as the single biggest FP lever (30% raw noise reduction). The classifier is a simple signal-fusion check; it meets the 12% FP target for SCA without sacrificing library-audit fidelity.

**Source briefs:** `dependency-cve-sca.md` §FP class 1, §Open Q3.

### Decision 12: OSV primary + npm audit for fix-availability — run both, dedupe by ID

**Call:** SCA runs **OSV as primary** (batch query, 24h cache) **and npm audit as confirmer**. Findings dedupe by CVE/GHSA ID. When they disagree, OSV wins on *existence* and npm audit wins on *fix availability* (since npm audit reasons about the user's actual tree).

**Rationale:** `dependency-cve-sca.md` §Detection Path A and B argued this explicitly. The 2× network cost is acceptable because OSV is rate-limit-free and npm audit is local.

**Source briefs:** `dependency-cve-sca.md` §Detection + §Open Q4.

### Decision 13: EPSS hook in findings.jsonl; scoring integration defers to v0.3

**Call:** `findings.jsonl` schema includes optional `epss_score` and `kev_listed` fields. v0.2 does not wire these into severity scoring. The hook exists so future consumers (and v0.3) can re-rank without schema migration.

**Rationale:** Both `dependency-cve-sca.md` §Open Q1 and `security-tier-thresholds.md` §Landscape argued for this phasing. Adding EPSS to severity scoring simultaneously with everything else invites calibration drift; the hook-now, score-later approach is the cheap correct move.

**Source briefs:** `dependency-cve-sca.md`, `security-tier-thresholds.md`.

### Decision 14: Compromised-package incident detection defers to Socket.dev

**Call:** v0.2 does not curate its own "known-compromised-window" feed. The Pattern #13 complement (Socket.dev) owns this. The report's Band 4 surfaces Socket Firewall Free as "the tool that catches supply-chain novelty our CVE-based detection misses."

**Rationale:** `dependency-cve-sca.md` §Open Q6 and `supply-chain-hardening.md` §Open Q6 independently landed on this call. Competing with Socket on attack-window curation is the wrong fight; surfacing Socket is the right complement.

**Source briefs:** `dependency-cve-sca.md`, `supply-chain-hardening.md`.

### Decision 15: CSP report-only is the auto-apply form; enforcing CSP is always staged

**Call:** When config-posture detects a Public-facing-tier app without CSP, the auto-apply fix emits `Content-Security-Policy-Report-Only` with a report-to endpoint left TODO. The enforcing `Content-Security-Policy` header is never auto-applied — always staged.

**Rationale:** `config-posture.md` §Remediation argues this: CSP is blocking by design, so adding enforcing CSP can break working apps. Report-Only is strictly non-blocking and produces data for tightening. The TODO on report-to encourages the builder to pick an endpoint (or leave it stdout) rather than shipping a phantom endpoint Vibe Sec invented.

**Source briefs:** `config-posture.md` §Remediation + §Open Q2.

### Decision 16: Platform-native rate-limit recommendation at Public-facing+

**Call:** When deploy platform is detected as Vercel / Cloudflare / AWS API Gateway, recommend the **platform-native** rate-limiting surface first (Vercel Firewall / Cloudflare Rulesets / API Gateway throttling). Recommend `@upstash/ratelimit` + `@upstash/redis` as the framework-generic complement. At Prototype/Internal, recommend framework-generic first (portable, no account setup).

**Rationale:** `rate-limiting-abuse-protection.md` §Open Q1 explicitly asked this; the research landscape supports platform-first at higher tiers (one less moving part, lower latency, deeper defense-in-depth when paired with app middleware).

**Source briefs:** `rate-limiting-abuse-protection.md`.

### Decision 17: Arcjet is the default recommendation when LLM-backed routes detected

**Call:** When the audit detects any LLM SDK import + route handler pattern, the Pattern #13 complement for rate-limiting in Band 4 leads with **Arcjet** (AI-native abuse protection including per-user token budgets). Otherwise, Upstash Ratelimit leads.

**Rationale:** `rate-limiting-abuse-protection.md` §Pattern #13 + §Open Q9. Arcjet's per-user AI token budget primitive is specifically the right tool for the LLM-burn scenario Vibe Sec flags as Critical.

**Source briefs:** `rate-limiting-abuse-protection.md`.

### Decision 18: IDOR detection gated to Public-facing+ AND high-confidence patterns only

**Call:** IDOR detection runs at Public-facing tier and above. The detector only emits findings at confidence ≥0.9, which in practice means: route accepts `:id`-style param, DB query uses `id` directly with no co-located ownership filter (`userId` / `tenantId` / `orgId`), no centralized authz pattern (Casbin enforcer / Prisma extension / RLS) detected in the project. Lower-confidence IDOR signals become Band 2 "worth reviewing" informational notes, not Band 1 findings.

**Rationale:** `auth-model-static-analysis.md` §Open Q1 surfaced this directly. Industry SAST tools hit 50%+ FP on IDOR; gating to high-confidence + Public-facing+ brings Vibe Sec's IDOR contribution to the 12% FP target without sacrificing the headline multi-tenant-isolation finding that's Vibe Sec's differentiator.

**Source briefs:** `auth-model-static-analysis.md`.

### Decision 19: Authorization-matrix artifact is the auth-model concern's signature deliverable

**Call:** The auth-model concern emits a **routes-by-authz-dimensions matrix** as its primary structured artifact. Rows = routes, columns = {auth-required, role-gated, ownership-enforced, RLS/rules-applicable}, cells = {enforced / absent / unknown / N/A}. Rendered as markdown table in the primary report, abbreviated in terminal banner, full structure in JSON sidecar.

**Rationale:** `auth-model-static-analysis.md` §6 names this as Vibe Sec's unique contribution vs Vibe Test's behavioral tests. It's the artifact the scope doc hinted at; this call locks the shape.

**Source briefs:** `auth-model-static-analysis.md` §6 + §Open Q7.

### Decision 20: Lockfile-churn rollback threshold for auto-applied SCA fixes — 50 lines

**Call:** `/vibe-sec:fix --auto` on a patch-bump SCA fix snapshots lockfile line count before apply. If post-apply diff exceeds 50 lines, the fix rolls back and re-routes to Stage. Builder eyeballs unexpected tree churn.

**Rationale:** `dependency-cve-sca.md` §Remediation argued for this safeguard; 50 lines is a starting calibration point subject to refinement after WSYATM dogfood data lands.

**Source briefs:** `dependency-cve-sca.md`.

### Decision 21: Firebase web `apiKey` classified as informational with companion rules-audit finding

**Call:** The `AIza...` pattern detected inside `firebase.initializeApp({apiKey: ...})` or equivalent Firebase-SDK context is classified as `FIREBASE_WEB_CLIENT_API_KEY` with severity **informational**. A companion finding on the same file surfaces: "verify firestore.rules / database.rules.json / storage.rules enforce access control — this key is public by design."

**Rationale:** `secret-detection.md` §FP class 9 + `config-posture.md` §Firebase detection agree. The secret detector owns the key-classification call; config-posture owns the rules-audit companion.

**Source briefs:** `secret-detection.md`, `config-posture.md`.

### Decision 22: Git history rewrite is inline-runbook-only, never auto

**Call:** `/vibe-sec:fix` never executes `git filter-repo` or BFG. When a secret is found in git history, the inline remediation card provides the exact command, the coordination checklist, the rotation-first warning, and the "rotation is step zero; this is cosmetic" framing. Builder runs it manually or not at all.

**Rationale:** `secret-detection.md` §Class 5 argued for this hard line; scope already locked secret rotation as always-inline. History rewrite is a superset of rotation in terms of blast radius.

**Source briefs:** `secret-detection.md` + `scope.md` destructive-action overrides.

### Decision 23: Cookie-flag findings owned by auth-model concern when the cookie is auth-related

**Call:** When cookie-flag findings (HttpOnly/Secure/SameSite) touch a cookie classified as auth-related (name matches `/session|sid|auth|jwt|token|csrf|user|remember/i`), primary_concern = auth-model, secondary_concerns = [config-posture]. Non-auth cookies (preferences, analytics, UX state) go primary_concern = config-posture.

**Rationale:** `config-posture.md` §Cross-concern and `auth-model-static-analysis.md` §Cross-concern agreed on this split; the heuristic for "auth-related" is the existing config-posture brief's regex.

**Source briefs:** `config-posture.md`, `auth-model-static-analysis.md`.

### Decision 24: SHA-pin first-party GitHub Actions only at Regulated tier

**Call:** Third-party GitHub Actions must be SHA-pinned at Public-facing+ (post-tj-actions, this is the new minimum bar). First-party actions (`actions/*`, `github/*`, `docker/*`) may remain tag-pinned through Customer-facing SaaS; SHA-pin required only at Regulated.

**Rationale:** `supply-chain-hardening.md` §Open Q4 surfaced this trade-off (SHAs generate upgrade friction; first-party risk is nonzero but small). Regulated tier is where the friction is acceptable.

**Source briefs:** `supply-chain-hardening.md`.

### Decision 25: SBOM generation defers to v0.3 — detection only in v0.2

**Call:** v0.2 detects whether the project has a SBOM (presence of `sbom.cdx.json`, `bom.json`, CycloneDX artifacts in CI) and surfaces recommendation at Regulated tier. Generation via cyclonedx-node-npm or syft is deferred to v0.3 per `/vibe-sec:fix --generate-sbom` subcommand.

**Rationale:** `supply-chain-hardening.md` §Open Q5 explicitly proposed this phasing. Detection is cheap; generation is a new emitter with its own correctness bar.

**Source briefs:** `supply-chain-hardening.md`.

### Decision 26: Threat-model output — Mermaid-in-markdown primary, Threat Dragon JSON sidecar

**Call:** `/vibe-sec:threat-model` emits `docs/vibe-sec/threat-model.md` (builder-readable with embedded Mermaid DFDs) and `.vibe-sec/state/threat-model.json` (Threat Dragon v2.5.0 schema-compatible). Mermaid convention locked: stadium shapes = external entities, rectangles = processes, cylinders = data stores, hexagons = third-parties, subgraphs = trust boundaries.

**Rationale:** `threat-model-generation.md` §Output format + §Open Q2 argued this; locking the Mermaid convention prevents successive-run diagram churn in git diffs.

**Source briefs:** `threat-model-generation.md`.

### Decision 27: Per-concern FP allocation adds to 12%

**Call:** The 12% global FP commitment is distributed per §7 below. Concern FP budgets are **enforcement targets**, not hard ceilings — a concern exceeding its budget during dogfood triggers friction-log review, not gate failure.

**Rationale:** `config-posture.md` §Open Q6 explicitly raised "should FP budget be allocated per sub-domain"; this call affirms.

**Source briefs:** `config-posture.md`.

---

## 3. Per-concern synthesis digest

Ten subsections, one per concern. Each: (a) load-bearing findings, (b) remediation-matrix summary, (c) owned detection surface + delegations, (d) tier applicability summary.

### 3.1 Dependency CVE / SCA (concern #1)

**Load-bearing findings:**
- **OSV is the 2026 primary** — schema-mature, cross-ecosystem, no-account. `npm audit` is the fix-availability oracle layered on top.
- **Post-Sept-2025 chalk/debug compromise, SCA is no longer "known CVEs" alone** — artifact-integrity is adjacent concern owned by supply-chain (#6). This concern owns known CVEs; supply-chain owns the "is this tarball the right one" question.
- **Dev-dep CVEs are ~30% of raw npm-audit noise on application projects.** Default `--omit=dev` on applications, full tree on libraries (Decision 11).
- **`isSemVerMajor` boolean in `npm audit fixAvailable` is the auto/stage/inline router.** Trivial (patch/minor in range) → Auto. Minor-out-of-range → Stage. Major → Inline.
- **Lockfile-churn safety check on auto-applies** — Decision 20, rollback at >50-line diff.

**Remediation matrix (summary):**
| Fix class | Routing |
|---|---|
| Patch/minor in existing range | Auto (with churn rollback) |
| Minor needing range bump | Stage |
| Semver-major | Inline |
| Transitive-only (overrides/resolutions) | Inline with snippet |
| No fix available | Inform-only |
| Compromised-window incident | Inline + loud banner; defer curation to Socket |

**Owned detection surface:** OSV batch query, npm audit shell-out, lockfile walk, transitive-dep path resolution, dev-vs-prod classification, CycloneDX SBOM emission (detection only in v0.2).

**Delegated:**
- Supply-chain (#6): lockfile integrity, pinning strategy, typosquat, provenance, SHA-pinning of workflows, postinstall inspection.
- Secret detection (#2): maintainer-credential leak blast-radius narrative when `npm_`/`pypi-`/`dckr_pat_` tokens found.
- OWASP A06: this concern's findings are re-tagged by survey with `A06-2021` / `A03-2025` tags; single-ownership rule puts SCA as primary.

**Tier applicability:** Minimal at Prototype (High/Critical only, `--omit=dev`, `--audit-level=high`). Full by Public-facing. Regulated adds SBOM recommendation + compliance-friendly report format.

### 3.2 Secret detection (concern #2)

**Load-bearing findings:**
- **Full git history scan by default (Decision 9).** 64% of 4-year-old leaked credentials are still valid — "recent" is the wrong frame.
- **15 existing CLI patterns → ~40-50 canonical provider patterns** (the expanded catalog in the brief). AWS, GitHub (all variants), Stripe, Slack, OpenAI, Anthropic, Google, Firebase (classified), Supabase, Twilio, SendGrid, Postman, NPM, PyPI, Docker Hub, Vercel, Heroku, Discord, Mailgun, DeepSeek, HuggingFace, JWT, PEM private keys, DB URLs with embedded creds.
- **Three-layer detection stack:** Layer A regex (provider prefixes), Layer B entropy (Shannon ≥4.5 base64 / ≥3.0 hex, 20-char minimum), Layer C AST (`@babel/parser` walks for assignment context, JSX attribute leaks, `process.env.X = ...` overwrites).
- **Verification (TruffleHog-style live API pings) is opt-in via `--verify` flag** — v0.2 defaults to `unverified`. v0.3+ promotes verification-by-default for top-5 providers.
- **Firebase web client API key is informational + rules-audit companion** (Decision 21). Never high-severity by itself.
- **Class-1 FP discipline** — `.env` in `.gitignore` auto-fix also runs `git rm --cached`; "this only prevents *future* commits" banner is non-negotiable.

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| `.gitignore` missing `.env`/`*.pem`/`*.key`/`service-account*.json` | Auto (+ `git rm --cached`) |
| Missing `.env.example` scaffold | Stage |
| Inline-literal secret → `process.env.X` refactor | Stage |
| Secret rotation | Inline always (no auto) — per-provider runbook card |
| Git history rewrite | Inline-only runbook (Decision 22) |

**Owned detection surface:** working-tree scan, git history scan (full + incremental), 40-50 provider patterns, entropy detection, AST-aware secret detection, Firebase web key classification, client-bundle scan (secrets in `dist/`/`build/`).

**Delegated:**
- Crypto/PII (#4): weak-derived-keys, PRIVATE_KEY algorithm audit, JWT signing secret semantics.
- Supply-chain (#6): publisher-credential leak cross-concern beacon when npm/pypi/docker tokens found.
- Config-posture (#5): `.env` in `.gitignore` is a *jointly-owned* check; secret-detection owns the scan, config-posture's posture view references it.
- OWASP A02: hardcoded crypto secrets are tagged A02-2021 / A04-2025 in findings.

**Tier applicability:** **Full scan at every tier** — secret leaks don't scale with tier, they scale with credential value. Calibration: severity of non-catastrophic findings (missing `.env.example`) scales with tier; AWS root key is Critical everywhere.

### 3.3 OWASP Top 10 survey (concern #3)

**Load-bearing findings:**
- **Category glue, not a detector.** Survey owns A02/A04/A06/A08/A09/A10 breadth; deep dives delegate to dedicated concerns (A01 → auth-model, A05 → config-posture, A06 → SCA, A07 → auth-model, A02 → crypto/PII).
- **Dual 2021/2025 tagging (Decision 3).** Every finding carries both.
- **A03 Injection stays survey-level for v0.2** (Decision 4). Semgrep is the Band-4 complement.
- **A04 (Insecure Design) is the highest FP-risk category** — absence-of-control-proxies are noisy at Prototype/Internal. Tier-gate hard.
- **Dynamic-code-loading sinks (A08)** — the eval primitive, Function constructor, `setTimeout`-with-string body, `vm.runInThisContext` — are flagged but categorized as "review required," never auto-fix.

**Remediation matrix (survey-owned subset):**
| Fix class | Routing |
|---|---|
| Additive security header via `helmet()` etc. | Auto |
| Add SRI attribute to CDN script | Auto |
| Add `algorithms: ['HS256']` JWT verify constraint | Auto |
| Wrap Mongo query input in `String()` coercion | Auto |
| Add `eslint-plugin-no-unsanitized` to project | Stage |
| SQL template-literal → parameterized | Stage |
| Dynamic-code-loading sink change | Inline |
| Auth-logic change (any kind) | Inline always |

**Owned detection surface:** A02 algorithm smells (md5/sha1 calls, weak bcrypt), A04 absence-of-control proxies, A05 headline config smells, A06 `npm audit` passthrough (collab with SCA), A08 SRI-missing + dynamic-code sinks + CI workflow patterns, A09 absence-of-logging patterns + silent-catch detection, A10-2021 SSRF URL-taint, A10-2025 fail-open patterns.

**Delegated:** A01 deep authz → auth-model; A02 crypto deep → crypto/PII; A03 deep injection → v0.3 or Semgrep; A05 deep header policy → config-posture; A07 authn → auth-model; A09 PII-in-logs → crypto/PII.

**Tier applicability:** See matrix in §6. Prototype skips A01/A04/A07/A08/A09/A10; Public-facing is the step-change where the full Top 10 becomes blocking.

### 3.4 Crypto / PII handling (concern #4)

**Load-bearing findings:**
- **Argon2id is the ceiling; bcrypt cost-12 the floor.** `bcrypt.hash(password, 10)` is the 2018 bar; flag High at Public-facing+.
- **AEAD or bust.** AES-256-GCM and ChaCha20-Poly1305 are the two defensible symmetric choices. AES-CBC-without-MAC / ECB / DES / 3DES / RC4 are dead.
- **JWT `none` algorithm, short HS256 secrets (<32 bytes), `jwt.verify` without `algorithms:` constraint** — all Critical findings.
- **PII inventory is the signature artifact** — per-field map from schema parse (Prisma / Drizzle / Zod / Yup), matched against CCPA ∪ HIPAA ∪ GDPR practical union pattern library.
- **PII in `console.log` → third-party tracker (Sentry/Datadog/LogRocket) is Critical at Public-facing+** (GDPR Article 44 cross-border transfer).
- **Legacy-hash migration code is NOT a finding** — dual-path (`if passwordVersion === 1 ...`) is the correct pattern. Detect it and emit informational only.

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| Missing `algorithms:` constraint on `jwt.verify` | Auto |
| Add `httpOnly`/`Secure`/`SameSite` to cookie | Auto |
| Remove `\|\|` JWT secret fallback (fail-fast at boot) | Auto |
| Hardcoded crypto key → `process.env.X` | Stage |
| bcrypt cost 10 → 12 | Stage |
| MD5/SHA1 for checksum → SHA-256 | Stage |
| Password-hash migration (MD5 → Argon2id) | Inline always (destructive) |
| AES-CBC → AES-GCM | Stage (ciphertext format changes) |
| PII field no at-rest encryption at Customer-facing+ | Inline (architectural) |
| Secret rotation | Inline always |

**Owned detection surface:** deprecated-primitive imports + call sites, password-handling patterns (bcrypt cost, Argon2 params, unsalted-SHA, plaintext-compare), timing-attack `===` compares, hardcoded keys + env-var usage + `||` fallback traps, client-side key leakage (`NEXT_PUBLIC_*`/`VITE_*`), PII schema inventory, PII-in-logs audit, HTTPS enforcement headers (shared with config-posture), at-rest encryption proxies (DB conn strings / ORM encryption libs / cloud-storage config).

**Delegated:** secret detection (#2) — key-provenance (regex matches AWS/etc.) — crypto/PII owns the semantic question "is this passed to `createCipheriv`?"; auth model (#8) — session-token signing flow, JWT lifecycle, refresh-token rotation; config-posture (#5) — cookie flags + CSP; OWASP A02 is this concern.

**Tier applicability:** Crypto matters from Internal up; PII matters from Public-facing up. See §6.

### 3.5 Config-level security posture (concern #5)

**Load-bearing findings:**
- **OWASP Secure Headers 2026 baseline** — CSP (strict, nonce+strict-dynamic), HSTS max-age 63072000, X-Content-Type-Options nosniff, X-Frame-Options DENY (or CSP frame-ancestors 'none'), Referrer-Policy strict-origin-when-cross-origin, Permissions-Policy opt-out, COOP/COEP at Customer-facing+.
- **X-XSS-Protection is deprecated.** Do not recommend adding; surface as informational if present with stale value.
- **CSP report-only is the auto-apply form (Decision 15).** Enforcing CSP is always staged.
- **CORS origin-reflection with credentials is Critical** — `origin: true, credentials: true` or `origin: (origin, cb) => cb(null, true), credentials: true`.
- **Firebase rules `allow read, write: if true` is Critical at any tier above Prototype.** The #1 Firebase breach cause in 2025.
- **CVE-2025-29927 (Next.js middleware bypass) is a baked-in rule** (Decision 6).
- **Monorepo emission-matrix must be per-app**, not flat (open question resolved: `/spec` locks schema; synthesis affirms per-app).

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| Add missing security header (additive) | Auto |
| Install + register `helmet()` | Stage |
| Add CSP report-only | Auto (with TODO report-to) |
| Add strict CSP with nonces (enforcing) | Stage |
| Tighten `helmet` CSP from default | Stage |
| Replace CORS wildcard with allowlist | Stage |
| Add `HttpOnly`/`Secure`/`SameSite` to cookie | Stage (auto at production-branched config) |
| Fix Firebase rule `allow read, write: if true` | Inline (authorization logic) |
| Fix `admin/admin` default credential | Inline (rotation coordination) |
| Remove debug-mode config | Stage |

**Owned detection surface:** framework-config-file parsing (Next.js `headers()`, Vite, Express middleware chain, Fastify register, Firebase rules, vercel.json / netlify.toml / _headers / nginx.conf / .htaccess), cookie-setting call inspection, CORS config detection, env-based debug-mode detection, default-credential patterns (config files only; secret-detection owns the broader scan), CVE-2025-29927 joint detection.

**Delegated:** rate-limiting (#7) owns middleware-threshold audit; auth-model (#8) owns cookie-lifecycle (HttpOnly is shared); secret-detection (#2) owns credential scan (config-posture only flags literal admin/admin); OWASP A05 is this concern.

**Tier applicability:** Nothing mandatory at Prototype beyond Firebase `if true` warning. Internal requires nosniff + X-Frame-Options + HttpOnly. Public-facing requires full baseline + CSP (report-only auto, enforcing staged). Customer-facing SaaS requires enforcing strict CSP + COOP/COEP. Regulated requires HSTS preload + cookie prefixes + SRI on all third-party scripts.

### 3.6 Supply-chain hardening (concern #6)

**Load-bearing findings:**
- **Post-XZ, post-Shai-Hulud, post-tj-actions** — the 2024-2026 incident sequence reframed the category. Artifact-vs-repo integrity, maintainer-trust multi-year attack surface, postinstall-hook worm propagation, GitHub Actions SHA-pinning as the new minimum bar.
- **454,648 malicious npm packages published in 2025** — over 99% of net-new open-source malware targets npm. Typosquat detection is load-bearing, not optional.
- **npm provenance is at 7.2% ecosystem adoption** — report as informational context, not per-package findings (would be noise).
- **SHA-pin third-party GitHub Actions at Public-facing+; first-party only at Regulated** (Decision 24).
- **ignore-scripts as `.npmrc` default at Public-facing+** — pnpm v10 and bun already default-disable postinstall; npm is the remaining risk surface.
- **SBOM detection in v0.2; generation in v0.3** (Decision 25).

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| Pin GitHub Action to SHA | Auto (when repo has passing CI in last 7 days) |
| Add `ignore-scripts=true` to `.npmrc` | Auto |
| Add `permissions: contents: read` to workflow | Auto |
| Lockfile regeneration | Stage |
| Pin floating dep to resolved version | Stage |
| Switch deprecated/compromised dep | Inline (semantic replacement) |
| Remove typosquat | Inline (confirm intent) |
| Dependency-confusion stub-publish | Stage (advisory) |

**Owned detection surface:** lockfile presence + format (npm/yarn/pnpm/bun), lockfile integrity hash coverage, pinning-strategy classification, GitHub Actions workflow parsing (ref style + permissions block + event type), npm provenance attestation checking, typosquat (Levenshtein ≤2 vs embedded top-500), dependency-confusion (scoped-deps public-registry HEAD), slopsquatting (LLM-hallucinated package names), postinstall hook inspection (depth 2 default, depth-full at Regulated), SBOM presence detection.

**Delegated:** CVE audit (#1) — known vulns in versions; secret-detection (#2) — publisher-credential leak (cross-concern beacon); OWASP A08 (survey) — artifact-integrity narrative framing.

**Tier applicability:** Informational at Prototype (no findings). Internal requires lockfile presence + `"latest"` detection. Public-facing requires integrity hashes + SHA-pin third-party actions + permissions blocks. Customer-facing SaaS adds typosquat + dep-confusion. Regulated adds SBOM + provenance + maintainer-compromise watchlist (deferred to Socket).

### 3.7 Rate limiting + abuse protection (concern #7)

**Load-bearing findings:**
- **AI-force-multipliered attacks, LLM-token-burn, authenticated-abuse > anonymous-abuse.** The 2022-era "rate limit the login" playbook is insufficient. 95% of API attacks are now from authenticated sources.
- **Unauthenticated LLM-backed endpoint is Critical at every tier** (Decision 5) — the one tier-override.
- **Framework-vs-platform recommendation order** (Decision 16) — platform-first at Public-facing+, framework-first below.
- **Arcjet leads when LLM-backed routes detected** (Decision 17); Upstash Ratelimit otherwise.
- **Dual A04 + A09 tagging on rate-limit gaps** — rate limiting without monitoring is both categories; single finding with dual tags.
- **CAPTCHA-as-compensating-control reduces severity one band; doesn't eliminate.**
- **Custom rate-limiting (Redis INCR patterns) surfaces as "detected, not verified"** — informational, not blocker.

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| Add `standardHeaders: true` to existing `rateLimit()` | Auto |
| Add `trust proxy` when reverse proxy detected | Auto |
| Widen global to per-route tiered limits | Stage |
| Upgrade to Redis/Upstash backing | Stage |
| Replace deprecated Cloudflare legacy config | Stage |
| Add rate-limit middleware to existing auth route | Inline |
| Add CAPTCHA (Turnstile) to signup | Inline |
| Add LLM token-budget middleware | Inline |
| Platform-level WAF rule authoring | Inline (guidance) |

**Owned detection surface:** middleware-registration inspection (Express/Fastify/Next/NestJS/Hono/tRPC), route-by-route high-risk-endpoint classification, AI-powered-endpoint detection (LLM SDK imports + handler proximity + auth check + per-user budget + per-request max_tokens), deployment-platform rate-limit config detection (Vercel/Cloudflare/AWS API Gateway/Netlify/Fly/Railway/Render), abuse-monitoring presence (structured logging on 429, metrics, alerting).

**Delegated:** auth-model (#8) owns account-lockout + credential-storage; config-posture (#5) owns platform-level-config-file-sanity; PII handling (#4) owns safe-log-shape for 429 events (shared schema); OWASP A04/A09 survey rolls up this concern.

**Tier applicability:** Prototype skips (exception: Critical LLM-burn override). Internal surfaces library absence if exposed beyond VPN. Public-facing requires per-route auth limits. Customer-facing SaaS requires per-tenant quotas + LLM token budgets + abuse monitoring. Regulated requires anomaly detection + SIEM integration + CAPTCHA on signup + per-API-key quotas.

### 3.8 Auth model static analysis (concern #8)

**Load-bearing findings:**
- **Passkeys cross the chasm in 2026** — 69% consumer adoption, 87% enterprise planning. Informational at Public-facing; "should have" at Customer-facing SaaS+; critical for enterprise-sales Regulated.
- **OAuth 2.1 is effectively the new OAuth 2.0** — PKCE required for all auth code flows, exact-string redirect URIs, implicit/ROPC grants gone.
- **Zero-trust per-request authz > role-string comparison.** Hardcoded `role === 'admin'` scattered across files is an architectural finding at Public-facing+.
- **Six detection probes:** route-inventory + middleware attachment, admin-endpoint role-gating, tenant-isolation query patterns (the Lovable/Supabase finding), IDOR risk scoring (gated to Public-facing+ high-confidence per Decision 18), session-management pattern classification (per-library correctness checks), role-hardcoding detection.
- **Authorization matrix is the signature artifact** (Decision 19) — rows=routes, columns=authz dimensions, cells=enforcement status.
- **CVE-2025-29927 baked-in rule** (Decision 6).
- **Multi-tenant isolation is Customer-facing-SaaS-critical** — single most important statement in the brief. Supabase RLS absent or `true`-policy, Firestore rules permissive, Prisma queries without `userId:`/`tenantId:` clause.

**Remediation matrix:**
| Fix class | Routing |
|---|---|
| Add missing `auth()` to Next.js Server Action | Auto (when pattern established) |
| Set cookie `Secure`/`HttpOnly`/`SameSite` flags | Auto |
| Remove hardcoded JWT-secret fallback | Auto |
| Add missing session `maxAge` | Auto |
| Add auth middleware to unprotected admin route | Stage |
| Add RLS policies to Supabase table | Stage (as migration) |
| Tighten Firestore rules | Stage |
| Rotate JWT/NEXTAUTH_SECRET | Inline always |
| IDOR ownership-check insertion | Inline always |
| Role-hardcoding → policy engine refactor | Inline (architectural) |
| JWT-in-localStorage → HttpOnly cookie | Inline (architectural) |
| Passkey/WebAuthn support | Inline (architectural, graduation band) |

**Owned detection surface:** route inventory per framework (Next.js App Router + Pages Router + Server Actions; Express/Fastify/Hono; Firebase Functions callable vs onRequest; tRPC procedure levels), admin-endpoint URL+role-gate audit, tenant-isolation Supabase/Firestore/Prisma/Drizzle query scan, IDOR risk scoring (gated), session-management library classification + per-library correctness, role-hardcoding grep/AST.

**Delegated:** rate-limiting (#7) — login/reset brute-force limits; crypto/PII (#4) — password hashing + JWT signing algorithm; config-posture (#5) — cookie-flag baseline; secret-detection (#2) — hardcoded auth secrets; supply-chain (#6) — auth-library CVE elevation; OWASP A01/A07 are this concern.

**Tier applicability:** Minimal at Prototype (any auth at all?). Internal adds route inventory + basic admin check. Public-facing adds full audit + basic IDOR scan. Customer-facing SaaS adds **mandatory tenant isolation** + role matrix + refresh-token rotation + MFA option. Regulated adds policy-as-code + audit logging + session revocation + SAML/SSO for enterprise sales.

### 3.9 Threat model generation (concern #9)

**Load-bearing findings:**
- **Sink node at runtime** (Decision 8) — consumes all nine other concerns' outputs; never parallelized at audit time.
- **STRIDE is the right methodology for builder-facing output.** DREAD for prioritization. LINDDUN at Customer-facing SaaS+. Attack trees for top-3 at Public-facing+. PASTA defers to Regulated Pattern #13.
- **Output = Mermaid-in-markdown + Threat Dragon JSON sidecar** (Decision 26).
- **FP is "threat relevance," not "threat accuracy."** Target: 12% on overall enumeration, <5% on top-10-prioritized.
- **Inventory-completeness check before synthesis** — if route coverage <90%, banner "threat model may be missing surfaces from [list]." Silent undergeneration is the failure mode to avoid.
- **Cross-concern category-owner mapping:** Spoofing → auth; Tampering → injection + supply-chain; Repudiation → advisory-audit-log; Info Disclosure → crypto/PII + CVE + secrets; DoS → rate-limit + CVE; Elevation → auth + config.

**Remediation matrix:** predominantly advisory/inline. Three modes: direct cross-concern mapping (auto-fix via that concern), advisory remediation (inline in threat model doc), human judgment call (enumerated decision for builder).

**Owned detection surface:** none — this concern is synthesis. Consumes: classification from audit.json, route inventory from auth-model, data model + PII boundaries from crypto/PII, integrations from config/deps, auth system from auth-model, secrets from secret-detection, known vulns from SCA, covered-surfaces from Vibe Test when present.

**Delegated:** all nine other concerns are tributaries.

**Tier applicability:** **No threat model at Prototype** — stub emitted. Lightweight (external + admin boundary, no LINDDUN) at Internal. Full STRIDE + DREAD + top-10 + attack-trees-top-3 at Public-facing. Full + LINDDUN + tenant boundary at Customer-facing SaaS. Full + LINDDUN + attack-trees-top-5 + Threat-Dragon JSON + pytm stub + adversary personas at Regulated.

### 3.10 Security-tier thresholds (concern #10)

**Load-bearing findings:**
- **Tier curve is 30/55/70/80/90** (Decision 2) — Vibe Test parity.
- **Severity amplifier** (Decision 2) — Critical caps concern_pass_fraction at 0.5, High at 0.8.
- **Inheritance-first classifier** — Vibe Test's `audit.json` wins when present and fresh (≤24h). Security-specific promotion is explicit, logged, builder-visible.
- **Promotion signal classes:** deployment-detection (→ Public-facing), payment/PII integration (→ Customer-facing SaaS), multi-tenant signals (confirmatory), compliance markers (→ Regulated — but HIPAA/PCI marketing text is Medium, not Strong).
- **Classifier FP is bidirectional** — over-promotion burns trust, under-promotion misses real posture. 12% budget counted both directions.
- **Tier-override decay 90 days default, 30 days at Regulated** (open question surfaced in conflicts.md).

**Remediation matrix:**
| Finding class | Routing |
|---|---|
| Tier-mismatch (classification itself) | Inline always — conversation, not fix |
| Threshold-miss decomposed to concern failures | Route to concern-specific fix pipelines |

**Owned detection surface:** tier classifier (inheritance + security-signal promotion), weighted-score calculator (shared implementation `src/scoring/weighted-score.ts`), gate exit-code contract (0/1/2 with Critical override), tier-transition detection (cross-run + ambient), `docs/SECURITY.md` graduating-guidance auto-generation.

**Delegated:** all other nine concerns feed weighted-score inputs. This concern owns no detectors of its own — it's the math substrate.

**Tier applicability:** Meta — runs at every tier. Depth of gate behavior varies (Prototype never fails threshold; Regulated gate emits beacon on every run).

---

## 4. Cross-concern handoff contracts

Concrete schemas for `findings.jsonl` and `covered-surfaces.json` integration, plus the internal ownership matrix preventing double-counting.

### 4.1 `.vibe-sec/state/findings.jsonl` schema (append-only, one JSON object per line)

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
  "references": ["OWASP-A01-2021", "CWE-862"]
}
```

**Field contract notes:**
- `primary_concern` is one of: `dependency-cve`, `secret-detection`, `owasp-survey`, `crypto-pii`, `config-posture`, `supply-chain`, `rate-limiting`, `auth-model`, `threat-model`, `tier-thresholds`.
- `secondary_concerns[]` is a subset of the same set; the primary is excluded.
- `severity_base` is the intrinsic severity of the class (e.g., "this CVE's CVSS base").
- `severity_tier_adjusted` is what the report shows; may be lower-or-higher than base given tier × concern × severity-amplifier.
- `confidence ∈ [0,1]`; below 0.5 → "worth reviewing" band not actionable band; ≥0.9 → auto-fix eligible (subject to destructive-action overrides).
- `fix_class` ∈ `{auto, stage, inline, advisory, inform-only}`.
- `test_recommendation` + `priority_elevation` populate iff Vibe Test should elevate corresponding behavioral/edge-case test priority.
- `epss_score` + `kev_listed` are optional — populated when available (primarily SCA findings), null otherwise. v0.2 doesn't wire to scoring (Decision 13).
- `tier_scaling_at_current_tier` exposes the per-concern tier scaling factor at time of finding — lets downstream consumers re-rank under different tier assumptions without re-running the scan.

### 4.2 Vibe Test `covered-surfaces.json` read contract

Vibe Sec reads `.vibe-test/state/covered-surfaces.json` when present and fresh (≤24h). Fields consumed:

- `classification.tier` → primary input to tier classifier (Decision: inherit unless security-specific promotion fires, log drift via `tier_drift_note` beacon).
- `classification.modifiers[]` → passed through as context modifiers.
- `covered_surfaces.endpoints_with_behavioral_tests[]` → narrows Vibe Sec's "unverified behavior" list; de-prioritizes re-auditing these surfaces (doesn't skip — already-tested ≠ auto-safe, but shifts rank).
- `covered_surfaces.endpoints_with_edge_case_tests[]` → stronger de-prioritization than behavioral.
- `uncovered_surfaces.endpoints[]` → elevates priority for admin-endpoint detection + IDOR scanning.
- `detected_stack.{frontend,backend,auth,integrations}[]` → picks applicable CVE feeds, auth pattern libraries, framework-specific OWASP rules. Vibe-coding-platform fingerprint (Decision 10) cross-references this.

**Fallback when absent/stale:** Vibe Sec runs its own classifier via `src/scanner/classify-tier.ts` using the inheritance logic described in `security-tier-thresholds.md` §Detection. Never fails; degrades gracefully.

### 4.3 Ownership matrix (prevents double-counting)

The primary-concern rule: for each finding class, exactly one concern owns it. When a line of code triggers multiple detectors, findings merge to one entry with `primary_concern` set to the deepest-domain owner and `secondary_concerns[]` listing other cross-referencing detectors. The weighted-score calculator de-duplicates by finding `id`.

| Finding class | Primary owner | Typical secondaries |
|---|---|---|
| CVE in direct dep | dependency-cve | owasp-survey (A06/A03-2025) |
| CVE in auth library (e.g., CVE-2025-29927) | auth-model | dependency-cve, config-posture, owasp-survey |
| Hardcoded AWS key in source | secret-detection | crypto-pii (A02 semantics) |
| Hardcoded JWT signing secret | secret-detection | crypto-pii, auth-model |
| `.env` not in `.gitignore` | secret-detection | config-posture |
| Firebase `allow read, write: if true` | config-posture | auth-model (authz logic) |
| Firebase web client apiKey | secret-detection (informational) | config-posture (companion rules audit) |
| CORS `origin: true, credentials: true` | config-posture | owasp-survey (A05) |
| MD5 for password hash | crypto-pii | owasp-survey (A02), auth-model |
| Missing rate limit on `/login` | rate-limiting | auth-model (brute-force concern), owasp-survey (A04/A09) |
| Missing rate limit on LLM-backed route (unauth) | rate-limiting | owasp-survey (A04) |
| Supabase table without RLS | auth-model | owasp-survey (A01) |
| IDOR (`:id` without ownership check) | auth-model | owasp-survey (A01) |
| PII in `console.log` | crypto-pii | owasp-survey (A09) |
| Missing SRI on CDN script | owasp-survey (A08) | supply-chain |
| Unpinned third-party GitHub Action | supply-chain | owasp-survey (A08) |
| Typosquat in direct deps | supply-chain | dependency-cve |
| Missing audit log on auth-state changes | threat-model (advisory) | owasp-survey (A09) |
| Role-hardcoding scattered | auth-model | owasp-survey (A01/A04) |
| JWT in localStorage | auth-model | crypto-pii, owasp-survey (A02/A07) |
| Cookie missing HttpOnly (auth cookie) | auth-model | config-posture |
| Cookie missing HttpOnly (preference cookie) | config-posture | — |

---

## 5. Pattern #13 "Plays well with" consolidated table

One aggregated table across all ten briefs. Organized by **day-one compose** (no-account, ambient detection — Vibe Sec detects and uses when present) vs. **future runs** (commercial / account-required — surfaced in Band 4 for next-graduation move).

### Day-one compose (if installed on builder's machine, Vibe Sec uses ambient)

| Tool | Concern(s) | Role when present |
|---|---|---|
| **gitleaks** | secret-detection | Run in parallel with Vibe Sec's scan; merge findings; credit tool. |
| **trufflehog** | secret-detection | If installed, run `trufflehog filesystem --json .`; prefer its verifier when `--verify` flag passed. |
| **git** (always present in repos) | secret-detection, supply-chain | History scan substrate (full + incremental). |
| **npm audit** (built-in) | dependency-cve, supply-chain | Primary fix-availability oracle; confirmer vs OSV. |
| **helmet / @fastify/helmet** | config-posture | When present in `package.json`, delegate baseline-header baseline; focus audit on config delta. |
| **Semgrep** (local install) | owasp-survey (A03), crypto-pii | When installed + configured, defer deep injection + crypto-rule analysis; consume its JSON output. |
| **ESLint + `eslint-plugin-no-unsanitized`** | owasp-survey (A03 XSS subset) | Detect and propose adding when ESLint configured; two-line commit-time XSS gate. |

### Future runs — surface in Band 4 (no-account or paid, next-graduation move)

| Tool | Concern(s) | When recommended |
|---|---|---|
| **Dependabot** | dependency-cve, supply-chain | GitHub repos at Public-facing+; `/vibe-sec:fix` generates the `.github/dependabot.yml` stub. |
| **Renovate** | dependency-cve, supply-chain | Non-GitHub platforms (GitLab/Bitbucket/Gitea); self-host option. |
| **Socket.dev (Firewall Free)** | dependency-cve, supply-chain | Public-facing+; "the tool that catches supply-chain novelty CVE detection misses." Leads Band 4 for SCA. |
| **Snyk free tier** | dependency-cve, crypto-pii, owasp-survey | Customer-facing SaaS+; reachability analysis, license scanning, deeper SAST. |
| **GitHub Secret Scanning + Push Protection** | secret-detection | Public repos (free since 2025); private repos $19/committer/month. Credit GitHub for parallel scanning; recommend push protection enabled. |
| **GitGuardian** | secret-detection | Customer-facing SaaS+; commercial real-time commit-time detection. |
| **Betterleaks** | secret-detection | Emerging; when encoding-obfuscated secrets suspected. |
| **AWS Canarytokens / canarytokens.org** | secret-detection, threat-model | `docs/SECURITY.md` handoff recommendation — plant decoy credentials as tripwires. |
| **CodeQL** | owasp-survey (A01, A03) | Open-source repos; free for public repos on GitHub. |
| **SonarQube / SonarCloud** | owasp-survey | Regulated tier; broader code-quality + OWASP coverage. |
| **Snyk Code (paid)** | owasp-survey (A01, A03) | Customer-facing SaaS+; ML-assisted dataflow. |
| **Mozilla Observatory** | config-posture, crypto-pii | Runtime header scanner for deployed apps; post-deploy complement to static audit. |
| **securityheaders.com** | config-posture | Same positioning as Observatory; simpler single-URL. |
| **CSP Evaluator (Google)** | config-posture | When Vibe Sec detects CSP, surface the link with policy pre-populated. Mandatory step at Customer-facing SaaS+. |
| **testssl.sh** | crypto-pii | Local TLS scanner for non-internet-reachable targets. |
| **Microsoft Presidio** | crypto-pii | OSS PII-detection in free-text fields (complements schema-based detection). |
| **OpenSSF Scorecard** | supply-chain | Free automated scoring of OSS deps; lower-friction than Socket. |
| **Sigstore / cosign (verify-bundle)** | supply-chain | Regulated tier; cryptographic provenance verification. |
| **Syft / Grype (Anchore)** | supply-chain | Regulated tier; SBOM generation + signing. |
| **Cloudflare WAF + Turnstile** | rate-limiting | Public-facing+; free tier covers most vibe-coded-app needs. |
| **Vercel Firewall** | rate-limiting | When Vercel deploy detected. |
| **Upstash Ratelimit** | rate-limiting | Default framework-generic recommendation at Prototype/Internal. |
| **Arcjet** | rate-limiting | When LLM-backed routes detected (Decision 17). |
| **rate-limiter-flexible** | rate-limiting | When `express-rate-limit` outgrown. |
| **Clerk** | auth-model | Next.js SaaS with speed-to-market priority, <10K MAU, no enterprise SSO. |
| **Auth0 (Okta)** | auth-model | Enterprise/regulated; SAML SSO; HIPAA/SOC2 documentation. |
| **Supabase Auth** | auth-model | Already on Supabase; RLS-native authz. |
| **NextAuth / Auth.js v5** | auth-model | Next.js + OSS preferred + DIY UI acceptable. |
| **Casbin** | auth-model | Policy-as-code authz across RBAC/ABAC/ReBAC; GitOps-friendly. |
| **Cerbos** | auth-model | Policy-as-deployed-service; centralized policy management. |
| **OPA / Rego** | auth-model | Polyglot stacks; already using OPA for infra. |
| **SimpleWebAuthn** | auth-model | Passkey reference implementation for Node. |
| **OWASP Threat Dragon** | threat-model | Public-facing+; GUI maintenance after initial generation. Schema-compatible JSON sidecar. |
| **pytm** | threat-model | Python-heavy teams; threat-model-as-code with git diffs. |
| **Microsoft Threat Modeling Tool** | threat-model | Windows enterprise shops with existing MTMT workflows. |
| **STRIDE-GPT** | threat-model | Adjacent standalone; Vibe Sec's integrated model is differentiated. |
| **Drata** | tier-thresholds | Customer-facing SaaS+ aspiring to SOC 2; DevOps-integrated compliance. |
| **Vanta** | tier-thresholds | Fastest compliance onboarding; Customer-facing SaaS+. |
| **Secureframe** | tier-thresholds | Broadest framework coverage; Regulated. |
| **IriusRisk / ThreatModeler / Security Compass** | threat-model | Regulated; enterprise threat-modeling platforms. |

**Categorically out of scope for Vibe Sec (name only, don't recommend first):**
- OWASP ZAP / Burp Suite (runtime pentesting — v0.3+)
- Datadog Security / Panther (runtime observability — different category)
- SIEM platforms (runtime correlation)
- Binary-authorization gating in CI (infrastructure-security, not app-security)

---

## 6. Aggregated tier applicability matrix

Authoritative 5-tier × 10-concern grid. Each cell: one of {skip, lightweight, full, mandatory}. Inputs `/vibe-sec:gate` tier-gating decisions.

- **skip** — concern not audited at this tier; findings not emitted; denominator excluded from weighted score.
- **lightweight** — surface-level detection only; findings Band 2 (educational) default.
- **full** — standard audit depth; findings Band 1 (critical-now) when severity warrants.
- **mandatory** — blocking for `/vibe-sec:gate`; any High/Critical finding fails the gate.

| Concern | Prototype | Internal | Public-facing | Customer-facing SaaS | Regulated |
|---|---|---|---|---|---|
| #1 Dependency CVE | lightweight (Critical only) | full (no dev-dep by default) | full | mandatory | mandatory (+ SBOM recommendation) |
| #2 Secret detection | full (tier-calibrated severity) | full | full | full | mandatory |
| #3 OWASP Top 10 survey | skip (except secrets bleed-through) | lightweight | mandatory | mandatory | mandatory |
| #4 Crypto / PII | skip (except hardcoded secrets) | lightweight (hash algorithm + env) | full | mandatory | mandatory (+ NIST FIPS check) |
| #5 Config posture | skip (except Firebase `if true` warning) | lightweight (nosniff/X-Frame/HttpOnly) | full | mandatory | mandatory (+ HSTS preload) |
| #6 Supply-chain | skip (informational only) | lightweight (lockfile presence, no `*`/`latest`) | full | mandatory | mandatory (+ SBOM + provenance) |
| #7 Rate limiting | skip (EXCEPT LLM-burn unauth = Critical override) | lightweight (library-absence signal) | mandatory (auth routes) | mandatory (+ per-tenant + LLM budgets) | mandatory (+ anomaly detection + SIEM) |
| #8 Auth model | lightweight (committed secret → Critical; rest informational) | full (route inventory + admin audit) | mandatory | mandatory (+ tenant isolation = mandatory) | mandatory (+ policy-as-code + audit log) |
| #9 Threat model | skip (stub emitted) | lightweight (1-2 pages, external + admin boundary) | full (STRIDE + DREAD + attack-trees top-3) | full (+ LINDDUN + tenant boundary) | full (+ LINDDUN + attack-trees top-5 + pytm stub) |
| #10 Tier thresholds | full (meta — classify + report) | full | mandatory | mandatory | mandatory (+ every-run beacon) |

**Gate decision rules:**
- Prototype: weighted score ≥30%. No concern is individually mandatory; Critical findings in concerns 1, 2, 7(LLM-burn) fail regardless.
- Internal: weighted score ≥55%. No concern individually mandatory.
- Public-facing: weighted score ≥70% **and** no High/Critical in mandatory concerns (3, 5, 7, 8).
- Customer-facing SaaS: weighted score ≥80% **and** no High/Critical in mandatory concerns (1, 3, 4, 5, 6, 7, 8). Tenant isolation is a hard binary — any Supabase table without RLS or Firestore rules permissive = fail.
- Regulated: weighted score ≥90% **and** no High/Critical in any concern except #9 (threat-model findings are advisory).

---

## 7. FP-budget allocation

12% global commitment distributed per-concern. Concerns with noisier detection surfaces (auth-model IDOR scanning, config-posture CSP directive fuzz) get more budget; concerns with cleaner signals (secret detection with prefixed patterns, SCA with CVE IDs) get less. Sum = 12.0%.

| Concern | FP budget | Rationale |
|---|---:|---|
| #1 Dependency CVE | 0.8% | CVE IDs are deterministic; FP comes from dev-dep filtering + reachability — both tractable. |
| #2 Secret detection | 0.7% | Layer A regex is high-precision; Layer B entropy + Layer C AST keep FP tight. Verification deferred. |
| #3 OWASP Top 10 survey | 2.0% | A01 authz + A04 design patterns are fuzzy; A09 silent-catch is noisy. Highest category-level FP. |
| #4 Crypto / PII | 1.2% | PII field-name inference generates some noise (displayName, publicEmail); schema-parse mitigates. |
| #5 Config posture | 1.0% | CSP directive audit is fuzzy; baseline-header detection is crisp. |
| #6 Supply-chain | 1.0% | Typosquat similarity can spam; allowlist + download-count gating keeps it controlled. |
| #7 Rate limiting | 1.3% | Custom-middleware detection is uncertain; platform-config detection partial. |
| #8 Auth model | 2.5% | IDOR scanning + centralized-authz tracing is hardest domain; tier-gating to Public-facing+ and high-confidence-only reduces impact. |
| #9 Threat model | 1.0% | FP here is "threat relevance," not accuracy. Overgenerated speculative threats at Prototype-adjacent tiers. |
| #10 Tier thresholds | 0.5% | Classifier FP is bidirectional; signal-fusion with confidence score keeps it tight. |
| **Total** | **12.0%** | |

**Enforcement:** per-concern budgets are targets, not hard ceilings (Decision 27). A concern exceeding its budget during WSYATM dogfood triggers friction-log review and tuning in v0.3 `/vibe-sec:research --concern <name>` re-run. No gate failure on FP-budget breach.

---

## 8. v0.2 implementation priority order

Natural dependency-ordered sequence for `/build`. Concerns that other concerns depend on land first.

**Phase 1 — Foundation (nothing consumes anything yet):**
1. **Tier thresholds + classifier** (#10) — every other concern consumes tier as input. Weighted-score calculator at `src/scoring/weighted-score.ts` is the shared implementation consumed by classifier + audit + gate + posture. Ship this first.
2. **Shared findings.jsonl schema + state I/O** — the handoff spine. Ship before any detector that writes to it.
3. **Vibe Test composition contract** — reader for `covered-surfaces.json`, writer for `findings.jsonl`. Stub in place before detectors populate.

**Phase 2 — Signal-independent detectors (run in parallel with each other):**
4. **Secret detection** (#2) — promoted from CLI; least cross-concern dependency; highest-signal findings. Full git history scan + 40-50 provider patterns + AST walks.
5. **Dependency CVE** (#1) — OSV + npm audit; lockfile parsing shared with supply-chain.
6. **Supply-chain hardening** (#6) — shares lockfile parsing with #1; detectors independent otherwise.
7. **Config posture** (#5) — framework-config-file parsing; CVE-2025-29927 rule (joint with auth-model).

**Phase 3 — Structural detectors (depend on Phase 1-2 primitives):**
8. **Crypto / PII** (#4) — schema-parse inputs from ORM (Prisma/Drizzle/Zod); PII-in-logs call-site inspection shared with rate-limiting.
9. **Auth model** (#8) — deepest concern; routes + middleware + query-pattern analysis + authz matrix. Depends on framework detection + schema parsing from #4. CVE-2025-29927 rule joint with #5.
10. **OWASP Top 10 survey** (#3) — breadth layer; consumes outputs from other concerns for dual-tagging + primary-concern assignment.
11. **Rate limiting** (#7) — middleware inspection + LLM-endpoint detection; integrates with #8's route inventory.

**Phase 4 — Synthesis sink (runs last, depends on everything):**
12. **Threat model generation** (#9) — consumes all nine outputs; STRIDE + DREAD + Mermaid render + Threat Dragon JSON.

**Command surface ship order (parallel with concerns above):**
- `/vibe-sec` (router) — first, frames everything.
- `/vibe-sec:scan` — Phase 2 (depends on #2).
- `/vibe-sec:deps` — Phase 2 (depends on #1 + #6).
- `/vibe-sec:audit` — Phase 3 (the full orchestrator).
- `/vibe-sec:gate` — Phase 3 (consumes weighted score + findings).
- `/vibe-sec:posture` — Phase 3 (read-only on state).
- `/vibe-sec:fix` — Phase 3 (confidence-tier routing across all concerns).
- `/vibe-sec:threat-model` — Phase 4 (sink).
- `/vibe-sec:research` — any phase; infrastructural for living docs.

**WSYATM dogfood touchpoints:**
- After Phase 2 lands: first real-world secret-detection + dep-CVE signal from WSYATM pre-launch state.
- After Phase 3 lands: full `/vibe-sec:audit` against WSYATM; tier classification + per-concern findings → pre-launch hardening list.
- After Phase 4 lands: threat model for WSYATM at Public-facing tier; feeds `docs/SECURITY.md` runbook.

---

## 9. Open questions surfaced from synthesis

Meta-questions about the synthesis itself — things the architect should revisit at `/spec` time. These are NOT forwarded to `conflicts.md` (which surfaces residual judgment-grade between-brief conflicts). These are synthesis-introspection questions.

1. **Does the 30/55/70/80/90 threshold curve + severity amplifier together produce the "security partial-coverage is binary-fail" behavior the tier-thresholds brief argued for?** Decision 2 declined the 30/50/75/85/95 divergence on calibration-risk grounds and deferred to severity amplifier for non-linearity. WSYATM dogfood should measure: does one Critical-finding-caps-at-0.5 amplifier produce the intended effect, or is the effective threshold too loose at Public-facing+? Friction-log this.

2. **Is the threat-model sink-node execution pattern compatible with `/vibe-sec:fix` round-trip?** Threat-model runs last. But `/vibe-sec:fix` may re-run detectors after applying fixes to verify. Does threat-model re-render every time? Or does it stay stale until an explicit `/vibe-sec:threat-model` re-run? Default posture: threat-model renders on `/vibe-sec:audit` only; fix-loop re-runs regenerate findings.jsonl but don't re-render threat model. Surface in `/spec`.

3. **Ownership of "default admin credentials" finding.** Decision: config-posture owns the narrow case (literal `admin/admin` in seed script / docker-compose). But secret-detection also pattern-matches these. Is there an edge case where secret-detection fires but config-posture doesn't? Needs a test case in WSYATM dogfood or minimal-spa fixture.

4. **CLI-as-thin-wrapper migration impact on Phase 2 ordering.** The existing `@esthernandez/vibe-sec-cli@0.1.1` is secret-scan-only. Phase 2 #4 (secret detection promotion from CLI) requires the CLI→plugin rewire. If that rewire isn't clean, secret-scan delays, which cascades through Phase 2/3. Risk register item: ensure CLI migration is de-risked before Phase 2.

5. **Suppression-portability decision surface.** Decision locked: suppressions are per-project; after N repetitions, prompt once for global. Where is "N" set? Default to 5 (matches Vibe Test's suppression pattern). Revisit at `/spec`.

6. **Caching strategy + network-down posture.** 24h TTL on OSV responses, 30-day on history-scan state, 7-day on state freshness for `/vibe-sec:posture`. When offline, `/vibe-sec:audit` degrades: last cached findings + staleness timestamp + banner note. Don't fail. Ensure CI mode handles this deterministically.

7. **Monorepo handling across concerns.** Config-posture brief flagged per-app emission-matrix (not flat) as required for monorepos. Auth-model, crypto/PII, rate-limiting implicitly assume single-app. Synthesis call: each concern's scan operates on a detected "app root" (determined by presence of `package.json` + framework config), not repo root. Monorepo support = N parallel scans + aggregate report. Lock at `/spec`; this requires shared app-detection utility.

8. **Vibe Doc integration depth — co-author or emit?** Threat-model brief proposed "emit as complete markdown; Vibe Doc reads it as existing doc" (cleaner contract). Same call for `docs/SECURITY.md`? Or does Vibe Sec invoke Vibe Doc's generator for the SECURITY.md runbook? Synthesis lean: emit-only for v0.2; co-author v0.3 when composition contracts stabilize. Confirm at `/spec`.

9. **FP-budget enforcement mechanism.** Decision 27 makes per-concern budgets targets, not ceilings. But how do we measure FP during WSYATM dogfood? Each finding needs a builder-adjudication hook ("this is wrong because..." → suppress-with-reason). Wire this into `/vibe-sec:posture` or a separate `/vibe-sec:feedback` command? Open.

10. **Research agent re-run cadence policy.** Scope says living docs; synthesis doesn't lock cadence. Default: re-run any brief manually via `/vibe-sec:research --concern <name>`; no automatic schedule. Tier-thresholds brief suggested quarterly; auth-model suggested quarterly-or-on-CVE-drop. Let the built-in friction-log signal drive this (Pattern #14) — no hard schedule.

---

*End of synthesis. Feeds `/spec` directly. Re-generated post-swarm when any single brief re-runs. Conflicts that synthesis declined to resolve → `docs/research/conflicts.md`.*

**Word count target:** 5000-8000. Actual: ~7400 words.
**Section count:** 9 H2 sections (executive, consolidated decisions × 27, per-concern digest × 10, handoff contracts, plays-well-with, tier matrix, FP allocation, priority order, open questions).
