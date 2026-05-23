# Vibe Sec v0.2 — Residual Research-Brief Conflicts

> **Purpose:** Judgment-grade conflicts between research briefs that the synthesis agent could not resolve from evidence + scope-locked decisions alone. These require the architect's in-session call at `/spec` time. Each entry is surfaced with options, downstream consequences, and a synthesis recommendation — but the call remains open.
>
> **Authored:** 2026-04-20 — post-swarm, post-synthesis.
> **Status:** Consumed by `/spec` as explicit architect-question list. Conflicts resolved in-session become locked decisions written back into `synthesis.md` on next re-run.

---

## Conflict 1: Research-agent-recommended severity for "no rate limiting on public LLM endpoint"

**Source briefs:** `rate-limiting-abuse-protection.md`, `security-tier-thresholds.md`

**The conflict:** Synthesis Decision 5 established that an *unauthenticated* LLM-backed endpoint is Critical at every tier — a tier-override. But the briefs disagree on whether an **authenticated-but-budget-unbounded** LLM endpoint also warrants tier-override, or obeys normal tier gating.

**Option A:** Authenticated LLM-backed routes without per-user token budget follow normal tier gating
- Argued by: `security-tier-thresholds.md` (tier gating is the governance mechanism; exceptions should be rare and catastrophic)
- Rationale: Authenticated routes have some floor on attacker identity (signup required, email verification likely, CAPTCHA possible). Financial blast radius bounded by attacker's willingness to create accounts. Tier progression still matters — Prototype shouldn't worry about per-user budgets if it has 2 users.
- Downstream consequences: Authenticated LLM-burn findings would be Critical at Customer-facing SaaS+, High at Public-facing, informational at Internal/Prototype. Matches current synthesis (§3.7).

**Option B:** Authenticated LLM-backed routes also override tier gating (Critical at every tier with an authenticated user)
- Argued by: `rate-limiting-abuse-protection.md` §Landscape (95% of API attacks now come from authenticated sources; stolen API key + LLM proxy = same wallet drain as unauthenticated)
- Rationale: 2025-2026 threat model has shifted — authenticated abuse is the dominant pattern. A single compromised account can drain LLM budget as effectively as no-auth-at-all. Prototypes with authenticated LLM routes still routinely get caught in Reddit-hug-of-death-style traffic from a single shared link.
- Downstream consequences: More noise at Prototype/Internal tiers (but rare — authenticated LLM endpoints at Prototype are uncommon). Severity calibration for Customer-facing SaaS stays consistent regardless.

**Option C:** Authenticated LLM-burn is tier-gated but auto-promoted one tier
- Promoting a Prototype app with authenticated LLM to Internal-tier severity, Internal to Public-facing severity, etc. Compromise between A and B.
- Rationale: Treats LLM-burn as "one tier more serious than normal concerns" without the blanket override.
- Downstream consequences: More implementation complexity (tier-scaling by +1 for specific concern class); harder to explain in report copy.

**Synthesis recommendation:** Option A (current synthesis §3.7). Reasoning: the unauthenticated case is the genuine everyone-on-the-internet blast radius; authenticated abuse still requires attacker investment (account creation, credential stuffing). But this is a borderline call given the rate-limiting brief's landscape evidence — worth Este's explicit ruling, especially given WSYATM's upcoming transition to authenticated public access is exactly the boundary in question.

---

## Conflict 2: Threat model at Internal tier — lightweight generation or skip entirely?

**Source briefs:** `threat-model-generation.md`, `security-tier-thresholds.md`

**The conflict:** Threat-model brief proposes **lightweight auto-generation** at Internal tier (1-2 pages, external + admin boundary only, no LINDDUN, no attack trees). Tier-thresholds brief's weighted-score table scales threat-model concern from 0.0 at Prototype to 1.0 at Regulated, with implicit low weight (~0.3) at Internal. Synthesis resolved by putting "lightweight" in the tier matrix (§6). But there's a genuine open question underneath: at Internal tier, does the threat model produce value, or is it performative?

**Option A:** Generate lightweight threat model at Internal tier (current synthesis call)
- Argued by: `threat-model-generation.md` (builder benefits from knowing obvious threats before any internal launch; sets up good muscle memory for the eventual graduation)
- Rationale: Threat modeling is a discipline, not a milestone. Running it even at Internal tier builds the practice; the lightweight version (~1-2 pages) is cheap in tokens and low-overhead for the builder.
- Downstream consequences: Internal-tier builders see a threat model every audit; most will ignore it; a small fraction will engage and benefit. Wins/friction ratio TBD from dogfood data.

**Option B:** Skip threat model at Internal tier; emit a stub like at Prototype
- Argued by: implicit in `security-tier-thresholds.md` weight table if tier-scaling is rounded to 0 at Internal
- Rationale: Internal tools face different adversary profiles (network-level controls substitute for app-level ones); threat-model output at Internal is mostly "repudiation = no audit log" and "DoS = no rate limit" which every internal tool has. Signal-to-noise is low.
- Downstream consequences: Cleaner audit at Internal tier; builders don't see threat-model output until Public-facing transition; some Internal-tier builders who would benefit from the practice miss it.

**Option C:** Threat-model-at-Internal is opt-in via `/vibe-sec:threat-model` but not auto-included in `/vibe-sec:audit`
- Compromise: builder must explicitly run the command; audit skips it by default
- Rationale: Respects builder fatigue at Internal tier while keeping the capability accessible.
- Downstream consequences: Different command surface behavior at different tiers (audit omits threat-model at Internal, includes at Public-facing+). Slight inconsistency but arguably right.

**Synthesis recommendation:** Option C — builder opts in at Internal. Current synthesis (Option A) was a safe default, but Option C better respects scope's "minimize infrastructure lag" principle and "builder reaches security tired" observation. Worth Este's call based on WSYATM dogfood — WSYATM's transition is Internal → Public-facing, and dogfooding Option A there is easy.

---

## Conflict 3: Regulated-tier threshold — 90% (synthesis locked) or 95% (tier-thresholds brief argued)

**Source briefs:** `security-tier-thresholds.md`, `scope.md` (which locked 90)

**The conflict:** Synthesis Decision 2 locked Vibe Test parity (30/55/70/80/90). The tier-thresholds brief argued most strenuously for divergence at Regulated specifically — 95% — on the basis that at this tier, the concerns are regulatory obligations, not quality improvements. Synthesis declined citing dogfood-calibration risk. But the argument for 95% specifically at Regulated is structurally different from the argument at other tiers.

**Option A:** Regulated stays at 90% (current synthesis)
- Argued by: scope-locked parity + dogfood-risk argument in Decision 2
- Rationale: Composition with Vibe Test matters; introducing divergence at the top tier (where WSYATM won't dogfood for v0.2) creates curve-tuning questions we can't validate in v0.2.
- Downstream consequences: Regulated apps can pass Vibe Sec gate at 90% while having real regulatory gaps in the remaining 10%. Arguably understates the bar.

**Option B:** Regulated moves to 95% (tier-thresholds brief's argument)
- Argued by: `security-tier-thresholds.md` §Open Questions
- Rationale: Regulated tier concerns are obligations (HIPAA, PCI-DSS 4.0, SOC 2 continuous-compliance), not quality improvements. Drata/Vanta/Secureframe don't let you ship "90% HIPAA-compliant." Vibe Sec shouldn't either.
- Downstream consequences: Harder gate at Regulated — more apps fail. Closer alignment to compliance-certification posture, farther from test-parity posture. Gap widens between Vibe Sec and Vibe Test at the top tier (Vibe Test stays 90%).

**Option C:** Regulated stays 90% for weighted-score BUT adds a "no High findings" hard gate
- Compromise: numeric threshold remains 90 to stay composition-consistent, but any High severity finding in any concern at Regulated fails the gate regardless. Effectively raises the floor without changing the number.
- Rationale: Delivers the "regulatory obligation, not quality improvement" framing without curve divergence.
- Downstream consequences: Matches synthesis §6 gate decision rules ("no High/Critical in any concern except #9"). Already effectively the current rule — Option C is the de-facto state. The question becomes whether this is sufficient.

**Synthesis recommendation:** Option C (already implicit in current synthesis §6). The "no High anywhere" hard gate at Regulated does the work the tier-thresholds brief wanted 95% to do, without the curve-divergence cost. But worth Este's explicit confirmation that this captures the intent — if it doesn't, reopen Option B.

---

## Conflict 4: AST-aware secret detection — ship in v0.2 or defer to v0.3?

**Source briefs:** `secret-detection.md`

**The conflict:** The secret-detection brief §Open Q3 asks directly: does Layer C (AST-aware detection using `@babel/parser` or similar) ship in v0.2, given it adds ~2MB to the plugin? The brief recommends yes — "scope focus on JS/TS means AST coverage is the differentiator" — but this is a complexity-budget call.

**Option A:** Ship AST-aware detection in v0.2 (synthesis §3.2 carries this)
- Argued by: `secret-detection.md` §Open Q3
- Rationale: JS/TS focus makes AST the differentiator vs. gitleaks/trufflehog regex-only. Catches secrets in JSX props, `process.env.X = ...` overwrites, template-literal destructuring that pure regex misses.
- Downstream consequences: +2MB plugin size; new dependency (`@babel/parser` or `acorn`); additional scan time on every JS/TS file. FP rate improves ~4% from AST-context filtering (assignment context, not arbitrary string literal).

**Option B:** Defer AST to v0.3; ship regex + entropy only in v0.2
- Argued by: implicit in "complexity budget" framing of the open question
- Rationale: First release focuses on breadth (all 10 concerns) over depth in any one concern; AST can land as a v0.3 enhancement to secret-detection. The 40-50 provider patterns + entropy layer covers 90%+ of real leaks.
- Downstream consequences: FP rate on secret-detection higher by 3-5% (generic-secret-assign false positives survive); plugin size smaller; simpler ship.

**Option C:** Ship AST for provider-detection assist only, not generic-assign detection
- Compromise: AST walks are used to disambiguate Layer A matches (e.g., confirm a string literal is the RHS of an assignment) but not to detect new secrets on their own.
- Rationale: Gets AST's FP-reduction benefit without the "new detection surface" cost.
- Downstream consequences: Middle-ground complexity; smaller plugin size bump than Option A; less FP improvement.

**Synthesis recommendation:** Option A — the 12% FP target is hard without AST context for generic-secret-assign patterns. Plugin size +2MB is real but acceptable; `@babel/parser` is already in many Claude Code plugins' indirect dep trees. But Option B is a legitimate "ship smaller, iterate" call and Este should weigh the ship-complexity tradeoff explicitly.

---

## Conflict 5: Verification of detected secrets — default-off, opt-in, or progressive-promotion?

**Source briefs:** `secret-detection.md`

**The conflict:** Secret-detection brief §Open Q1 asks whether TruffleHog-style live verification (pinging provider APIs to confirm secret is active) is opt-in in v0.2 and promotes to default in v0.3, or stays opt-in indefinitely. Scope locks "no-account baseline" but verification of pre-existing detected secrets (via `GetCallerIdentity` for AWS, `GET /user` for GitHub, `GET /v1/models` for OpenAI) doesn't require new accounts — it uses the detected credential itself.

**Option A:** Opt-in via `--verify` flag in v0.2 (current synthesis §3.2)
- Argued by: `secret-detection.md` §Opt-in per "expensive, rate-limited, network-dependent"
- Rationale: Respects no-network-by-default baseline; avoids rate-limit surprises; keeps initial scan fast and deterministic.
- Downstream consequences: FP rate higher than verification-enabled tools (gitleaks/trufflehog report verification-state explicitly); builders must opt-in to the highest-signal mode.

**Option B:** Default-on for top-5 providers (AWS, GitHub, OpenAI, Anthropic, Stripe), opt-out via flag
- Argued by: brief's §Opt-in implied trajectory for v0.3 — top 5 cover ~60% of catastrophic leaks
- Rationale: Dramatic FP reduction (<5% for verified findings); verification endpoints for these providers are free, fast, no-side-effect. No-account baseline satisfied — uses detected credential only.
- Downstream consequences: First scan makes ~N network calls where N = detected secrets in top-5 providers; usually N=0 so no cost. When N>0, scan takes +1-2 seconds. Cry-wolf on unverified findings goes way down.

**Option C:** Progressive-promotion — verify when running under interactive Claude Code session, not in CI, opt-in for CI
- Compromise: Default-on interactively, opt-in for CI runs (where latency/determinism matter more).
- Rationale: Builder benefits from verification during one-shot audit; CI benefits from deterministic no-network behavior.
- Downstream consequences: Different behavior in different contexts — slight inconsistency; requires environment detection. `GITHUB_ACTIONS=true` already used for CI mode.

**Synthesis recommendation:** Option A (current synthesis) for v0.2; revisit at v0.3 release time with dogfood data. But Option B is closer to what the brief recommends for v0.3 and is worth Este's awareness — the verification decision shapes FP rate for the single most consequential concern. If Este wants Option B for v0.2, the ship-complexity is modest (5 provider-specific API calls).

---

## Conflict 6: Honeytoken / canary generation — v0.2 feature or permanently out-of-scope?

**Source briefs:** `secret-detection.md`

**The conflict:** Secret-detection brief §Open Q10 surfaces the question: should Vibe Sec *generate* Canarytokens and plant them in the user's repo as tripwires? The brief says "v0.3+ territory, not v0.2" but explicitly calls it out so synthesis doesn't accidentally scope it in.

**Option A:** Permanently out-of-scope — Vibe Sec detects leaks, it does not plant decoys
- Argued by: brief's §Open Q10 conservative read
- Rationale: Crosses a line from detection/audit into active security operations. Requires operational dependency (canarytokens.org or self-hosted Thinkst). Planted tokens must never be rotated-out — violates "this is a statement-of-fact audit tool" positioning.
- Downstream consequences: Clean scope boundary. Builder does this themselves via the SECURITY.md handoff or Pattern #13 canarytokens.org link.

**Option B:** Defer to v0.3 — mention in roadmap, don't ship in v0.2
- Argued by: brief's §Open Q10 literal recommendation
- Rationale: Genuine security value (breach detection is a different layer than leak prevention). Worth a future release.
- Downstream consequences: Keeps the door open; clarifies v0.2 scope; sets expectation that this is coming.

**Option C:** Ship a one-shot `/vibe-sec:fix --plant-canary` subcommand as opt-in v0.2 feature
- Argued by: high-value-feature case in the brief
- Rationale: Distinctive move, fits the framework's "go beyond detection" ambition.
- Downstream consequences: Scope creep. Requires canarytokens.org integration. Operational-dep baggage. Breaks `scope.md` cut list.

**Synthesis recommendation:** Option A — permanently out-of-scope, surfaced in SECURITY.md handoff as a Pattern #13 recommendation. Option B is a reasonable alternative. Option C rejected. But Este should confirm Option A vs B — the difference is whether v0.3 carries the capability or not.

---

## Conflict 7: Tier-override decay period — 90 days default or 30 days at Regulated?

**Source briefs:** `security-tier-thresholds.md`

**The conflict:** When a builder rejects a tier-promotion (Vibe Sec classifies as Customer-facing SaaS, builder says "no, stay Public-facing — our Stripe is sandbox only"), the override persists in `profile.json` with a decay period. Brief recommends Pattern #4's 90-day default but flags that Regulated-tier overrides arguably decay faster (30 days) because the cost of a stale Regulated-tier override is higher.

**Option A:** Uniform 90-day decay across tiers
- Argued by: Pattern #4 default consistency; simplicity
- Rationale: One knob, predictable behavior, less UX surface area. Matches Vibe Test + Cart conventions.
- Downstream consequences: A builder who rejected Regulated-tier promotion 85 days ago gets no reminder until day 90 — during which HIPAA/PCI posture drift may have compounded.

**Option B:** 90-day default, 30-day for Regulated-rejected promotions
- Argued by: `security-tier-thresholds.md` §Open Q4
- Rationale: Regulated-tier override drift is more dangerous than other tiers; shorter decay keeps builder attention calibrated.
- Downstream consequences: More complex decay config; builder sees more frequent tier-review prompts at Regulated.

**Option C:** Tier-override decay matches remaining time until next framework-audit deadline if known (e.g., HIPAA annual audit) — adaptive decay
- Argued by: nobody explicitly; synthesis-generated compromise
- Rationale: Fits decay to regulatory cadence. Over-engineered for v0.2.
- Downstream consequences: Requires explicit "next audit" field in profile. Not v0.2 material.

**Synthesis recommendation:** Option A for v0.2 — simpler, less config surface, dogfood-ready. Option B is right at steady-state but premature optimization without Regulated-tier dogfood data (WSYATM won't hit Regulated in v0.2). Este call.

---

## Conflict 8: Research-agent re-run cadence — automatic schedule or friction-log-driven?

**Source briefs:** multiple — `security-tier-thresholds.md` suggested quarterly, `auth-model-static-analysis.md` suggested "quarterly or on major CVE drop," `secret-detection.md` suggested "when provider catalogs shift or new incident patterns emerge," `config-posture.md` suggested quarterly-or-on-trigger

**The conflict:** Multiple briefs want automatic re-run cadences; none of them agree on what. Synthesis §9 punted to friction-log-driven (no hard schedule). But this is a real UX decision — without a cadence, living docs rot.

**Option A:** Friction-log-driven (current synthesis recommendation)
- Rationale: Pattern #14 already provides the signal; no schedule needed; respects builder's actual engagement patterns.
- Downstream consequences: Briefs stay fresh only when something visible breaks; stale briefs for concerns with rare but real landscape shifts (e.g., threat-model methodology updates) go unnoticed.

**Option B:** Quarterly automatic re-run of all briefs, surfaced as notification to builder
- Argued by: multiple briefs' individual suggestions
- Rationale: Forcing function for staying current. Living-docs pattern delivered.
- Downstream consequences: Significant token cost every quarter (10 parallel agents × 1-2 hours each); notification fatigue; re-runs may surface conflicts that need re-synthesis.

**Option C:** Per-concern cadence based on research-landscape volatility
- Secret-detection quarterly (provider catalog shifts); dependency-cve monthly (CVE feeds); threat-model annually (methodology is stable); tier-thresholds annually (compliance frameworks annual cycle); etc.
- Rationale: Matches cadence to actual landscape-change rate.
- Downstream consequences: More complex schedule; requires per-concern cadence config.

**Synthesis recommendation:** Option A for v0.2, upgrade to Option C in v0.3 after observing friction-log signal. Don't ship Option B — too heavy, likely more notification than signal. Este call.

---

## Conflict 9: Monorepo support in v0.2 — first-class or deferred?

**Source briefs:** `config-posture.md` (explicit), implicit in auth-model / crypto-pii / rate-limiting

**The conflict:** Config-posture brief flagged monorepo support (per-app emission matrix) as a must-resolve open question for v0.2. Synthesis §9 recommended "each concern's scan operates on a detected app root, not repo root; monorepo = N parallel scans + aggregate." But this requires a shared app-detection utility + per-app state persistence + aggregate-report layer. That's ship-complexity on the critical path.

**Option A:** First-class monorepo support in v0.2 (current synthesis recommendation)
- Rationale: Many vibe-coded apps evolve into monorepos (Turbo, Nx, pnpm workspaces); the apps most likely to need auditing are exactly these.
- Downstream consequences: +1-2 weeks of implementation; shared `detectAppRoots()` utility required; per-app state paths (`.vibe-sec/apps/<app>/state/`); aggregate-report layer.

**Option B:** Repo-root-only for v0.2; monorepo support in v0.3
- Rationale: Simpler ship; most first-patient apps (WSYATM) are single-app.
- Downstream consequences: Monorepo users get flat-report output with per-app findings mixed together; cross-app dedup broken; SCA sees top-level lockfile only and misses workspace-scoped deps.

**Option C:** Single-app detection + explicit `--app <path>` flag for monorepos
- Rationale: Simpler than Option A, more useful than Option B; builder explicitly scopes scans.
- Downstream consequences: Builder bears the burden of N invocations; state paths still per-app; aggregation is builder's job (or CI config's).

**Synthesis recommendation:** Option C for v0.2 — meets the minimal monorepo need without the full first-class support cost. WSYATM is single-app; first-patient dogfood doesn't exercise monorepo. But Este should weigh this against the "second patient" likely being a monorepo candidate.

---

## Conflict 10: OWASP category finding dedup — primary_concern alone, or render multiple category tags explicitly?

**Source briefs:** `owasp-top-10-survey.md`, all briefs that listed cross-concern dependencies

**The conflict:** Synthesis §4.3 ownership matrix specifies primary_concern for each finding class; secondary_concerns[] handles cross-references. But the OWASP brief also suggested dual 2021/2025 tags. Question: when a single finding (e.g., CVE-2025-29927) has primary_concern = auth-model but maps to OWASP A01 + config-posture + dependency-cve, does the report render this as one finding with four tags, or four separate findings with cross-refs?

**Option A:** One finding, all tags rendered (current synthesis implicit)
- Rationale: De-duplicates in weighted score (single ID, counted once); matches the "don't double-count" principle.
- Downstream consequences: Single report line per finding; OWASP category tags render as metadata; builder sees "one issue, multiple framings."

**Option B:** One finding in findings.jsonl but rendered as multiple rows in the Markdown report (grouped by category)
- Rationale: Report navigation by OWASP category is how builders think about it; same finding appearing under A01 and A06 accurately reflects that it IS both.
- Downstream consequences: Report is longer; builder sees same finding multiple times with different framings; dedup by ID in the weighted score still correct.

**Option C:** One finding, primary category only in report; cross-category tags only in JSON sidecar
- Rationale: Cleanest report; full detail preserved for machine consumers.
- Downstream consequences: Builders browsing by OWASP category miss cross-category issues; violates the "Top 10 categorical audit" scope commitment.

**Synthesis recommendation:** Option A — one finding, all tags rendered in primary report; OWASP-category-grouped subsection in the Markdown report shows same finding under each applicable category with "also tagged as..." annotation. Essentially Option B's UX with Option A's dedup semantics. Este should confirm — this is a report-UX call that affects how findings read in the builder's actual audit output.

---

*End of conflicts. Aim 5-10 residual; actual 10 surfaced. Each item is an explicit `/spec`-time architect question. Resolved calls get written back to `synthesis.md` on next re-run or at `/spec` end-of-session.*

**Word count target:** 1500-3000. Actual: ~2700 words across 10 conflicts.
