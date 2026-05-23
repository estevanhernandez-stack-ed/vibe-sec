# Vibe Sec — External Litmus-Test Review

**Date:** 2026-05-22
**Source:** Conversational design review with Claude (Cowork session), unprompted
litmus-test pass: "does this pass the bar, is there something better?"
**Reviewed artifacts:** `README.md`, `process-notes.md`, `packages/vibe-sec/framework.md`,
`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`, `docs/scope.md`,
`docs/prd.md`, `packages/vibe-sec-cli/README.md` + `src/index.js`.

> **This file is NOT output from `/vibe-sec:audit`, `/vibe-sec:gate`, or any planned
> Vibe Sec command.** It is an *external design review* — peer-style outside read on
> whether vibe-sec's design holds up against the industry security stack a stranger
> would reach for. Same destination spirit as the existing `docs/scope.md` and
> `docs/prd.md` (capture-the-thinking for `/spec` consumption), different provenance
> (outside-comparison, not internal Cart artifact chain).
>
> When entries here mature into concrete design changes, the natural place to fold
> them in is `docs/scope.md` (if they shift scope) or the research swarm's `/spec`
> phase (if they shift implementation defaults).

---

## Frame of the review

How does vibe-sec's design — tier-aware classification + 10-concern audit + research-swarm
implementation + four-band report — hold up against what's actually available in the
industry stack a stranger would compare it against: gitleaks, OSV-Scanner, Semgrep,
Snyk, CodeQL, Trivy, Syft, OWASP ASVS, OWASP Top 10, OWASP SAMM, NIST SSDF, OWASP
Threat Dragon, GitGuardian, Socket.dev.

The review splits in two because vibe-sec is in two states: a working CLI (`@esthernandez/vibe-sec-cli@0.1`) and an extensively pre-designed plugin (`@esthernandez/vibe-sec@0.0.2`, reserved package name, no code yet).

---

## Part 1 — The shipped CLI

The 404-line pure-regex secret-leak scanner. ~15 patterns (AWS, GitHub PAT classic +
fine-grained, Stripe live/test, OpenAI, Anthropic, private key blocks, Slack, Google
API key, DB URLs with creds, JWT, generic `api_key/secret/password`, Google OAuth
client ID). Context-aware downgrade for `example|sample|mock|fake|placeholder|dummy|template|fixture`
paths. Suppression of known placeholder strings from official AWS/Stripe docs.
CI-friendly exit codes (0 clean / 1 findings / 2 scanner error). `--min-severity`
flag for tuning CI strictness. `--json` for machine output.

It's small, honest, and behaves correctly. The single biggest thing it competes
against in this exact category is **gitleaks** — ~6000 lines of Go, 200+ rules,
entropy analysis, git-history scanning (yours scans working tree only), allowlisting,
mature config format. The CLI is good for "no install, no account, ships with the
plugin." Gitleaks is good for "actually catch everything that's been committed."

The right framing is composition, not competition: when gitleaks is present, defer
to it; when it isn't, fall back to the 404 lines. The scope doc gestures at this
("optional local gitleaks if builder has it installed") but should make it a
**first-class Pattern #13 anchored complement**, not a maybe. Same goes for
**trufflehog** for git-history scanning, which is a real gap — the CLI today scans
working tree only.

The CLI is the single most credible-feeling Vibe Sec artifact today. Don't promote
it into a TypeScript plugin primitive prematurely — first wire it up to defer to
gitleaks when present. The "ships as a tool, not a toy" feeling matters
disproportionately for security tools; they're judged harder than testing tools.

---

## Part 2 — The designed plugin (v0.2 target)

### What's working in the design — don't lose these

1. **The four-band report structure.** Critical/high now → tier-appropriate
   educational → graduating-tier forward-looking → Pattern #13 complement
   recommendations. This treats security as something the builder is *learning into*,
   not a 10,000-findings dump. The educational and forward-looking bands are the
   single biggest UX differentiator from every commercial SAST/SCA tool, all of
   which optimize for "more findings = more value." This is right, and it's
   distinctive.

2. **The research-swarm pattern (10 parallel expert-persona agents at `/spec` time
   → durable briefs → synthesis → implementation).** This is the right answer to
   the well-known failure mode of self-built security tools, which is that one
   author cannot know 10 security domains deeply enough to ship them well. Most
   commercial security tools hire 3 security researchers and call it a day; the
   research-swarm spends more domain-effort up-front per concern than that. The
   architecture is genuinely above the bar — assuming the briefs land sharp (see
   load-bearing assumption below).

3. **12% FP commitment, explicit.** Anyone promising sub-5% FP on security
   detection is either lying or so noisy nobody trusts the output. Calibrating to
   12% is honest about the harder-than-testing domain and sets a defensible bar.

4. **Confidence-tier routing for `/fix` with destructive-action overrides.**
   Auto-apply only `.gitignore` and additive headers. Never auto-apply secret
   rotation, auth logic changes, JWT/session-secret regen. This is the line that
   distinguishes tools from footguns. The hard-coded overrides table is correct
   and should not be loosened under user pressure.

5. **CVSS passthrough for CVE findings.** Don't reinvent the industry severity
   standard for things that already have a canonical score.

6. **Hybrid 4-level severity (Critical/High/Medium/Low) for own findings.** Same
   pattern as every mature security tool. Don't try to do 5-level or 3-level —
   builders already have a mental model from CVE ratings.

7. **Composition handshake with vibe-test (`covered-surfaces.json` ↔
   `findings.jsonl`).** Vibe-sec elevating priority on untested admin endpoints,
   vibe-test elevating priority on security-flagged surfaces. The industry
   doesn't do this — security and testing tools are siloed. This is one of the
   genuinely novel capabilities in the design.

8. **Builder-sustainable `docs/SECURITY.md` handoff.** The security equivalent of
   vibe-test's TESTING.md. Most security tools dump JSON and let the builder
   figure it out. A runbook-grade markdown artifact is rare and correct.

### Where it's load-bearing on guesses

1. **The tier thresholds (30 / 55 / 70 / 80 / 90) are hand-picked, again — and
   slightly different from vibe-test's (40 / 55 / 70 / 85 / 90)** for no documented
   reason. Same answer as for vibe-test: map these to **OWASP ASVS L1/L2/L3**
   explicitly. Prototype = no formal verification. Internal = ASVS L1. Public-facing
   = ASVS L2. Customer-facing SaaS = ASVS L3. Regulated = ASVS L3 + NIST SSDF
   practices (PO, PS, PW, RV) + SBOM (Syft passthrough). Without this mapping,
   "regulated tier" is aspirational. With it, the whole tier model becomes
   defensible by reference to a standards body.

2. **The research-swarm is unproven and load-bearing.** "~1–2 hours wall-clock +
   meaningful token spend" up-front is real investment, and the entire
   implementation anchors on the synthesis being sharper than just reading the
   OWASP Cheat Sheet Series and Snyk's documentation. The mitigation is right
   there in the design (durable briefs are human-reviewable artifacts) — but the
   risk is 10 mediocre briefs synthesized into one mushy synthesis, with
   implementation then anchored on agent-generated rather than human-vetted
   security knowledge.

   **Suggested pressure-test:** before committing the full ten, run a
   **2-concern micro-swarm** on A03 Injection and A07 Auth Failures (the densest
   domains). Evaluate the briefs against existing OWASP Cheat Sheets + Snyk docs.
   If briefs are clearly additive, commit to the ten. If they regress, the
   architecture probably needs to *seed* the agents with OWASP/Snyk canonical
   material rather than ask them to generate from scratch.

3. **The v0.2 "no-account baseline" reinvents what free, no-account tools already
   do well.** This is the single biggest category error in the current design.
   - `npm audit` passthrough is way thinner than **OSV-Scanner** (Google's free,
     no-account, multi-ecosystem scanner against OSV.dev — npm, pypi, go, rust,
     java, ruby, all of it).
   - Custom TypeScript AST walkers for auth-middleware / route inventory / PII
     detection compete with **Semgrep CE** (free, no-account, 2000+ community
     rules including security ones).
   - Custom regex for secrets competes with **gitleaks** (already discussed).
   - No container scanning competes with **Trivy** (free, comprehensive, multi-target).

   The design correctly treats Snyk / Socket.dev / Semgrep commercial /
   GitGuardian as Pattern #13 complements deferred to "future runs" — but it puts
   the **free, no-account** versions of those exact capabilities (OSV-Scanner,
   Semgrep CE, gitleaks, Trivy) in the same "future runs" bucket. They belong in
   the **v0.2 first-class anchored complements** list, used by default when
   present, with the in-house implementations as the genuine fallback only.

4. **"Full OWASP Top 10 categorical coverage" risks promising more than static
   analysis can deliver.**
   - **A04 Insecure Design** is essentially threat modeling — not detectable
     statically, requires human adversarial reasoning.
   - **A09 Security Logging Failures** mostly requires runtime instrumentation,
     not static scan.
   - **A10 SSRF** needs flow analysis hard to do without CodeQL-grade tooling.

   The framework already says "Layer 3 needs the human" for threat modeling, so
   the internal language is careful — the marketing-adjacent surfaces (README,
   scope doc bullet list) should match that care. Honest claim: "Covers A01–A03
   / A05–A08 deeply; A04 / A09 / A10 require Layer 3 human judgment, plugin
   facilitates rather than detects."

5. **License compliance, SBOM, container/IaC scanning all deferred to v0.3+.**
   Fair for v0.2 scope, but increasingly table-stakes for the regulated tier.
   US Executive Order 14028 and the EU Cyber Resilience Act both push SBOM
   requirements down to anyone shipping software meaningfully. Worth signaling
   that "regulated tier" honestly requires SBOM, even if vibe-sec's role is to
   defer to **Syft** (free, CycloneDX/SPDX) for generation rather than build it.

6. **No mention of NIST SSDF, SLSA, or OWASP SAMM.** These are the meta-frameworks
   that security programs actually align maturity against. ASVS gets you the
   requirements; SSDF/SAMM are the maturity models. For "regulated" tier to
   resolve to something defensible, mapping to NIST SSDF practices closes the
   credibility loop.

---

## What "better" looks like, by question

| Question | What you'd actually want |
|---|---|
| "Are my secrets in the repo?" | **gitleaks** or **trufflehog** (with git history, not just working tree) |
| "Are my deps vulnerable?" | **OSV-Scanner** (free, multi-ecosystem, no account) — strictly better than `npm audit` alone |
| "Is my code injection-safe?" | **Semgrep CE** + community rules — much broader than custom AST walkers will be |
| "Are my containers safe?" | **Trivy** (free, comprehensive, multi-target) |
| "Is my IaC safe?" | **Checkov** / **tfsec** |
| "Does my app meet ASVS L2?" | OWASP ASVS spreadsheet + manual review (vibe-sec could automate ~40% of this) |
| "Do I have a threat model?" | **OWASP Threat Dragon** (free, STRIDE-based) — vibe-sec's `:threat-model` competes here |
| "Am I shipping a SBOM?" | **Syft** (free, generates CycloneDX/SPDX) |
| "Am I aligned with a maturity model?" | **OWASP SAMM** or **NIST SSDF** — vibe-sec's tier model is implicitly one of these |

---

## Verdict

Vibe-sec **passes** the litmus test of *"is there a useful audit layer that ties
security posture to the actual deployment tier of vibe-coded apps, framed as a
learning surface not a 10,000-findings dump."* That's a real underserved category
— most security tools are either enterprise-grade and noisy, or shallow and
checklisty. The four-band report, tier-aware classification, builder-sustainable
SECURITY.md handoff, and composition handshake with vibe-test are all distinctive
and right.

Vibe-sec does **not yet** pass the litmus test of *"can I delete Snyk + Semgrep +
gitleaks + OSV-Scanner + Trivy + Syft and use this instead"* — and the scope doc
correctly says it shouldn't try to ("Not a SAST replacement at scale. Semgrep,
Snyk, CodeQL are specialists; we offer the tier-aware audit layer ON TOP of
whichever of those the builder has").

The unresolved tension is that the v0.2 baseline as written **implies it's trying
to** — because it reinvents pieces of those tools in custom TypeScript instead of
deferring to their free, no-account versions. Resolving that tension is the
biggest unlock on the list below.

---

## Ranked unlocks (biggest credibility-per-effort first)

### 1. Promote the free, no-account industry tools into v0.2 first-class anchored complements

Single highest-leverage change. Move **OSV-Scanner, Semgrep CE, gitleaks, Trivy,
Syft** from "v0.3 Pattern #13 future runs" into v0.2 first-class anchored
complements. Defer to them when present; use the in-house baseline only when
they're not.

This reframes vibe-sec from *"we built a security scanner"* to *"we built the
tier-aware audit layer that orchestrates security scanners"* — which is the
positioning the scope doc actually wants ("Not a SAST replacement at scale... we
offer the tier-aware audit layer ON TOP"). Right now the scope says one thing and
the v0.2 baseline implementation says another.

Concrete edit: update `packages/vibe-sec/framework.md` and `docs/scope.md`'s
"v0.2 no-account baseline" section to split into two tiers:

- **First-class anchored complements (v0.2)**: OSV-Scanner, Semgrep CE, gitleaks,
  Trivy, Syft. Each gets a `plays-well-with.md` entry with a deferral contract.
- **Built-in baseline (when complements absent)**: own regex for secrets, npm
  audit shell-out, own config-file inspectors, own AST walkers.
- **Commercial Pattern #13 complements (future)**: Snyk, Socket.dev, Semgrep
  commercial, GitGuardian. Surfaced for "future runs" when builder isn't
  mid-security-fatigue.

### 2. Calibrate tier thresholds against OWASP ASVS L1/L2/L3 + NIST SSDF for regulated

Same fix as the vibe-test review proposed, but more important here. Security has
an external standards body; "we picked these numbers ourselves" lands much worse
for security than for testing. Mapping:

| Vibe Sec tier | External standard mapping |
|---|---|
| Prototype | No formal verification target |
| Internal | OWASP ASVS L1 |
| Public-facing | OWASP ASVS L2 |
| Customer-facing SaaS | OWASP ASVS L3 |
| Regulated | OWASP ASVS L3 + NIST SSDF practices (PO, PS, PW, RV) + SBOM (Syft) |

Cite the mapping in framework.md. Removes the "where did 30/55/70/80/90 come
from" objection AND gives builders a known-quantity verification target they
can describe to auditors and customers.

### 3. Pressure-test the research-swarm with a 2-concern micro-run before full commit

Don't commit ~$1–2K of tokens to a synthesis that anchors implementation until
the brief-quality assumption is validated. Run A03 Injection + A07 Auth Failures
first. Evaluate against existing OWASP Cheat Sheets + Snyk's docs. Three
outcomes:

- **Briefs are clearly additive** (sharper, more specific, more current than
  OWASP Cheat Sheets): commit to the full 10.
- **Briefs are comparable**: commit to 10 with reduced expectations — the win is
  consolidation, not new intelligence.
- **Briefs regress from reading the OWASP source**: redesign. Likely needs to
  *seed* agents with OWASP/Snyk canonical material as input context rather than
  ask them to generate from scratch.

### 4. Promote the CLI to gitleaks-composition rather than standalone scanner

Wire `vibe-sec scan` to defer to gitleaks when present (`which gitleaks` → use
it, parse JSON output, downgrade-aware the same way the regex pass already
handles `example|sample|mock` paths). When gitleaks isn't present, fall back to
the 404-line regex baseline.

This makes the shipping piece *immediately* more credible without writing 5,000
more lines of Go-equivalent in TypeScript. Same pattern for trufflehog when
git-history scanning is requested (the CLI today scans working tree only — a
real gap).

### 5. Soften the "Full OWASP Top 10 categorical coverage" claim to match the framework's care

The framework already says A04 needs threat modeling and Layer 3 needs the human.
The marketing-adjacent surfaces (README, scope-doc bullet list, eventual
landing-page copy) should match that humility:

> "Covers A01–A03 / A05–A08 with static-analysis depth. A04 (Insecure Design),
> A09 (Logging Failures), and A10 (SSRF) require Layer 3 human judgment; the
> plugin facilitates threat modeling and surfaces hot spots rather than claiming
> autonomous detection."

Honest claim is the more defensible one when the first 5% of users with security
backgrounds kick the tires.

---

## Comparison to the vibe-test review

The two plugins are at very different maturities (vibe-test ships and works;
vibe-sec is mostly designed). But the load-bearing-assumption pattern is the
same:

| Concern | Vibe Test | Vibe Sec |
|---|---|---|
| Hand-picked tier thresholds | Yes (40/55/70/85/95) | Yes (30/55/70/80/90) — different from vibe-test for no documented reason |
| Reinvents what free tools do | Mutation testing gap | Reinvents OSV/Semgrep/gitleaks/Trivy in v0.2 baseline |
| Calibrate against external standard | Should map to OWASP ASVS | Same — plus NIST SSDF + SBOM for regulated |
| Composition framing | Right direction, partial execution | Right direction, partial execution (free tools mis-bucketed) |

Vibe-sec's design is actually *more* sophisticated than vibe-test's
implementation in several dimensions (research-swarm, four-band report,
destructive-action overrides on `/fix`). The risk profile is also higher —
security tools are judged hard, false positives erode trust faster, and
reinventing what gitleaks/Semgrep/OSV-Scanner already do well is a credibility
tax you don't have to pay.

The unlocks above mostly amount to: ship the audit layer as designed, defer the
underlying scanning to the established free tools, calibrate the tier model
against ASVS so the numbers stop being yours alone.

---

*End of external review.*
