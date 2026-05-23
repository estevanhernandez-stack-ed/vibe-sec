# Vibe Sec

> *"Everything is in scope at 626Labs LLC."*
> *"Work from the future. We are already behind."*
> *"Leave the builder self-sufficient — with or without us."*

**Target release:** v0.2 (first full plugin release)
**Authored:** 2026-04-19 during the `/scope` phase of Vibe Cartographer
**Persona:** Architect (same as Vibe Test)
**Mode:** Builder
**Inputs:** `docs/builder-profile.md`, `packages/vibe-sec/framework.md` (thesis), `packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md` (positioning + handshake schemas), Vibe Test's full artifact chain as architectural reference

## Idea

A Claude Code plugin that **performs a tier-aware, classification-first security audit of vibe-coded applications** — the diagnostic counterpart to Vibe Test's testing audit. Ten security concerns covered with domain depth, calibrated to the builder's actual deployment tier (prototype → customer-facing SaaS → regulated). Ships alongside its CLI sibling (`@esthernandez/vibe-sec-cli@0.1.1`, secret-leak scanner, already live on npm) as the fourth plugin in the 626Labs `vibe-plugins` marketplace.

Distinctive architectural move: the plugin is **built from parallel domain-research-agent synthesis**. 10 expert-persona agents research one security concern each at `/spec` time, produce durable briefs, and their consolidated findings drive the implementation. The plugin ships with genuine domain depth in each area rather than author-intuition across ten unevenly-familiar domains.

Companion thesis (`packages/vibe-sec/framework.md`) and positioning (`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`) are both pre-written and committed.

## Who It's For

**Primary:** Builders shipping vibe-coded apps who reach the security question LAST. They're tired by the time they get there. They don't want to sign up for five new tools. They need an honest, tier-appropriate read on what actually matters for their specific deployment — not a generic OWASP checklist, not SAST-grade false-positive spam.

**Specific segments:**
- Solo builders post-PMF transitioning from internal-demo to public-facing
- Agency builders handing off vibe-coded MVPs to clients with security expectations
- Indie builders at the internal-beta → public-launch tier boundary
- Engineers inheriting vibe-coded repos where the security surface was never mapped

**The gap Vibe Sec fills** (per `gap-analysis-as-of-vibe-test-v0.2.md`):

The 626Labs ecosystem has Cart (planning + architecture), Vibe Doc (documentation completeness), Vibe Test (test audit + generation). Each touches security at the edges of its primary concern but **none does security as first-class audit**. Vibe Sec owns ten concerns no sibling plugin covers:

1. Dependency CVE audit / Software Composition Analysis
2. Secret detection in working tree + git history
3. OWASP Top 10 categorical audit (A01–A10)
4. Crypto / PII handling audit
5. Config-level security posture (CSP, CORS, security headers)
6. Supply chain hardening (lockfile integrity, dependency pinning)
7. Rate limiting + abuse protection posture
8. Auth model static analysis (role/permission matrix audit)
9. Threat model generation (STRIDE/DREAD-style from inventory)
10. Security-tier thresholds + gating (mirror of Vibe Test's tier model, security-flavored)

## Inspiration & References

**Shared 626Labs scaffolding:**
- [`packages/vibe-sec/framework.md`](../packages/vibe-sec/framework.md) — Vibe Sec thesis
- [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](../packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md) — positioning + handshake schemas
- `docs/self-evolving-plugins-framework.md` (to be copied from `vibe-test/` or `app-readinessplugin/` into this solo) — the Pattern #1–16 playbook

**Sibling plugins (inherited house pattern):**
- Vibe Cartographer — slash commands, SKILL.md files, `docs/`-driven artifacts, architect-voice reports with clear hierarchy
- Vibe Doc — documentation completeness as a discipline; Vibe Sec composes with it for threat-model generation
- Vibe Test — the most directly-referenced architectural precedent: tier-classification, weighted-score calculation, three-channel output (markdown + banner + JSON sidecar), builder-sustainable handoff

**Ecosystem complements Vibe Sec will defer to (Pattern #13 "Plays well with"):**
Deferred as **post-v0.2 expansion paths** per the "minimize infrastructure lag" design principle — these require accounts/installs the builder is least willing to accept during the tired-from-security moment. Surfaced for "future runs" once initial audit is done.

- **Snyk** — deep SCA + runtime vulnerability intelligence
- **Socket.dev** — supply-chain risk scoring
- **Semgrep** — pattern-based SAST
- **GitGuardian** — secret detection at commit time
- **gitleaks** — local secret-scan baseline (optionally used by Vibe Sec itself if installed)
- **OWASP ZAP / Burp** — runtime penetration testing (categorically out of scope for v0.2)
- **trufflehog** — historical secret-scan
- **Dependabot / Renovate** — automated dependency updates

For v0.2 the no-account baseline: **`npm audit`** (built-in), **OSV open database** (no account, direct API), optional local **gitleaks** if builder has it installed.

**First-patient / dogfood target:**
- **WeSeeYouAtTheMovies** — same target as Vibe Test's dogfood, but with real stakes this time. The app is planned to transition from **Internal (associate-facing)** to **Public-facing (open web)**. Vibe Sec v0.2's dogfood acceptance test is running against WSYATM's actual pre-launch hardening, surfacing the security bar the app needs to meet at Public-facing tier. Real launch ammunition — not a synthetic demo.

## Goals

**Option C — thesis + plugin, sequenced** (same as Vibe Test).

### 1. Thesis (`framework.md` published as essay/blog)

Success = the *argument* lands — it reframes what security hygiene means for AI-prototyped apps. Audience: builders + engineers thinking about the security vacuum in vibe-coded applications.

### 2. Plugin (`vibe-sec` ships to the 626Labs marketplace as v0.2+)

Success metrics:
- Builder installs plugin, runs `/vibe-sec:audit` against their app, gets a report that is *tier-appropriate*, *curated*, and *educational* — not a compliance checklist
- All 10 concerns covered with domain-research depth (via the research-swarm approach)
- False-positive rate: **12%** across the board (harder-than-testing domain; matches security-tool industry expectations; looser than Vibe Test's <5% because security detection is genuinely more fuzzy)
- WSYATM dogfood: Vibe Sec identifies the security bar for Public-facing tier transition and surfaces what needs to change before the app opens up

### North star

A builder who just shipped a vibe-coded app runs `/vibe-sec:audit` in a Claude Code session and gets an honest, tier-appropriate read on the specific security surfaces that matter for *their* deployment context. The report tells them what to fix NOW, what's fine-at-this-tier but worth reading, what'll matter when they graduate, and what tools belong in their toolbelt for ongoing security practice.

## What "Done" Looks Like

**v0.2 first full-plugin release ships with:**

### Command surface (router + 8 subcommands = 9 top-level)

```
/vibe-sec              # router — intro + guided entry point
/vibe-sec:audit        # full 10-concern audit, tier-calibrated
/vibe-sec:scan         # secret-leak scan (promoted from CLI)
/vibe-sec:fix          # confidence-tier-routed remediation (non-destructive auto; destructive always staged/inline)
/vibe-sec:gate         # CI-safe pass/fail against app's security tier
/vibe-sec:posture      # ambient tier-aware security posture summary
/vibe-sec:threat-model # STRIDE/DREAD-style model generation from inventory
/vibe-sec:deps         # dependency CVE audit (npm audit + OSV passthrough)
/vibe-sec:research     # re-run domain-research agent for one concern (living docs pattern)
```

(Consolidation from 9 → 7–8 may happen during `/spec` if any commands overlap meaningfully.)

### Classification model

**5 maturity tiers** (mirror of Vibe Test's, security-flavored thresholds):

| Tier | Security bar (weighted-score style) | Expected concern coverage |
|---|---|---|
| Prototype / hackathon | 30% | Secret scan + basic dep audit only |
| Internal tool | 55% | + secret scan history, basic auth posture, config baseline |
| Public-facing | 70% | + OWASP Top 10 categorical audit, CORS/CSP posture, threat model |
| Customer-facing SaaS | 80% | + PII handling audit, multi-tenant isolation, crypto audit, rate limiting |
| Regulated / enterprise | 90% | + full compliance surface, supply chain hardening, deep auth model analysis |

(Exact per-concern applicability matrix is a `/spec`-time output, informed by research briefs.)

### Confidence-tier routing for `/vibe-sec:fix`

Same 3-tier routing as Vibe Test (auto ≥0.90 / stage 0.70–0.89 / inline <0.70), **with destructive-action overrides**:

| Fix type | Confidence-tier behavior |
|---|---|
| `.env` missing from `.gitignore` | Auto-apply regardless of confidence |
| Security headers (CSP / HSTS / cookie flags) | Auto-apply if additive; stage if replacing existing config |
| CORS wildcard → explicit origins | Stage (may break frontend) |
| CVE-flagged dep bump | Stage (may break tests — Vibe Test runs on accept to verify) |
| Leaked secret rotation | **Never auto** — always inline, with ops-checklist remediation |
| Auth logic changes | **Never auto** — always inline, detailed rationale |
| JWT/session secret regen | **Never auto** — invalidates live sessions |
| Adding missing security surface (helmet.js, rate limiter, etc.) | Confidence-tier routing normally |

### Severity + report model

- **Hybrid severity:** 4-level (Critical / High / Medium / Low) for Vibe Sec's own findings + **CVSS passthrough** for CVE findings from `npm audit` / OSV
- **Tier × concern drives severity** (e.g., committed AWS key is Critical at Public-facing, High at Prototype)
- **False-positive commitment:** **12% FP** across-the-board
- **Four-band report structure** (the "curated + boundary-expanding" design brief applied to security):
  1. **Critical / High** — action needed now
  2. **Tier-appropriate but worth reading** — educational surface about security classes at this tier
  3. **Tier-inappropriate but if you graduate** — forward-looking guidance for the graduating-to-next-tier story
  4. **Pattern #13 complements** — tools that would catch classes we don't

### Research-swarm architecture (the distinctive move)

**Runs at `/spec` time, not `/build` time.** 10 parallel expert-persona domain-research agents, one per security concern, each producing a durable `docs/research/<concern>.md` brief with this shape:

- Landscape — current best practices, OWASP position, industry tools
- Detection mechanics — how to identify the concern programmatically
- False-positive risks — classes of legit-code that look like findings
- Remediation patterns — what fixes look like
- Pattern #13 complements — tools that already solve this well
- Tier applicability — at which maturity tiers does this matter

**Conflict resolution: staged synthesis + builder-resolve.**

- Synthesis agent runs automatically post-swarm → produces `docs/research/synthesis.md` draft with automated conflict resolutions where the call is clear
- Remaining conflicts surface to Este at `/spec` time as explicit architect-question list
- C (mechanical voting) rejected — security depth needs judgment, not majority rule

**Living docs.** `/vibe-sec:research --concern <name>` re-runs one concern's agent periodically. Updates the brief as OWASP guidance shifts, new CVE classes emerge, new tools mature. Feeds Pattern #14 wins.jsonl loop.

**Cost posture.** 10 parallel agents + 1 synthesis = significant wall-clock (~1–2 hours per full swarm) + meaningful token spend. Explicitly budgeted as a **one-time investment per release cycle**, not a recurring cost. Re-runs are per-concern and targeted.

### Three-channel output

Same three-render pattern as Vibe Test (markdown primary + ANSI terminal banner + JSON sidecar). Consistency across the marketplace matters.

- Markdown artifact in `docs/vibe-sec/` of the target project — durable runbook-grade
- Terminal banner in-chat — live curation + education surface
- JSON sidecar in `.vibe-sec/state/<command>.json` — machine-readable for CI + cross-plugin consumption

### Vibe Test composition (handshake contracts)

Per the gap-analysis document's concrete schemas:

- **Vibe Test → Vibe Sec:** read `.vibe-test/state/covered-surfaces.json` if present. De-prioritize audit depth on already-behaviorally-tested surfaces; elevate priority on untested-admin-endpoint-style surfaces. Use the tier classification from `audit.json` if fresh.
- **Vibe Sec → Vibe Test:** write `.vibe-sec/state/findings.jsonl` — append-only, one finding per line. Vibe Test reads this at `/vibe-test:generate` time to elevate edge-case-test priority on security-sensitive surfaces.
- **Fallback when absent:** Vibe Sec runs its own tier classification via the same inventory patterns Vibe Test uses (`src/scanner/classify-app-type.ts`). Either inherit or re-scan — never fail.

### v0.2 no-account baseline — orchestration-first (revised at `/spec`)

**The pivot (locked at `/spec`, per the 2026-05-22 external litmus review):** Vibe Sec is the **tier-aware audit and orchestration layer, not another scanner.** It defers to the established free, no-account security tools when they're present on the system and runs an in-house TypeScript baseline ONLY when those tools are absent. The product is the layer — classification, severity calibration, four-band report, fix routing, threat-model synthesis — not the raw detection underneath. Per concern, a deferral contract names the external tool of record (used when present) and the in-house fallback scope (used when absent). See `docs/spec.md` §3 for the full per-concern table.

**First-class anchored complements (v0.2 — use by default when present, credit the tool):**
- **OSV-Scanner** — multi-ecosystem CVE scanner against OSV.dev; primary for SCA when present (strictly better than `npm audit` alone)
- **Semgrep CE** — 2000+ community rules; defer deep injection (A03) + crypto + authz analysis when installed
- **gitleaks** — secret scan, working tree + git history; defer when present
- **trufflehog** — git-history secret scan + live verification (`--verify`); defer when present
- **Trivy** — container scanning; surfaced when a Dockerfile is present
- **Syft** — SBOM generation (CycloneDX/SPDX) at Regulated tier

**In-house baseline (the genuine fallback, used ONLY when the anchored complement is absent):**
- `npm audit` shell-out + OSV.dev direct batch query (dedupe by ID) for CVE classification
- Own TypeScript regex + entropy + AST-walk for secret detection (promoted from CLI), with full git-history scan
- Own config-file inspectors (Next.js headers, vite.config, .env.example, firebase.json, vercel.json, etc.)
- Own static analysis for auth-middleware detection, route inventory, tenant-isolation, PII-field detection
- CVE-2025-29927 baked-in rule (not a pass-through npm-audit hope)

**Commercial Pattern #13 complements** — surfaced in Band 4 for "future runs" (the builder is willing to install more when not mid-security-fatigue):
- Snyk free tier for reachability + license scanning
- Socket.dev (Firewall Free) for supply-chain attack-window novelty
- GitGuardian for commercial real-time commit-time secret detection
- Dependabot / Renovate for automated dependency updates
- OWASP ZAP / Burp for runtime pen testing (v0.3+ territory)

### Monorepo / solo-repo shipping context

- Ships from `packages/vibe-sec/` in the `vibe-sec` solo repo (`github.com/estevanhernandez-stack-ed/vibe-sec`)
- Canary channel: `estevanhernandez-stack-ed/vibe-sec` (tracks solo `main`)
- Stable channel: aggregated `vibe-plugins` marketplace pins to a specific tag
- npm: `@esthernandez/vibe-sec` (plugin) + `@esthernandez/vibe-sec-cli` (CLI)
- CLI becomes a **thin wrapper** around the plugin's TypeScript primitives (same pattern as Vibe Test — secret-scan logic promoted from CLI into `packages/vibe-sec/src/secrets/`, CLI re-exports for headless CI use)

### First-patient acceptance bar

**Vibe Sec v0.2 passes when:**
- `/vibe-sec:audit` against real `C:\Users\estev\Projects\WeSeeYouAtTheMovies\` produces a correct **Public-facing tier** (or Customer-facing-SaaS) classification, given WSYATM's planned transition from associate-facing to open web
- All 10 concerns surface findings (or honest absence-of-findings) with the four-band report structure
- The false-positive rate on WSYATM's findings stays ≤12%
- The dogfood run produces real pre-launch hardening guidance Este actually uses before opening WSYATM to the public
- `/vibe-sec:gate --ci` in mocked `GITHUB_ACTIONS=true` exits with correct code + GitHub Actions annotations

## What's Explicitly Cut

**Deferred to v0.3+ (everything is in scope at 626Labs LLC, just not on the first truck):**

| Capability | Deferred to | Why |
|---|---|---|
| Runtime penetration testing | v0.3+ (or never) | Different discipline; ZAP/Burp are specialists; out of the static-audit positioning |
| Paid SCA as required dependency | v0.3 as opt-in complement | Minimize-infrastructure-lag principle |
| Compliance certification document generation (HIPAA/SOC2 audit prep) | Not our problem | Adjacent concern; specialists exist |
| Real-time runtime monitoring | Not our category | Observability, not audit |
| License compliance | v0.3+ or never | Adjacent concern; separate audit |
| Full cloud-infrastructure IAM audit | v0.3+ or never | Cloud-level, not app-level |
| Autonomous security fix application without builder approval | **Never** | Same hard line Vibe Test drew — propose, never auto-apply destructive changes |
| Python / Go / Rust project support | v0.3+ | JS/TS focus for v0.2, matches Vibe Test's v0.2 scope |
| Cross-repo supply chain audit | v0.4+ | Niche; grows into plugin if user base demands |

**Explicit non-goals (identity-protecting):**

- **Not a pentesting tool.** We statically analyze; we don't exploit.
- **Not a SAST replacement at scale.** Semgrep, Snyk, CodeQL are specialists; we offer the tier-aware audit layer ON TOP of whichever of those the builder has.
- **Not a compliance certifier.** We surface concerns; we don't produce HIPAA/SOC2 audit paperwork.
- **Not a runtime monitoring tool.** Observability tools (Datadog Security, Panther) are categorically different.
- **Not a replacement for security expertise.** Builder-sustainable handoff exists so builders own their security practice. The plugin augments, never substitutes for judgment.

## Loose Implementation Notes

*Non-binding. Gets refined in `/spec` (after research swarm).*

### Plugin structure (inherits Vibe Test's agent-heavy pattern)

- **SKILL-primary:** classification, report narrative, remediation proposals, threat-model generation, research-agent orchestration — all live in SKILL.md markdown
- **Deterministic TypeScript in `src/`:** secret-pattern regex, config-file parsers, `npm audit` shell-out, OSV API client, AST walkers for auth-middleware + PII detection, state I/O, CLI entrypoint
- **No paid-API dependencies in v0.2 runtime**
- **Build tool:** tsup (matches Vibe Test)
- **Test runner:** vitest (matches Vibe Test)
- **State storage:** `~/.claude/plugins/data/vibe-sec/` (profile, sessions, friction, wins) + `<project>/.vibe-sec/` (per-project state, pending fixes, findings)

### Research artifacts shipped with the plugin

- `docs/research/<concern>.md` × 10 — one per security concern, living doc
- `docs/research/synthesis.md` — consolidated resolved-conflict synthesis
- `docs/research/conflicts.md` — unresolved conflicts list, updated per research re-run

### Files Vibe Sec emits per run

- `<target>/.vibe-sec/state/audit.json` — classification + per-concern findings summary
- `<target>/.vibe-sec/state/findings.jsonl` — individual findings (for Vibe Test consumption)
- `<target>/.vibe-sec/pending/` — staged fixes awaiting builder review
- `<target>/docs/SECURITY.md` — builder-sustainable handoff runbook (security equivalent of Vibe Test's TESTING.md)
- `<target>/.github/workflows/vibe-sec-gate.yml` — opt-in CI config stub

### Open questions for `/spec` to resolve

1. **Tier × concern applicability matrix.** Exact spec-time output from research briefs.
2. **`findings.jsonl` schema concretization.** gap-analysis had a sketch; `/spec` locks it.
3. **Research-agent prompt templates.** Expert-persona charter + brief-shape contract.
4. **CLI-as-thin-wrapper migration.** How the existing `src/index.js` in `vibe-sec-cli` rewires to consume plugin primitives.
5. **Reporting cadence policy.** Every audit fresh? Cache findings for 7 days? Watch-mode incremental? (Probably on-demand per command; `/vibe-sec:posture` reads cached.)
6. **Consolidation of 9 commands → 7–8.** Is `:deps` separate from `:audit`, or folded in? `:scan` vs `:audit`?
7. **Vibe-Doc integration depth for threat-model handoff.** Co-author `docs/SECURITY.md` with vibe-doc when present?
8. **Tier-threshold numeric calibration.** Research-informed decision: do the 30/55/70/80/90 thresholds carry over from Vibe Test, or does security need different numerics?

## Appendix — Decision Log from `/scope`

**Mandatory questions (6):**

1. **v0.2 scope** → All 10 concerns, research-swarm-first approach (not a capability cut)
2. **CLI vs TypeScript** → CLI logic promoted to plugin TypeScript; CLI becomes thin wrapper
3. **Tier classification inheritance** → Compose with Vibe Test's classifier when present, fall back to own scan
4. **Infrastructure lag minimization** → npm audit + OSV baseline; commercial tools are Pattern #13 complements for future runs
5. **Command surface** → Router + 8 subcommands = 9 top-level (may consolidate during `/spec`)
6. **First patient** → WeSeeYouAtTheMovies at its associate-facing → public-facing tier transition (real pre-launch stakes)

**Round 2 deepening (20+ locked decisions):**

- Research orchestration: `/spec` time, durable briefs, parallel, expert personas, living docs, new `/vibe-sec:research` command
- Severity: hybrid 4-level + CVSS passthrough, tier × concern drives severity, four-band report
- False-positive: 12% across-the-board commitment
- `/vibe-sec:fix` authority: confidence-tier routing + destructive-action overrides; folds "harden" into "fix"
- Conflict resolution: staged synthesis + builder-resolve at `/spec` time

**/scope deepening rounds:** 1 (unusual for Este — zero was expected; research-swarm novelty justified extra depth)

**Active shaping observed:** Este pushed on Q1 with the swarm-research move (architectural ambition increase), on Q4 with no-account baseline (user-fatigue-aware design), and on Q6 with the WSYATM tier-transition (real-stakes dogfood). Three load-bearing architectural decisions driven by the builder, not the agent.

---

*End of scope. Next: `/spec` — translate these requirements into a technical blueprint. Research-swarm dispatch happens as the first substantive `/spec` beat.*
