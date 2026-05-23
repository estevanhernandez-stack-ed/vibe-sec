# Builder Profile — Vibe Sec

> Returning-builder compressed profile. Identity and technical experience are sourced from the unified profile at `~/.claude/profiles/builder.json` (last updated 2026-04-18). Only project-scoped fields are elaborated here.

## Who They Are

**Estevan Hernandez.** Builder and outsider, based in Fort Worth. Runs 626Labs. Fourth Vibe Cartographer run this month (Sanduhr shipped, Cart meta-dogfood in flight, Vibe Test v0.2 shipped 2026-04-18, now **Vibe Sec**). Vibe Sec is the fourth and currently-final plugin in the 626Labs Vibe Plugins marketplace.

Arrives at /scope with two pre-written thesis documents already committed to the Vibe Sec solo repo:

- **`packages/vibe-sec/framework.md`** — Vibe Sec's core thesis. Security gap finder for vibe-coded apps. Detects the predictable security gaps AI-prototyped applications ship with and fixes what it can. Tiered by app type and deployment context.
- **`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`** — The positioning doc written during Vibe Test's `/prd` phase (2026-04-17). Defines what Vibe Sec uniquely owns vs what the other three 626Labs plugins cover. 10 concerns mapped, handshake schemas defined, ship sequence locked (Vibe Test first, Vibe Sec second — already in flight).

## Technical Experience

**Level:** Experienced (per unified profile).
**Stack for this project:** Node 20+, TypeScript 5.x strict, pnpm workspaces. Matches Vibe Test's stack choices — shared architectural decisions from spec.md Decision 1 (agent-heavy split, thin `src/` deterministic primitives + rich SKILL markdown) apply here.
**AI agent experience:** Deep. Built Vibe Cartographer, Vibe Doc, and Vibe Test — all running in production via this marketplace.
**What he wants to explore for Vibe Sec specifically:** how to deliver security audit depth WITHOUT turning into yet-another-SAST-tool. The answer per `framework.md` is tier-awareness and classification-first, same playbook as Vibe Test.

## Mode

**Builder.** Brisk pacing, minimal process ceremony.

## Persona

**Architect.** Same as Vibe Test — framework-class work, tradeoff-heavy systems design ahead. The security domain especially rewards architect-voice reasoning because the interesting questions are all tradeoffs (coverage vs false-positive rate; tier thresholds; OWASP categorical depth vs signal-to-noise; integration handshake depth with Vibe Test + other tools).

## Project Origin

**Solo repo established 2026-04-19** as part of the monorepo → solo-repos migration:

- Repo: `github.com/estevanhernandez-stack-ed/vibe-sec`
- Packages already shipped:
  - `@esthernandez/vibe-sec@0.0.2` — reservation stub with plugin.json + framework.md
  - `@esthernandez/vibe-sec-cli@0.1.1` — 404-line secret-leak scanner, pure regex + light heuristics, CI-safe exit codes. **First actually-shipping Vibe Sec capability.**
- Stable channel: pinned at `vibe-sec-v0.0.2` in the aggregated `vibe-plugins` marketplace
- Canary channel: `estevanhernandez-stack-ed/vibe-sec` direct install (currently filtered out by Cowork because no commands/skills exist yet — /scope work will fix that)

**What's here already that /scope can lean on:**
1. `packages/vibe-sec/framework.md` — the full Vibe Sec thesis
2. `packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md` — positioning relative to Cart + Vibe Doc + Vibe Test, with concrete handshake schemas for Vibe Test integration
3. `packages/vibe-sec-cli/src/index.js` — 404 lines of working secret-scanner code (the first shipping capability of Vibe Sec), with 10+ detection patterns for AWS keys, GitHub PATs, Stripe keys, Firebase API keys, etc.
4. The Vibe Test codebase as architectural reference — same TypeScript + pnpm + vitest pattern carries forward

**Starting point:** not greenfield. Thesis + positioning + first shipping capability + architectural pattern all pre-existing. /scope's job is to sequence WHICH next capabilities ship in the full plugin and in what order.

## Project Goals

**Option C — thesis + plugin, sequenced** (same as Vibe Test).

Two artifacts:

1. **Thesis as essay/blog post.** `framework.md` + the gap-analysis ship as a published argument that reframes the AI-coding security conversation. Audience: builders and engineers thinking about what security hygiene *means* for AI-prototyped apps. Success = the argument lands; shifts how people think about "security for vibe-coded apps."
2. **Full plugin v0.2+ shipped.** Goes beyond the CLI's secret-leak scanner. `/vibe-sec:audit`, `/vibe-sec:scan`, `/vibe-sec:fix` (or whatever the command surface ends up being) — running against any vibe-coded app, classifying by tier, surfacing what uniquely matters for that tier. Ships from the solo repo's canary channel first, promoted to stable via the aggregated marketplace once proven.

**North star:** a builder who just shipped a vibe-coded app runs `/vibe-sec` in a Claude Code session and gets an honest, tier-appropriate audit of the specific security surfaces that matter for *their* deployment context — not a generic compliance checklist, not an OWASP Top 10 rote walkthrough, not a false-positive spam.

**Explicit scope constraint from prior conversation:** Vibe Sec must compose cleanly with the other three 626Labs plugins. It consumes `.vibe-test/state/covered-surfaces.json` (if present) to de-prioritize already-behaviorally-tested surfaces. It emits `.vibe-sec/state/findings.jsonl` for Vibe Test to consume and elevate priority on corresponding edge-case tests.

## Design Direction

**Plugin surface:** inherits the 626Labs house pattern — slash commands, `SKILL.md` files, `docs/`-driven artifacts, casual-but-sharp voice, banner-style reports with clear structural hierarchy. No deviation from Cart / Vibe-Doc / Vibe-Test conventions.

**Security output UX (the load-bearing design decision):** same "user-friendly AND boundary-expanding" design brief as Vibe Test, applied to the security domain. The report is not a compliance checklist. It is curation. It shows the builder:

- Which security surfaces the app actually has (auth flows, PII boundaries, injection vectors, crypto-at-rest points, third-party credentials) — a lot of vibe-coded apps don't know what their security surface IS
- Which of those surfaces matter at the app's tier (a prototype with 3 users doesn't need PCI-grade key management; a customer-facing SaaS does)
- Which are in good shape, which are tier-appropriate-but-could-be-hardened, which are wrong-for-this-tier and need action now
- What tools belong in their toolbelt for ongoing security practice — complements, not replacements (OWASP ZAP, snyk, etc.)

**Shared creative sensibility:** clean, functional, high-contrast. Dark themes, muted palettes, clear information hierarchy. Polish valued but never at the expense of shipping.

**Open design question for `/spec`:** report output channels. Same three-render pattern Vibe Test uses (markdown + terminal banner + JSON sidecar)? That worked. Or does Vibe Sec need something different (a severity-ordered table? An attack-tree visualization?)? Probably the three-render pattern again — consistency across the marketplace matters.

## Prior SDD Experience

**Deep.** Same as Vibe Test — Este built the Vibe Cartographer plugin that teaches structured development. `/reflect` quiz can stay at expert-practitioner level.

## Architecture Docs

**Two core documents already in the solo repo:**

1. **`packages/vibe-sec/framework.md`** — Vibe Sec thesis. Read this as the product argument, not the technical blueprint.
2. **`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`** — positioning + composition + handshake schemas. Read this as the architectural foundation for how Vibe Sec fits into the 626Labs marketplace.

**Shared scaffolding (reference — not yet copied into vibe-sec solo):**

- `docs/self-evolving-plugins-framework.md` from either `app-readinessplugin/docs/` or `vibe-test/docs/` — the Pattern #1–16 playbook. Applies identically to Vibe Sec. Worth pulling into this solo's docs/ during `/scope` or `/spec` so downstream commands have it locally-readable.

**Stack direction for `/spec`:** inherit Vibe Test's architectural decisions:
- TypeScript-first plugin
- Claude Code skill files + slash commands
- Local-first data storage under `~/.claude/plugins/data/vibe-sec/`
- Data-contract-first design
- Agent-heavy split (SKILL-primary logic, thin `src/` for deterministic primitives like secret-pattern regex, dependency-audit shell-outs, config-file parsers)
- Three-channel output (markdown + banner + JSON sidecar)
- L2 self-evolution from day one

Specific test-running infrastructure, which dependency-audit backend (npm audit? socket.dev? snyk?), which secret-scan baseline (gitleaks? trufflehog? own regex like the CLI has today?) — all `/spec` decisions.

---

## Notes for Downstream Commands

- **Compress everything aggressively.** Thesis and positioning are both pre-written. /scope's real job is to confirm the positioning holds, decide v0.2 scope (what ships in the plugin beyond the secret-scanner CLI), and capture principled cuts. /prd will then lock epics + stories. Don't repeat the full thesis in scope.md — reference it.
- **Architect persona committed.** Frame security decisions as tradeoffs with long-term consequences. Name load-bearing choices and surface their reversibility.
- **Composition is load-bearing.** Vibe Sec doesn't exist in isolation — the Vibe Test integration handshake (`covered-surfaces.json` ↔ `findings.jsonl`) is a named PRD-time open question that /spec will concretize. Pattern #13 ecosystem-composition is a first-class concern.
- **The CLI is already shipping.** `@esthernandez/vibe-sec-cli@0.1.1` has 404 lines of real secret-scanner code. /spec should treat that as the first capability, not reinvent it. The plugin's `/vibe-sec:scan` subcommand may wrap the CLI (or the CLI may be promoted into a full plugin-level skill).
- **Cowork visibility constraint.** The solo's current `packages/vibe-sec/` is a stub with no commands/skills, which is why Cowork filters it out of the marketplace picker. Fixing that is an incidental side-effect of any /scope → /build work that produces real commands.
