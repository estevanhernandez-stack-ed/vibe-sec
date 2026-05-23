# Threat Model Generation — Research Brief

> Domain research for Vibe Sec v0.2 — Concern #9 (Threat Model Generation)
> Agent: threat-modeling expert (STRIDE / DREAD / attack-tree methodologies)
> Authored: 2026-04-20
> Status: durable brief, living doc (re-run via `/vibe-sec:research --concern threat-model-generation`)

---

## Framing

Threat model generation is **not a detector** — it is Vibe Sec's flagship synthesis deliverable. Where the other nine concerns each ask *"is this one specific thing broken?"*, threat modeling asks *"given the whole picture assembled by the other nine, what does an adversary actually do with this app?"* The output is a durable, builder-readable document — attacker goals, trust boundaries, data flows, categorized threats, mitigations — not a finding list. It is the capstone that consumes the other nine agents' briefs as raw material, runs synthesis, and emits a narrative.

## Landscape

### Methodologies — the five that matter

**STRIDE** (Microsoft, 1999, still not deprecated as of late 2025) remains the dominant developer-facing methodology. Six categories — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — give non-security-specialist builders a tractable mental model. Its acknowledged weakness: it conflates *threats* (mechanisms) with *outcomes* (impacts), and proposals like TLCTC (Top Level Cyber Threat Clusters) argue for cleaner separation. For Vibe Sec v0.2 the call is clear: **STRIDE is the right choice for builder-facing output** because the vibe-coded-app audience has zero appetite for category-system arguments. STRIDE is what they recognize from any OWASP-adjacent blog post.

**DREAD** (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is a prioritization rubric, not a modeling methodology. It layers on top of STRIDE to score individual threats. Criticized for subjectivity, still useful as a rough-cut ordering heuristic — the right way to produce the "top 5 threats for this tier" view a tired builder actually reads.

**PASTA** (Process for Attack Simulation and Threat Analysis) is the enterprise seven-stage methodology. Correct, thorough, and wildly inappropriate for the vibe-coded audience. PASTA belongs in Regulated-tier deferrals — a Pattern #13 complement, not attempted directly.

**Attack Trees** (Schneier, 1999) are a complementary visual technique — root = attacker goal, branches = sub-goals, leaves = concrete exploits. Useful as a supplement to STRIDE for the top-3 threats, not as a primary methodology.

**LINDDUN** (Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance) is the privacy-specific analog to STRIDE. Developed at KU Leuven; NIST-recognized on the NIST Privacy Framework resource list. In 2025 the framework was restructured around a metamodel expressing threat knowledge as types/criteria/examples/metadata with model-driven tool enablers — signaling a clear push toward automation-friendliness. For Vibe Sec this matters at **Customer-facing SaaS** and **Regulated** tiers, where PII handling is first-class.

### Tools

**OWASP Threat Dragon** (open source, browser + Electron + GitHub-backed) is the reference OSS tool. Current version 2.5.0 (following 2.4, which shipped schema 1.0.2 and reusable templates). Supports STRIDE, LINDDUN, CIA, DIE, and PLOT4ai natively with a rule engine that auto-generates threats and mitigations. Its JSON schema is open — the natural Pattern #13 complement: Vibe Sec can emit Threat Dragon-compatible JSON and let builders who want a GUI continue from there.

**Microsoft Threat Modeling Tool** (Windows-only GUI) is still actively maintained — GA 7.3.51110.1 shipped November 2025. STRIDE-per-element. Platform-locked but with an exhaustive rule library. Cite as a Pattern #13 complement for Windows-native enterprise users; don't try to replace it.

**pytm** (OWASP, Python) is the "threat-model-as-code" offering — define your system as Python objects (Process, Dataflow, Boundary), get DFD + sequence diagram + threat report as outputs. Architecturally aligned with what Vibe Sec does internally, but the manual-Python-description UX is friction-maximizing for the target audience. pytm is a good mental model for Vibe Sec's internal representation ("the model is code, diagrams are derived outputs") without being the user-facing surface.

### AI-assisted threat modeling — the 2024-2026 surge

This is where Vibe Sec has actual competition and must position carefully.

- **STRIDE-GPT** (mrwadams) — reference OSS AI threat modeling tool. LLM-backed (OpenAI, Anthropic, Google, Mistral, Groq, local Ollama/LM Studio). Accepts a GitHub URL, auto-analyzes README + key files, generates a model plus attack trees. Added OWASP Top 10 for Agentic Apps (ASI) and OWASP LLM Top 10 integration in 2025. Direct functional overlap with `/vibe-sec:threat-model` — but standalone, with no classification/tier awareness.
- **ASTRIDE** (2025 arXiv 2512.04785) — academic platform extending STRIDE for agentic-AI systems with AI-Agent-Specific Attack category (prompt injection, unsafe tool invocation, reasoning subversion). Vision-language-model-driven diagram reading. Signals the research direction.
- **Threat Thinker** (dev.to, 2025) — LLM threat modeling that consumes Mermaid / draw.io / screenshots / Threat Dragon exports. `--infer-hints` lets the LLM fill auxiliary information not in the diagram.
- **Paranoid** (theAstiv) — deterministic rule engine with 362 curated patterns across STRIDE + MAESTRO + OWASP + MITRE ATT&CK + ATLAS + CAPEC + cloud misconfigurations, with vision-API diagram ingestion.
- **Commercial platforms** — IriusRisk, ThreatModeler, Security Compass. All added LLM features in 2024-2025. Enterprise price points, not Vibe Sec's audience.

Carleton NGN Lab's research (arXiv 2505.04101, May 2025) found LLM performance on STRIDE classification for 5G threats **comparable across OpenAI/Anthropic/Google/Mistral/Groq but consistently needing enhancement** via fine-tuning or RAG. Translation: off-the-shelf LLMs are okay-not-great at naïve STRIDE categorization, and the industry answer is retrieval-augmented synthesis over a curated threat knowledge base — not raw generation.

**Positioning implication:** Vibe Sec is not building a better standalone STRIDE-GPT. The distinctive move is *integration* — ours is the only threat model that ingests the other nine concerns' structured findings and produces a tier-calibrated model. STRIDE-GPT has no concept of tier or classification. Vibe Sec does.

## Generation mechanics

### Inventory inputs

Every other Vibe Sec concern is a tributary. The synthesis agent does not re-scan — it reads what the other agents already produced:

- **Classification** (`audit.json`) — app type, tier, context modifiers. Drives which boundaries are live and which threats are in-scope.
- **Route/endpoint inventory** (auth model, #8) — every HTTP/RPC surface with its access-control disposition.
- **Data model + PII boundaries** (crypto/PII, #4) — what data exists, which fields are sensitive, where they live at rest and in transit.
- **Integrations** (config #5, deps #1) — third-party APIs, payment processors, auth providers.
- **Auth system** (#8) — session model, role matrix, authorization boundaries.
- **Secrets disposition** (#2) — what credentials exist, where they live, what access they grant.
- **Known vulns** (#1) — dep-level vulnerabilities that shift specific threats from hypothetical to realized.
- **Vibe Test's `covered-surfaces.json`** when present — which endpoints have behavioral/edge-case coverage (affects realism of Repudiation and Information Disclosure threats).

### Data-flow diagram reconstruction

The internal model is a **lightweight DFD** — not a pytm-grade process-decomposition, but enough to drive STRIDE-per-element. Nodes: external entities (users, admins, third-party APIs), processes (frontend, backend services, workers), data stores (primary DB, cache, object storage, logs), and the flows between them. Reconstructed by: routes → processes; data model → stores + flow labels; integrations → external entities; auth system → which flows cross authenticated boundaries.

### Trust boundary identification

Three canonical boundaries Vibe Sec always attempts to place:

1. **External user boundary** — client to backend. Everything the user sends is attacker-controlled. Always present.
2. **Admin/elevated-role boundary** — regular-user context to privileged context. Present whenever the role matrix has >1 role. Frequently the richest source of high-severity Elevation threats.
3. **Service-to-service boundary** — backend to third-party APIs, backend to DB/cache/object storage, service A to service B. Source of most Repudiation and Tampering threats when service-to-service auth is weak.

Context modifiers surface additional boundaries: **tenant** (multi-tenant SaaS), **regulated-data** (HIPAA/PCI/GDPR regions vs non-regulated processing), **build/deploy** (source code to production artifact — cross-cuts with supply chain, mostly surfaces at Regulated).

### Per-boundary STRIDE enumeration

The synthesis agent walks each (element, boundary) pair through the six STRIDE categories. Mechanically this is constrained enumeration, not open-ended generation — exactly where LLMs shine given a good template. Example fragment for `POST /api/waitlist` at the external-user boundary:

| Category | Generated threat | Mitigation |
|---|---|---|
| Spoofing | Attacker replays valid signup to spam waitlist | Rate limit + email verification (→ #7) |
| Tampering | Crafted payload injects HTML into confirmation email | Input validation + output encoding (→ #3) |
| Repudiation | No audit log — user claims "I didn't sign up" | Add signup event log (advisory) |
| Info Disclosure | Error response reveals email-already-on-waitlist (account enumeration) | Uniform response (advisory, inline fix) |
| Denial of Service | Unauthenticated, no rate limit — attacker exhausts DB/email quota | Rate limit per IP + daily cap (→ #7) |
| Elevation | N/A — endpoint intentionally unauthenticated | — |

### LLM-assisted synthesis

The synthesis agent is a prompt template with four rigid sections:

1. **Context preamble** — classification + tier + deployment context, injected verbatim from `audit.json`.
2. **Inventory dump** — structured JSON of routes, stores, integrations, auth model, known vulns. Not prose.
3. **Methodology instruction** — STRIDE-per-element walk for a specific boundary, plus DREAD scoring. At Customer-facing SaaS+, add LINDDUN privacy walk. At Regulated, add attack trees for top-3.
4. **Output contract** — markdown with specified H2s (Attacker goals, Trust boundaries, Data flows, Threats by category, Prioritized top 10, Mitigations mapped to concerns).

Output validated against a schema for structural completeness, not style. Missing sections = re-prompt. Same pattern as Threat Thinker and STRIDE-GPT; Vibe Sec's differentiator is upstream inventory quality, not prompt engineering.

### Output format — markdown and JSON

Two channels, consistent with Vibe Sec's three-channel pattern:

- **Primary: `docs/vibe-sec/threat-model.md`** — builder-readable markdown with embedded Mermaid diagrams. Mermaid is the right call: native rendering on GitHub/GitLab/Obsidian/Dendron, diff-friendly in git, with active community work (Mermaid issues #1893 and #5895) toward first-class DFD support. Markdown-plus-Mermaid is a durable runbook-grade artifact.
- **Sidecar: `.vibe-sec/state/threat-model.json`** — machine-readable. Schema aligned with OWASP Threat Dragon's JSON where feasible, to enable one-click Threat Dragon import and avoid inventing a bespoke schema nothing else reads.

Mermaid DFD convention (until the ecosystem stabilizes): trust boundaries as `subgraph`, external entities as stadium shapes, processes as rectangles, data stores as cylinders, third parties as hexagons. Document in the `docs/SECURITY.md` template so successive runs produce diff-friendly diagrams.

## False-positive risks

The 12% FP target in `scope.md` has different meaning here than for the other concerns. It is **threat relevance**, not threat accuracy. Every threat enumerated is a real threat class in principle — the question is whether it applies to *this app at this tier*.

**Overgenerated threats** — the agent walks STRIDE for every element and enumerates speculative edge cases that are technically possible but not meaningfully exploitable. Examples that deserve suppression: "Spoofing: attacker brute-forces session token" for a Firebase Auth app with 128+ bit random JWTs; "Denial of service: attacker overwhelms frontend" for a static-site Vercel deployment where CDN DoS protection is out of app-level scope; Elevation entries at Prototype tier for internal-only apps where the adversary model doesn't include role separation.

Mitigation: **tier-appropriate filtering as a final pass**. At Prototype, drop threats with implausible attacker-capability premises. At Public-facing+, keep them but label "advisory — likely low-priority."

**Undergenerated threats** — inventory incomplete, model misses threats the app actually has. The harder failure mode: the threat model looks complete but isn't. Inventory-completeness checks before synthesis:

- Route inventory covers >90% of routes detected by framework-specific scanners (Express `app.use`/`app.METHOD`, Next.js `app/` and `pages/api/`, Firebase Functions callable+HTTPS triggers).
- Data model covers every entity with a Zod/Prisma/Mongoose/Firestore-schema declaration.
- Integrations list covers every package.json entry with a known third-party SDK fingerprint.

If completeness is below threshold, emit a banner: *"Inventory completeness: 73% — threat model may be missing surfaces from [list]."* Silent undergeneration is the failure mode to avoid at all costs.

**Net FP accounting:** 40 threats with 5 speculative-not-applicable is 12.5% — on target. The prioritization view (top-10 DREAD-scored) needs tighter tolerance: a fake threat in the top-10 is embarrassing. Target for top-10 specifically: **<5% FP**, tighter than the across-the-board 12%.

## Remediation patterns

Threat-model output is predominantly **advisory/inline**. Threat modeling is Layer 3; fixes require architectural judgment. A generated threat model does not auto-write code. Three remediation modes:

1. **Direct cross-concern mapping → auto-fix via that concern.** "Information Disclosure: PII leaked via `lodash@4.17.15` CVE-2019-10744" maps to concern #1's auto-bump. The threat model references the finding by ID; the fix happens in the dep concern's lane; the threat model documents *why* in adversary terms.

2. **Advisory remediation → inline in the threat model.** "Repudiation: no audit log on auth-state changes." Architectural fix — add audit log table, wire auth events, decide retention. No mechanical remediation, clear advisory in `docs/SECURITY.md`.

3. **Human judgment call → surface for builder review.** "Tampering: Stripe webhook signatures verified but replay not guarded — should replay guards be added?" Cost/complexity depends on idempotency guarantees. The model enumerates the decision; the builder owns it.

Category → concern owner mapping:

| STRIDE | Typical remediation owner |
|---|---|
| Spoofing | auth model (#8), CSRF config (#5) |
| Tampering | injection (#3 / A03), supply chain (#6) |
| Repudiation | advisory — audit logging rarely covered elsewhere |
| Info Disclosure | PII/crypto (#4), CVE (#1), secrets (#2) |
| Denial of Service | rate limiting (#7), CVE (#1) |
| Elevation | auth model (#8), config (#5) |

## Pattern #13 complements

- **OWASP Threat Dragon** — for builders who want an interactive GUI after initial generation. Emit Threat Dragon JSON as sidecar, one-click import. Good for Public-facing+ where builders want ongoing model maintenance.
- **pytm** — for Python-heavy teams wanting threat-model-as-code with git-tracked diffs. Optional pytm stub output at Customer-facing SaaS / Regulated.
- **Microsoft Threat Modeling Tool** — for Windows enterprise shops with existing MTMT workflows. Cite as complement; no integration work.
- **STRIDE-GPT** — adjacent standalone offering. Don't integrate; the value props are orthogonal (Vibe Sec is audit-integrated, STRIDE-GPT is repo-drop).
- **LINDDUN reference** (linddun.org + 2025 metamodel) — link to the official catalog rather than re-encoding.
- **Commercial (IriusRisk, ThreatModeler, Security Compass)** — surface in the "if you graduate" band of the four-band report.

**When to defer entirely to a complement: probably never in v0.2.** Threat model generation is one of Vibe Sec's distinctive synthesis moves. The integrated, classification-aware, cross-concern-feeding version is the feature — deferring entirely loses the thesis. The right posture: *"Vibe Sec generates the initial model from your audit inventory; continue maintaining it in Threat Dragon / pytm if you want."* Synthesis is Vibe Sec; maintenance is the complement's territory.

## Tier applicability

Each tier has a different answer to "what does threat modeling look like here?"

| Tier | Posture |
|---|---|
| **Prototype / hackathon** | **No threat model.** Not worth the tokens. `/vibe-sec:threat-model` emits a stub: *"Threat modeling is not recommended at Prototype tier. Re-run when graduating to Internal+."* |
| **Internal tool** | **Lightweight auto-generated.** Inventory-driven STRIDE walk for the external-user boundary plus admin boundary if present. No LINDDUN, no attack trees. ~1-2 pages. Goal: builder knows obvious threats before internal launch. |
| **Public-facing** | **Full STRIDE.** All three canonical boundaries. DREAD on all threats. Top-10 prioritized. Attack trees for top-3. 5-10 pages. Goal: builder can defend the app's security model to a security-aware stakeholder. |
| **Customer-facing SaaS** | **Full STRIDE + LINDDUN privacy overlay + tenant boundary.** LINDDUN walk alongside STRIDE for every store with user-attributable data. 10-15 pages including privacy threat matrix. Goal: pass a privacy-focused review, answer GDPR/CCPA-adjacent questions. |
| **Regulated / enterprise** | **Full STRIDE + DREAD + LINDDUN + attack trees for top-5 + formal-review-friendly exports.** Threat Dragon JSON sidecar + pytm Python stub for git-tracked maintenance. 15-25+ pages. Goal: handed to an external auditor as the starting point for formal review. Explicitly *starting point* — Vibe Sec is not a certifier. |

The tier matrix is itself a deliverable of this brief — `/spec` should lock it into the per-concern applicability matrix referenced in `scope.md`'s open questions.

## Cross-concern dependencies

Threat model generation is **meta over all other Vibe Sec concerns** — the only concern with this property. Every other concern detects or classifies; threat modeling *synthesizes*. Concrete dependencies:

- **#1 CVE** → Information Disclosure + Tampering threats (realized, not hypothetical).
- **#2 Secrets** → Information Disclosure (worst kind — already-realized).
- **#3 Injection/OWASP Top 10** → Tampering and Information Disclosure; A01 access control → Elevation.
- **#4 Crypto/PII** → Information Disclosure + the entire LINDDUN overlay at Customer-facing SaaS+.
- **#5 Config** → Spoofing (missing CSRF), Info Disclosure (missing headers), DoS (no rate limit).
- **#6 Supply chain** → Tampering at the build/deploy boundary.
- **#7 Rate limiting** → DoS directly.
- **#8 Auth model** → Spoofing, Repudiation, Elevation. *Deepest dependency* — auth model output is the single largest input.
- **#10 Tier/gating** → sets the tier that determines methodology overlays.

**External dependencies (Pattern #13 composition):**
- **Vibe Test's `covered-surfaces.json`** — informs Repudiation and Info Disclosure assessments (untested endpoints more likely to harbor unenumerated threats).
- **Vibe Doc's threat-model template** — if present, hosts the rendered document. Vibe Sec owns *analysis*, Vibe Doc owns *document hosting*.
- **Cart's `/spec` architecture decisions** — informs trust-boundary identification.

**Execution-order implication:** threat modeling must run **last** in `/vibe-sec:audit` — after all other research/detection is complete. It cannot be parallelized with the other concerns; it is the sink node. This is the opposite of the research-swarm pattern at `/spec` time (parallel domain research). At audit run time, concerns execute in dependency order; threat modeling is the terminus.

## Open questions for synthesis

Questions the research-swarm synthesis agent should surface to Este at `/spec` time:

1. **DREAD scoring formula.** Three options: numeric 1-10 per dimension (subjective), ordinal High/Med/Low with lookup table (less precise, more consistent), or **hybrid — CVSS passthrough where CVE reference exists, ordinal DREAD otherwise**. Recommend the hybrid — consistent with Vibe Sec's existing CVE-passthrough severity model.
2. **Mermaid DFD conventions — lock them now.** Ecosystem hasn't converged. Lock stadium/rectangle/cylinder/hexagon mapping at `/spec` time; document in `docs/SECURITY.md` template as a contract. Otherwise successive runs drift and diffs churn.
3. **Threat Dragon JSON schema compatibility target.** Schema at 1.0.2 (v2.4), live development. Lock a version for v0.2; re-run this research quarterly for schema drift.
4. **LLM choice for synthesis.** Carleton study: all major LLMs perform comparably on STRIDE; RAG/fine-tuning needed for production-grade. Recommend: **default to host Claude Code model, allow profile override, document that Opus-class models produce noticeably better threat narratives.**
5. **Attack-tree rendering.** Options: Mermaid `graph TD` with manual root-goal labeling (works at Public-facing), ASCII tree in code block, or separate Graphviz `.dot` file (Regulated). Recommend Mermaid at Public-facing, Graphviz at Regulated.
6. **Incremental vs. full regeneration.** Re-run produces differential ("resolved: 3; new: 0") or always full? Recommend: **full document by default, with a "changed since last run" summary at the top when a prior run exists.**
7. **Vibe Doc handoff seam.** When Vibe Doc is installed: emit as markdown for Vibe Doc to re-render, or co-author? Recommend **emit as complete markdown**; Vibe Doc reads it as existing doc. Cleaner contract.
8. **Tier-graduation prompting.** Does the primary document include a graduation preview ("what this would look like at the next tier")? Recommend **current-tier only in the primary doc; graduation preview is a separate `--preview-tier` flag**.
9. **Adversary persona granularity.** Pure STRIDE walks categories; it doesn't name adversaries. Recommend adding **adversary personas at Public-facing+, tier-scoped**: script-kiddie always, motivated external at Public-facing+, insider at Customer-facing SaaS+, nation-state only when explicitly requested at Regulated. Named adversaries make the model more actionable.
10. **Re-run cadence for this brief.** Landscape moves fast: STRIDE-GPT added ASI/LLM Top 10 in 2025, LINDDUN restructured its metamodel in 2025, Threat Dragon shipped 2.4→2.5. Re-run at least quarterly. Re-runs should specifically check (a) new AI-assisted threat modeling tools that change the Pattern #13 landscape, (b) methodology changes in STRIDE/LINDDUN/PASTA, (c) schema updates in Threat Dragon / pytm.

---

## Sources

- [STRIDE-GPT — AI-powered threat modeling tool](https://github.com/mrwadams/stride-gpt)
- [LLMs' Suitability for Network Security: A Case Study of STRIDE (arXiv 2505.04101)](https://arxiv.org/html/2505.04101v1)
- [From Whiteboards to LLMs: Automating STRIDE Threat Models with GenAI](https://www.aicodeshield.com/blog/from-whiteboards-to-llms-automating-stride-threat-models-with-genai)
- [ASTRIDE: Security Threat Modeling for Agentic-AI (arXiv 2512.04785)](https://arxiv.org/html/2512.04785)
- [AI Threat Modeling — Security Compass](https://www.securitycompass.com/blog/ai-threat-modeling/)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [OWASP Threat Dragon v2.5.0 Release](https://github.com/OWASP/threat-dragon/releases/tag/v2.5.0)
- [OWASP Threat Dragon v2.4 docs](https://owasp.org/www-project-threat-dragon/docs-2/about/)
- [linddun.org — Privacy Engineering](https://linddun.org/)
- [LINDDUN — NIST Privacy Framework](https://www.nist.gov/privacy-framework/linddun-privacy-threat-modeling-framework)
- [Robust and reusable LINDDUN privacy threat knowledge — ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0167404825001087)
- [Comparing STRIDE vs LINDDUN vs PASTA — Security Compass](https://www.securitycompass.com/blog/comparing-stride-linddun-pasta-threat-modeling/)
- [OWASP pytm](https://github.com/OWASP/pytm)
- [pytm — OWASP Developer Guide](https://devguide.owasp.org/en/04-design/01-threat-modeling/02-pytm/)
- [Microsoft Threat Modeling Tool — Microsoft Learn](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Microsoft Threat Modeling Tool release notes](https://learn.microsoft.com/en-ca/azure/security/develop/threat-modeling-tool-releases)
- [Beyond STRIDE: Upgrading Microsoft Threat Modeling to TLCTC](https://tlctc.net/tlctc-microsoft-threat-modeling-stride.html)
- [Threat Thinker — LLM-Based Threat Modeling (dev.to)](https://dev.to/melonattacker/threat-thinker-trying-llm-based-threat-modeling-17o3)
- [Paranoid threat modeling tool](https://github.com/theAstiv/paranoid)
- [Mermaid issue #1893 — DFD for STRIDE](https://github.com/mermaid-js/mermaid/issues/1893)
- [Mermaid issue #5895 — Threat modelling](https://github.com/mermaid-js/mermaid/issues/5895)
- [PROTECT: Integrating STRIDE, DREAD, LINDDUN, PASTA](https://www.cloudauditcontrols.com/2025/12/protect-integrating-stride-dread.html)

---

*End of brief. Living doc — re-run via `/vibe-sec:research --concern threat-model-generation`.*
