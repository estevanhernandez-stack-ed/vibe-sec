# Supply Chain Hardening — Research Brief

> *Concern #6 — Supply chain hardening. Maps to OWASP A08 (Software and Data Integrity Failures). Written for Vibe Sec v0.2's `/spec`-time research swarm. Durable reference; re-runnable via `/vibe-sec:research --concern supply-chain-hardening`.*

**Persona:** Architect. **Tier focus:** Public-facing → Regulated. **Dogfood subject:** WeSeeYouAtTheMovies at the internal → public-facing tier transition.

---

## Landscape

The supply chain is now where attackers aim first. The code the builder writes is often not the soft spot — the 1,400 transitive dependencies they never looked at are. Between late 2023 and Q1 2026, the industry lived through a sequence of incidents that reframed the category:

**XZ Utils backdoor (CVE-2024-3094, CVSS 10.0).** A two-and-a-half-year social-engineering campaign by "Jia Tan" (JiaT75) to gain maintainer trust in the xz-utils project, culminating in malicious code inserted into upstream release artifacts for versions 5.6.0 and 5.6.1. The backdoor lived in the release tarballs — not the git tree — and was engineered to survive casual code review and activate through a build-time injection path into `liblzma`, then into `sshd` via systemd notification. It was caught by a single Postgres maintainer noticing SSH was 500ms slower. The lessons that calcified:

1. **Artifact-vs-repository discrepancy is a primary detection signal.** Release tarballs that don't match the git tree are the new canary.
2. **Maintainer trust is a multi-year attack surface.** Repos with a single maintainer who recently ceded control to a new contributor are a red flag that most tools still don't surface.
3. **"Only two versions affected" is not reassurance** when those two versions can enter the build graph through mirrors, distro packages, and CI defaults.
4. **Build-time threats are distinct from install-time threats** and need different detection — a clean `package-lock.json` proves nothing about what the upstream build did.

**The 2025 npm meltdown.** September 2025 saw the `chalk`/`debug`/~18-package compromise (2.6B weekly downloads across the blast radius) via maintainer phishing, followed by the **Shai-Hulud worm** on November 24, 2025 — a self-propagating payload riding postinstall scripts that compromised 500+ packages, exfiltrated GitHub tokens, CI/CD credentials, and cloud credentials, and used stolen tokens to compromise additional maintainer accounts in a worm loop. Shai-Hulud 3.0 landed December 29, 2025, and **SHA1-Hulud** (same family, preinstall-script variant) followed shortly after. The **GhostAction attack** on September 5, 2025, hit 327 GitHub users across 817 repositories via malicious workflow injection, exfiltrating 3,325 secrets (PyPI, npm, DockerHub tokens). **March 2026 Axios** was compromised via stolen npm maintainer credentials. In calendar year 2025, attackers published **454,648 malicious npm packages** — roughly half a million in one ecosystem in twelve months. Over 99% of net-new open-source malware now targets npm. This is the threat model.

**tj-actions/changed-files (CVE-2025-30066, March 14, 2025).** A single compromised GitHub Action — used by 23,000+ repositories — was modified to dump secrets from the Runner Worker memory into workflow logs. Because most users referenced the action by floating tag (`@v45`, `@main`), the compromise instantly propagated to every downstream repo. CISA issued an emergency advisory. The mitigation that worked: pinning third-party actions to a commit SHA rather than a tag. This single incident established **SHA-pinning of GitHub Actions** as the new minimum-bar best practice, the same way `package-lock.json` became minimum-bar after left-pad.

**npm provenance / Trusted Publishing.** npm's provenance feature reached GA in September 2023 and got a second GA moment when **Trusted Publishing** graduated in July 2025 — which made provenance the default (no more `--provenance` flag needed, npm CLI v11.5.1+). Adoption, however, is the punchline: **7.2% of npm dependencies** have provenance as of early 2026. Even the Sigstore project's own dependency tree is below 8% provenance. The top 50 most-downloaded packages sit at ~12% provenance. ~16,000 unique packages total. Provenance is technically solved. Provenance-verification-as-gating-policy is not yet an industry reflex.

**SLSA v1.x, Sigstore, CycloneDX.** SLSA split into tracks at v1.0 (build / source / dependencies) and stabilized at v1.1 through 2024–2025; v1.2 is in active development. Sigstore is now the signing substrate for npm, PyPI, Maven Central, Kubernetes, and Homebrew. `cosign verify-bundle` (cosign v2.4.0+) can verify npm provenance directly. CycloneDX and SPDX have both converged as acceptable SBOM formats; `syft` and similar tools produce signed SBOM attestations. The plumbing is mature. The builder using it is rare.

**The gap Vibe Sec fills at this concern:** the tooling landscape assumes an engineering org that already cares about supply chain. Vibe-coded builders don't — they `npm install` whatever the LLM suggested, ship, and move on. Vibe Sec's job is to make the **minimum viable hardening** legible and tier-appropriate.

---

## Detection mechanics

Seven detection families, each with a concrete parser and a clear false-positive profile.

### 1. Lockfile presence + format

The first question: is there a lockfile at all? No lockfile = no reproducibility = every `npm install` rolls a different dependency tree.

| Package manager | Lockfile | Parse target |
|---|---|---|
| npm | `package-lock.json` | JSON, top-level `lockfileVersion` (3 = npm 7+), `packages[]` with `resolved` + `integrity` |
| yarn classic | `yarn.lock` | Custom YAML-ish; parse with `@yarnpkg/lockfile` or regex |
| yarn berry | `yarn.lock` (different format) | YAML; `__metadata.version` header |
| pnpm | `pnpm-lock.yaml` | YAML, `lockfileVersion: 9.0` (pnpm 9+), `packages:` map |
| bun | `bun.lockb` (binary) + `bun.lock` (text, bun 1.2+) | Binary — shell out to `bun pm ls --json`; text is YAML-ish |

**Detection logic:**

- **No lockfile, `dependencies` in package.json non-empty** → `A08-no-lockfile` finding, high severity at Public-facing+.
- **Both `package-lock.json` and `yarn.lock` present** → `A08-lockfile-conflict` finding (two package managers disagreeing silently — common with vibe-coded apps where the LLM generated both).
- **Lockfile older than `package.json`** (mtime comparison with jitter tolerance) → `A08-stale-lockfile` warning.

### 2. Integrity hashes in lockfiles

In npm lockfile v2/v3, every resolved package has an `integrity:` field — a subresource-integrity hash (`sha512-...`). Its purpose: the `npm ci` reinstall path validates the downloaded tarball matches the hash. Missing integrity fields mean the lockfile can still be tampered with silently.

**Detection logic:**

- Walk every entry in `packages` (v3) or `dependencies` (v1). Count entries missing `integrity`. Report as percentage.
- **< 95% coverage** → finding.
- **0% coverage** → lockfileVersion 1 artifact; recommend `npm install` regenerate (which auto-upgrades to v3).

Yarn and pnpm both carry their own integrity equivalents — `yarn.lock` has `integrity:` lines, `pnpm-lock.yaml` has `integrity:` under each entry. Same check, different parser.

### 3. Pinning-strategy assessment

Parse `package.json` `dependencies` and `devDependencies`. Classify each version spec:

| Pattern | Classification |
|---|---|
| `"1.2.3"` | Exact pin |
| `"=1.2.3"` | Exact pin |
| `"~1.2.3"` | Tilde (patch-level floating) |
| `"^1.2.3"` | Caret (minor-level floating) |
| `">=1.2.3"`, `"*"`, `"x"`, `"latest"` | Unconstrained |
| `"git+..."`, `"file:..."`, `"http://..."` | Non-registry (requires deeper inspection) |

**Scoring:**

- Ratio of exact-pinned to total direct deps.
- **Caret is not automatically a finding** — the lockfile pins the actual version; caret lets `npm update` move forward. Only report as finding when **lockfile is missing AND caret is present** (then the caret actually floats in production).
- **Unconstrained or `latest` anywhere** → finding regardless.
- **Git/file/URL deps** → flag for inspection (often legit for internal packages; always legit to report the surface).

### 4. GitHub Actions workflow parsing

Walk `.github/workflows/*.{yml,yaml}`. Parse each `uses:` line.

**Classification:**

| Ref style | Example | Risk |
|---|---|---|
| SHA-pinned | `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` | Safe |
| Tag-pinned | `uses: actions/checkout@v4.1.7` | Medium — tags are mutable |
| Major-tag-pinned | `uses: actions/checkout@v4` | High — moves silently |
| Branch-pinned | `uses: some-action@main` | Critical — moves on every push |

**First-party vs third-party:**

- First-party = `actions/*`, `github/*`, `docker/*` (GitHub-verified-creator namespace). Tag-pinning acceptable at internal tier, SHA-pin required at Regulated.
- Third-party = everyone else. **SHA-pin required** at Public-facing+ (post-tj-actions, this is the new bar).

**Permissions check:**

- Workflow-level `permissions:` block present? Using least-privilege (`contents: read`) or the `write-all` default?
- `pull_request_target` event with unpinned third-party action → **critical** (classic escalation path).

### 5. npm provenance / attestation checking

For each direct dependency in `package-lock.json`:

```bash
npm view <pkg>@<version> --json | jq '.dist'
```

Check for `.dist.attestations`:

```json
"attestations": {
  "url": "https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>",
  "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
}
```

**Scoring:**

- Percentage of direct deps with provenance attestations.
- Not a blocker at lower tiers — current ecosystem baseline is 7–12%. Below Public-facing, surface as informational ("N of your deps publish with provenance — here's what that means").
- **Regulated tier:** provenance required for all direct deps that offer it (i.e., don't block on the 88% that don't publish it, but verify when it's offered).

Full cryptographic verification (via `cosign verify-bundle`) is a post-v0.2 Pattern #13 complement — mentioning the plumbing exists and pointing at Sigstore is enough for v0.2.

### 6. Typosquat / dependency-confusion similarity scoring

Two sub-checks.

**Typosquat detection:**

Maintain an embedded list of the top ~500 most-downloaded npm packages (static, refreshed per release). For each direct dep in `package.json`:

1. Compute Levenshtein distance against every entry in the top-500 list.
2. If distance ≤ 2 and the dep is **not** in the top-500 itself → finding.
3. Bonus signal: compare download counts. `react-dom-` (hypothetical squat) vs `react-dom` — if the suspect has <1% of the legit version's weekly downloads → elevate severity.

Examples that should trip the check: `typescriptjs`, `react-router-dom.js`, `zustand.js`, `node-ipc-` (vs legit `node-ipc`), packages with trailing hyphens or swapped letters.

**Dependency-confusion detection:**

Parse `package.json` for scoped packages (`@mycompany/foo`). Check the npm public registry for the unscoped name (`mycompany-foo` or `@mycompany/foo` published publicly). If a public package matches the internal scope → finding (attacker may have registered your internal name publicly to force confusion). This requires a registry HEAD request per scoped dep; cheap, parallelizable.

**Slopsquatting variant:** If the LLM hallucinated a package name (common in vibe-coded apps), that name may have been squatted by an attacker who watches AI-assistant output. Detection: direct deps with <10 weekly downloads AND published in the last 90 days AND name is syntactically close to a popular package → critical finding.

### 7. Postinstall hook inspection

Walk the dependency tree (direct + transitive up to depth 2 for cost). For each `package.json`:

- `scripts.preinstall` / `scripts.install` / `scripts.postinstall` present?
- If yes: classify.

| Pattern | Severity |
|---|---|
| `node-gyp rebuild` | Benign (native module) |
| `node <local-script>.js` | Medium — inspect script |
| `curl ... | sh`, `wget ... | bash` | Critical |
| Obfuscated (base64, hex, eval) | Critical |
| Network call of any kind | High |

Recommend `.npmrc` with `ignore-scripts=true` at Public-facing+ tier as the general-purpose countermeasure, with a whitelist approach for genuinely-needed build scripts. pnpm v10+ disables postinstall by default; bun has the same posture. Flag npm-with-postinstall-enabled as a tier-dependent finding.

---

## False-positive risks

Supply chain detection runs hot on false positives if not calibrated. The 12% FP commitment for Vibe Sec v0.2 is achievable but tight. Known legit patterns that look like findings:

**Caret ranges for devDependencies in internal-only projects.** A prototype or internal tool using `^` on dev tools (eslint, prettier, vitest) is fine — the lockfile pins the actual version, and the "risk" of a minor update is near-zero for tools that never run in production. Suppress caret-only findings when (tier ≤ Internal) AND (finding is exclusively in devDependencies).

**Unpinned actions in internal-only workflows.** A workflow file that only runs on `push` to a personal repo with no secrets isn't the same risk as a production release workflow. Vibe Sec can't know for certain whether a workflow is internal-only, but signals help: repo visibility (private), `permissions: { contents: read }`, no `secrets.` references in the workflow → lower severity. Flag but don't block.

**Legitimate popular-package variants.** `@types/react` is not a typosquat of `react`. `react-dom` is not a typosquat of `react`. `babel-plugin-` prefix packages are a known-good ecosystem. The typosquat detector needs a known-good allowlist (scoped packages, `@types/*`, well-known prefix ecosystems like `babel-plugin-*`, `eslint-plugin-*`, `vite-plugin-*`) to avoid spam.

**Missing provenance on pre-provenance-era popular packages.** `lodash`, `express`, `react` — many of the absolute-top packages predate provenance and haven't retrofitted it. Reporting every top-50 package without provenance as a finding would generate dozens of noise findings. Surface as ecosystem-level informational ("78% of your dependency tree lacks provenance, which is normal for the 2026 npm baseline") rather than per-package findings.

**Native-module postinstall hooks.** `node-gyp`, `prebuild-install`, `node-pre-gyp` — these are legitimate postinstall patterns for packages with C/C++ bindings (bcrypt, sharp, sqlite3). Allowlist these specific invocations. Only flag postinstall when the command doesn't match the known-native-module pattern.

**Git/file/URL dependencies inside monorepos.** `workspace:*`, `file:../packages/shared`, `git+ssh://...` for internal packages are normal. Detect monorepo context (`workspaces` field in package.json, `pnpm-workspace.yaml`, lerna config) and suppress the "non-registry dep" finding inside workspace-ref cases.

---

## Remediation patterns

This concern has **three fix-confidence tiers** mapping directly to Vibe Sec's confidence-tier routing.

### AUTO-APPLY (≥ 0.90)

- **Pin a GitHub Action to a SHA.** Given `uses: some/action@v4`, resolve `v4` to its current commit SHA via `gh api`, rewrite to `uses: some/action@<sha> # v4` (with comment preserving the human-readable tag for upgrade UX). Deterministic, reversible, no runtime effect until the next workflow run. Safe.
- **Add `ignore-scripts=true` to `.npmrc`.** Additive config change. Reversible. Caveat: builder must re-enable on trusted packages with genuine postinstall needs; surface that in the PR description.
- **Add `permissions: contents: read` to workflows missing a permissions block.** GitHub Actions defaults to write-all; tightening to read is safe unless the workflow writes, in which case the workflow already fails loudly (not a silent break).

### STAGE (0.70 – 0.89)

- **Lockfile regeneration.** `rm package-lock.json && npm install` — this is semver-sensitive. It can surface new transitive versions that break the build or introduce new CVEs. Always stage the diff, run tests (`vibe-test` composition hook) before accept, and surface the delta: "this regeneration moved lodash from 4.17.20 → 4.17.21, which fixes CVE-X." Never auto-apply.
- **Pinning a floating direct dep to the currently-resolved version.** `"^1.2.3"` → `"1.2.3"`. Low-risk mechanically but philosophically opinionated — some projects deliberately use caret for dev-deps to auto-patch. Stage, explain, let the builder decide. Bulk-pinning is a design choice, not a fix.
- **Dependency-confusion fix — publish internal package publicly.** If `@mycompany/foo` is internal-only but no public squat exists yet, recommend claiming the public name with a stub package (prevents future confusion). Researcher-grade judgment; stage as advisory.

### INLINE / ADVISORY (< 0.70)

- **Switching a deprecated or compromised dep to an alternative.** `moment` → `date-fns` or `dayjs`. This is a semantic replacement requiring code changes at every call site. Never automatic. Vibe Sec provides the analysis (which dep, why flagged, recommended replacement with trade-off notes) and defers the implementation to the builder, ideally paired with Vibe Test running the affected surfaces afterward.
- **Removing a typosquat.** Requires understanding whether the squatted package was actually used or just a typo that somehow installed. Always inline — builder confirms intent.
- **Responding to an in-the-wild maintainer compromise.** When a live incident is happening (Shai-Hulud-class event), Vibe Sec surfaces the affected versions, recommends pinning below the compromise window, points to the incident advisory, and stops there. Rotation of any leaked secrets is the builder's ops job.

---

## Pattern #13 complements

Deferred tools that belong in the builder's toolbelt for this concern. Surfaced in the "Pattern #13 complements" report band — not required for v0.2 but recommended for future runs.

**Strongly recommended:**

- **Socket.dev** — the strongest single complement. Socket scores individual packages on a multi-dimensional risk axis (install scripts, network access, known maintainer events, usage of eval/dynamic imports, recent ownership transfers). Paid for commercial use, free for open source. If the builder is at Public-facing+ and willing to sign up for one external tool, this is the one. Vibe Sec should surface this prominently when deps count > 50.
- **OpenSSF Scorecard** — free, automated. Runs weekly against the top 1M open-source projects; results in a public BigQuery dataset. Vibe Sec can optionally query Scorecard data for direct deps and surface the aggregate score, with a link to the full check breakdown. Lower-friction than Socket for the "show me a score" use case.
- **npm audit** — already in scope for Vibe Sec's `:deps` command; relevant here because CVE audit and supply-chain hardening overlap at the integrity-check layer.

**Useful at higher tiers:**

- **Snyk** — deeper SCA, faster CVE feed, supply-chain-specific scanners. Paid. Best for Customer-facing SaaS+ that already has a security budget.
- **Dependabot / Renovate** — automated dependency update PRs. Renovate is more configurable; Dependabot is more automatic. Neither catches supply chain compromise directly, but both reduce the window between a fix landing upstream and a dep being behind the update.
- **Sigstore / cosign (verify-bundle)** — for the builder who wants to actually verify provenance attestations cryptographically, not just check their presence. Regulated tier and up.
- **Syft / Grype (Anchore)** — SBOM generation in CycloneDX or SPDX formats, signable via Sigstore. Regulated tier.

**Defer categorically:**

- **Binary-authorization gating in CI** — this is an infrastructure-security concern, not an app-security concern. Out of Vibe Sec's positioning.
- **Runtime package-behavior monitoring** (Falco, Tetragon) — runtime security; categorically deferred.

---

## Tier applicability

Tier-gated per-concern matrix. Each tier is cumulative — higher tiers inherit all checks from lower tiers.

| Tier | Supply chain checks |
|---|---|
| **Prototype** | Informational only — "you have no lockfile, here's why that matters later." No findings. |
| **Internal** | Lockfile presence. Basic pinning sanity (no `"latest"`, no `"*"`). Postinstall hook scan surfaces findings but none elevated to critical. |
| **Public-facing** | + Integrity-hash coverage check. + GitHub Actions SHA-pin enforcement on third-party actions. + Permissions-block enforcement on workflows. + `ignore-scripts` recommendation if npm. |
| **Customer-facing SaaS** | + Typosquat scan. + Dependency-confusion check on all scoped deps. + Postinstall-hook whitelist enforcement (not just surfacing). + Provenance-presence reporting as informational. |
| **Regulated** | + Full SBOM generation (CycloneDX). + Provenance attestation required on direct deps that offer it. + Sigstore verification recommended. + All third-party actions SHA-pinned, no exceptions. + Maintainer-compromise watchlist check against current incident feeds. |

**Severity mapping at Public-facing tier (the dogfood tier for WSYATM):**

| Finding | Severity |
|---|---|
| No lockfile | Critical |
| Lockfile present, 0 integrity coverage | High |
| Lockfile present, <95% integrity coverage | Medium |
| `"latest"` or `"*"` in dependencies | High |
| Third-party GitHub Action tag-pinned (not SHA) | High |
| Third-party GitHub Action branch-pinned | Critical |
| `permissions:` block missing on workflow | Medium |
| `permissions: write-all` explicitly | High |
| Postinstall hook with network call | High |
| Typosquat suspicion (distance ≤ 2 to top-500, low downloads) | Critical |
| Dependency confusion (internal scope matched publicly) | Critical |

---

## Cross-concern dependencies

Supply chain hardening is not an island. Explicit overlaps with other Vibe Sec concerns:

**With Dependency CVE audit (concern #1).** Both audit the same `package.json` / `package-lock.json`. Different questions — CVE audit asks "does this version have known vulnerabilities?", supply chain asks "is this version's integrity verifiable and is the source trustworthy?". A package can pass CVE audit (no known CVEs) and fail supply chain hardening (maintainer compromise not yet discovered) — and vice versa. **Coordination rule:** both concerns walk the same parsed lockfile; share parsing output via `.vibe-sec/state/parsed-lockfile.json` to avoid double-parse cost. Findings emit separately; the report layer groups them under "Dependencies" when both fire on the same package.

**With OWASP A06 (Vulnerable and Outdated Components).** A06 and A08 overlap conceptually. A06 is CVE-focused, A08 is integrity-focused. Vibe Sec's OWASP categorical output lists the same findings under both categories when appropriate, with different framings. Don't double-count in the weighted score.

**With Secret detection (concern #2).** Compromised packages frequently exfiltrate secrets via postinstall hooks (Shai-Hulud's entire MO). If Vibe Sec's secret scan finds tokens in the working tree **and** the supply chain scan finds a suspicious postinstall hook, the two findings should be cross-referenced in the report narrative: "your repo has a GitHub token in `.env`, and dep X has a suspicious postinstall — if that dep ever ran, assume the token is compromised and rotate." This cross-concern narrative is a Vibe Sec distinctive — individual scanners don't do this.

**With Auth model (concern #8).** Supply chain compromise that exfiltrates JWT signing keys or session secrets invalidates every active session. The fix is ops, not code. Supply chain surfaces the incident; auth model surfaces the blast radius.

---

## Open questions for synthesis

Questions for the synthesis agent (and, where synthesis can't resolve, for Este at `/spec` time):

1. **How far down the transitive tree do we walk for postinstall hook inspection?** Direct only is too shallow (Shai-Hulud propagated through transitives). Full tree is expensive on large deps graphs. Proposal: depth 2 default, depth-full at Regulated tier. Confirm with synthesis.

2. **Do we maintain an embedded top-500 popular-packages list, or query live?** Embedded = fast, offline, stale. Live = accurate, adds latency + network dependency. Proposal: embedded list refreshed per Vibe Sec release; live query as opt-in for Regulated tier. Confirm.

3. **Does the typosquat check fire on devDependencies?** A typosquatted dev tool is still attacker-controlled code on the developer's machine, but the blast radius is narrower than production. Proposal: fire at same severity (a compromised eslint plugin owns the dev machine, which owns production credentials). Confirm.

4. **How aggressively do we enforce SHA-pinning of first-party actions (`actions/checkout`, etc.)?** Post-tj-actions, even first-party is a nonzero risk. But pinning first-party SHAs generates upgrade friction (SHAs are opaque). Proposal: tag-pin acceptable for `actions/*` and `github/*` namespaces through Customer-facing; SHA-pin required only at Regulated. This is a trade-off decision needing Este's sign-off.

5. **Do we expose a `vibe-sec supply-chain --generate-sbom` subcommand in v0.2, or defer?** SBOM generation is valuable at Regulated but requires a CycloneDX/SPDX emitter. Proposal: defer SBOM generation to v0.3; v0.2 ships with SBOM detection (does the project have one?) and recommendation, not generation.

6. **How do we surface live-incident awareness?** When a Shai-Hulud-class event is active, Vibe Sec should ideally know. Options: (a) embed a static incident list per release — stale fast, (b) query an incident feed at scan time — adds dependency, (c) punt to Pattern #13 (Socket.dev does this natively). Proposal: (c) for v0.2, with a static "known recent incidents to spot-check" list as a safety net.

7. **Does `/vibe-sec:fix --auto` auto-SHA-pin GitHub Actions, or always stage?** The fix is mechanically safe (deterministic rewrite), but it touches CI config, which is high-blast-radius if wrong. Proposal: auto-apply only when the repo has a passing CI run within the last 7 days (signal that the current action versions work); stage otherwise. Confirm.

8. **Is dependency confusion detection worth the registry round-trip cost at Public-facing?** The scoped-deps registry check is cheap per-dep but can add up on large monorepos. Proposal: run at Customer-facing+ only; show as informational-upsell at Public-facing. Confirm.

---

*End of brief. Durable. Re-run via `/vibe-sec:research --concern supply-chain-hardening`.*

## Sources

- [CVE-2024-3094 XZ Upstream Supply Chain Attack — CrowdStrike](https://www.crowdstrike.com/en-us/blog/cve-2024-3094-xz-upstream-supply-chain-attack/)
- [The XZ Utils backdoor: Everything you need to know — Datadog Security Labs](https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094/)
- [XZ Utils backdoor — Wikipedia](https://en.wikipedia.org/wiki/XZ_Utils_backdoor)
- [Generating provenance statements — npm Docs](https://docs.npmjs.com/generating-provenance-statements/)
- [Trusted publishing for npm packages — npm Docs](https://docs.npmjs.com/trusted-publishers/)
- [The 2026 State of Package Registry Provenance](https://zenn.dev/sqer/articles/e4df3d397f5651?locale=en)
- [Introducing npm package provenance — GitHub Blog](https://github.blog/security/supply-chain-security/introducing-npm-package-provenance/)
- [I audited the top 50 npm packages — DEV Community](https://dev.to/thecryptodonkey/i-audited-the-top-50-npm-packages-almost-none-ship-with-supply-chain-attestations-3ki8)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
- [SLSA Security levels](https://slsa.dev/spec/v1.0/levels)
- [OpenSSF Announces SLSA v1.0 Release](https://openssf.org/press-release/2023/04/19/openssf-announces-slsa-version-1-0-release/)
- [Typosquatting in Package Managers — Andrew Nesbitt](https://nesbitt.io/2025/12/17/typosquatting-in-package-managers.html)
- [The Night npm Caught Fire: 2025 JavaScript Supply-Chain Meltdown](https://dev.to/usman_awan/the-night-npm-caught-fire-inside-the-2025-javascript-supply-chain-meltdown-52o3)
- [Malicious Packages 2025 Recap — Xygeni](https://xygeni.io/blog/malicious-packages-2025-recap-malicious-code-and-npm-malware-trends/)
- [npm Supply Chain News: Lessons from 2026 — Safeheron](https://safeheron.com/blog/npm-supply-chain-news-lessons-from-attacks-2026/)
- [CISA Alert: tj-actions/changed-files compromise (CVE-2025-30066)](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)
- [GitHub Actions Supply Chain Attack — Wiz Blog](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [GitHub Actions Supply Chain Attack — Palo Alto Unit 42](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [OpenSSF Scorecard — GitHub](https://github.com/ossf/scorecard)
- [OpenSSF Scorecard official site](https://scorecard.dev/)
- [cosign Verification of npm Provenance — Sigstore Blog](https://blog.sigstore.dev/cosign-verify-bundles/)
- [Mitigating supply chain attacks — pnpm](https://pnpm.io/supply-chain-security)
- [NPM Ignore Scripts Best Practices — Node.js Security](https://www.nodejs-security.com/blog/npm-ignore-scripts-best-practices-as-security-mitigation-for-malicious-packages)
- [NPM Security Best Practices after Shai-Hulud — Snyk](https://snyk.io/articles/npm-security-best-practices-shai-hulud-attack/)
- [npm Supply Chain Attack Detection — Splunk](https://www.splunk.com/en_us/blog/security/npm-supply-chain-attack-detection-analysis.html)
- [NPM Security Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
