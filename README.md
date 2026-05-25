<p align="center">
  <img alt="Vibe Sec — security gap finder for vibe-coded apps" src="https://626labs.dev/assets/brand/plugins/vibe-sec-banner-1500x500.png" />
</p>

# Vibe Sec

**Tier-aware security audit for vibe-coded apps — it orchestrates the scanners you already trust, classifies what they find against your app's risk tier, and routes the fixes.**

[![stable](https://img.shields.io/github/v/tag/estevanhernandez-stack-ed/vibe-sec?label=stable&color=17d4fa)](https://github.com/estevanhernandez-stack-ed/vibe-sec/tags)

## What it does

Vibe-coded apps ship with a predictable, classifiable set of security gaps — secrets hardcoded for convenience, auth scaffolded as a thin wrapper, user input trusted everywhere, dependencies picked from training data. Vibe Sec knows that fingerprint. It doesn't try to out-detect gitleaks, OSV-Scanner, Semgrep, or Trivy — those are free, mature, and better at raw detection than anything worth rebuilding. It defers to them when they're present, falls back to an in-house baseline when they're absent, and adds the layer they all lack: tier-aware classification, severity calibration, a four-band report that respects builder fatigue, and confidence-routed fixes.

A full `/vibe-sec:audit` runs across **ten concerns**:

- **Secrets** — hardcoded keys, committed `.env` files, client-side exposure.
- **Dependency CVEs** — known vulnerabilities in direct and transitive deps.
- **Supply chain** — abandoned packages, typosquats, lockfile integrity, pinning.
- **Config posture** — CORS, security headers, TLS, debug mode, open cloud resource policies.
- **Crypto / PII** — sensitive data in logs, PII in responses, encryption at rest and in transit.
- **Auth model** — session handling, password storage, CSRF, frontend-only access control.
- **OWASP survey** — the Top 10, with honest coverage depth (static where static is the right instrument, surfaced via threat model where the work is human reasoning).
- **Rate limiting** — posture on auth and state-changing endpoints.
- **Tier thresholds** — the math substrate, always on; resolves "secure enough" to an OWASP ASVS level.
- **Threat model** — STRIDE/DREAD synthesis. The sink node — opt-in at Prototype/Internal, auto-included from Public-facing up.

The verdict leads: classified tier, weighted score vs the tier bar, PASS or FAIL — then the bands, named tools, and the worst item first.

## How it works

Vibe Sec ships as a **Claude Code plugin** (the audit + classification + fix layer) and a **standalone CLI** (the deterministic secret-leak scanner). The plugin's commands:

| Command | What it does |
|---|---|
| `/vibe-sec:audit` | Full tier-calibrated audit across all ten concerns — classify, detect, render the four-band report. |
| `/vibe-sec:scan` | Fast secret scan — defers to gitleaks/trufflehog, in-house Layer A fallback. |
| `/vibe-sec:deps` | Dependency + supply-chain check — CVEs, lockfile integrity, pinning. |
| `/vibe-sec:gate` | CI pass/fail vs tier — exit codes 0/1/2 plus GitHub Actions annotations. |
| `/vibe-sec:posture` | Read-only tier-aware summary from cached state — no re-scan. |
| `/vibe-sec:fix` | Confidence-routed remediation with destructive-action overrides. |
| `/vibe-sec:threat-model` | STRIDE/DREAD synthesis — Mermaid + Threat Dragon JSON. |
| `/vibe-sec:research` | Re-run one concern's domain research to refresh the living briefs. |

**The classifier drives everything.** Tier is a scope gate, not just a severity dial — concerns out of scope for your tier are excluded from the score denominator, so a Prototype app never reports as failing on Customer-facing concerns it never opted into. The tiers map to OWASP ASVS levels (Internal → L1, Public-facing → L2, Customer-facing → L3, Regulated → L3 + NIST SSDF + SBOM), so "secure enough" resolves to a known-quantity target you can hand to an auditor — not a self-chosen threshold.

**It defers, then credits whichever ran.** Per concern, Vibe Sec detects the tool of record — gitleaks/trufflehog for secrets, OSV-Scanner for CVEs, Semgrep CE for injection and authz, Trivy for supply chain — defers to it when present, runs the in-house baseline when absent, and re-classifies the output against your tier either way. The differentiator is the layer, not the detector.

**Fixes are confidence-routed.** High confidence (≥0.9) auto-applies — `.gitignore` entries, security headers, secret references. Medium produces a template you confirm. Low is advisory — the plugin names the gap, you make the architectural call.

## Validated on

A real Firebase app.

## Install

**Stable (recommended) — as a Claude Code plugin via the marketplace:**

```text
/plugin marketplace add estevanhernandez-stack-ed/vibe-plugins
/plugin install vibe-sec@vibe-plugins
```

**Canary — track this repo's `main`:**

```text
/plugin install vibe-sec@estevanhernandez-stack-ed/vibe-sec
```

**CLI via npm — the deterministic secret-leak scanner:**

```bash
npm install -g @esthernandez/vibe-sec-cli
vibe-sec scan .
```

The CLI is a pure-regex secret-leak scanner with severity tiers and CI-safe exit codes — no LLM in the loop. It detects API keys, tokens, and credentials leaked in source. The plugin orchestrates the full ten-concern audit on top.

## Repo structure

This is the **Vibe Sec solo repo** — the canary / edge-release channel. Two npm packages live here as a pnpm workspace:

- **`packages/vibe-sec/`** — the Claude Code plugin (`@esthernandez/vibe-sec`). The audit, classification, fix engine, and threat-model synthesis.
- **`packages/vibe-sec-cli/`** — the deterministic CLI (`@esthernandez/vibe-sec-cli`). The secret-leak scanner shipping today.

Development:

```bash
pnpm install
pnpm test          # runs vibe-sec-cli --help as a smoke test
```

Requires Node 20+ and pnpm 9+.

## Ecosystem positioning

Vibe Sec owns the **security-as-first-class-audit** surface no other 626Labs plugin touches:

- **Vibe Cartographer** captures architecture-level security concerns in `/prd` + `/spec` — but doesn't audit.
- **Vibe Doc** flags hardcoded-credential patterns in *documentation* — not source.
- **Vibe Test** generates behavioral tests that catch injection / auth edge cases — but doesn't classify the security surface itself. Vibe Sec inherits Vibe Test's tier classification via a handshake when present.

Full gap analysis: [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](./packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md).

## Links

- **Framework + thesis:** [`packages/vibe-sec/framework.md`](./packages/vibe-sec/framework.md)
- **Gap analysis:** [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](./packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md)
- **626 Labs:** https://626labs.dev

## Part of the Vibe ecosystem

One of 11 plugins in the **[Vibe Plugins](https://github.com/estevanhernandez-stack-ed/vibe-plugins)** marketplace from [626 Labs](https://626labs.dev) — foundations (Thesis Engine, Keystone) and process pillars (Cartographer, Doc, Sec, Test, Thesis, Iterate, Taker, Walk, Insights) for AI-assisted creation.

```text
/plugin marketplace add estevanhernandez-stack-ed/vibe-plugins
```

## License

MIT — © 626Labs LLC — *Imagine Something Else.*
