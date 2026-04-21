# Vibe Sec

> Security gap finder for vibe-coded apps — leaked secrets, sketchy auth, missing input validation, stale dependencies.

A Claude Code plugin (coming soon) and CLI (shipping now) for the **diagnostic security audit** of vibe-coded applications. Fills the security-as-first-class-audit gap no other 626Labs plugin touches — complements Vibe Test's test-layer coverage.

## Current status

- **`@esthernandez/vibe-sec-cli@0.1.0`** — **shipping now.** 404-line pure-regex secret-leak scanner. Detects AWS keys, GitHub PATs, Stripe keys, Firebase API keys, generic high-entropy strings. CI-safe exit codes. No LLM in the loop. `npm install -g @esthernandez/vibe-sec-cli && vibe-sec scan .`
- **`@esthernandez/vibe-sec@0.0.1`** — **package name reserved** for the full plugin. No code yet. Builds out per the framework in [`packages/vibe-sec/framework.md`](./packages/vibe-sec/framework.md) and the gap analysis in [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](./packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md).

## Repo structure

This is the **Vibe Sec solo repo** — the canary / edge-release channel. Two npm packages live here as a pnpm workspace:

- **`packages/vibe-sec/`** — the Claude Code plugin (`@esthernandez/vibe-sec`). Currently stub-only; the framework + gap-analysis docs define what the plugin becomes.
- **`packages/vibe-sec-cli/`** — the deterministic CLI (`@esthernandez/vibe-sec-cli`). Secret-leak scanner shipping today.

## Install channels

**Canary — for beta testers.** Paste this repo's URL in Claude Code's *Add Marketplace* dialog:

```
estevanhernandez-stack-ed/vibe-sec
```

Tracks `main` — bleeding edge, faster feedback, occasional breakage.

**Stable — for everyone else.** Install via the aggregated 626Labs marketplace:

```
estevanhernandez-stack-ed/vibe-plugins
```

Pins to a specific stable tag. You see new releases only after they're explicitly promoted from canary.

**CLI via npm:**

```bash
npm install -g @esthernandez/vibe-sec-cli
vibe-sec scan .
```

## Ecosystem positioning

Vibe Sec intentionally overlaps with zero other 626Labs plugins:

- **Vibe Cartographer** captures *architecture-level* security concerns in `/prd` + `/spec` — but doesn't audit.
- **Vibe Doc** flags hardcoded-credential patterns in *documentation* — not source.
- **Vibe Test** generates behavioral tests that catch injection / auth edge cases — but doesn't classify the security surface itself.

Vibe Sec owns: dependency CVE audit, secret detection in working tree + git history, full OWASP Top 10 categorical audit, crypto/PII handling audit, config-level security posture, supply chain hardening, rate-limiting posture, auth model static analysis, threat model generation, security-tier thresholds. Full gap analysis: [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](./packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md).

## Development

```bash
pnpm install
pnpm test          # runs vibe-sec-cli --help as a smoke test for now
```

Requires Node 20+ and pnpm 9+.

## Links

- **Framework + thesis:** [`packages/vibe-sec/framework.md`](./packages/vibe-sec/framework.md)
- **Gap analysis:** [`packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md`](./packages/vibe-sec/docs/gap-analysis-as-of-vibe-test-v0.2.md)
- **626Labs:** https://626labs.dev

## License

MIT — © 626Labs LLC
