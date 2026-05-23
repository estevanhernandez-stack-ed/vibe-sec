---
name: scan
description: >
  Full secret scan. Use when the user says "/vibe-sec:scan", "scan for secrets",
  "check for leaked keys", "did I commit a secret", "scan my repo for
  credentials", or wants a secrets pass. Detects the tool of record (gitleaks,
  then trufflehog) and defers to it when present; falls back to the in-house
  three-layer stack (regex + entropy + AST) when absent. Optional full git-history
  scan and --verify live-secret confirmation. Writes findings to
  .vibe-sec/state/findings.jsonl.
---

# Vibe Sec — scan

Full-stack secret detection. Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md`
for shared behavior, then run the scan.

## The orchestration contract

This is the orchestration pattern's first concrete instance:

1. **Detect the tool of record.** Probe for `gitleaks`, then `trufflehog`, on PATH.
2. **Defer when present.** Shell out, parse the JSON report into the neutral
   finding shape, credit the tool. gitleaks beats the in-house regex — re-frame
   it, don't compete.
3. **Fall back to the in-house full stack when absent.** Three layers, deduped
   by file:line:column (higher-precision layer wins):
   - **Layer A — regex.** ~40 provider patterns (AWS, GitHub all variants,
     Stripe, OpenAI, Anthropic, Slack, SendGrid, NPM/PyPI/Docker tokens,
     Discord, private keys, DB URLs with creds, and more).
   - **Layer B — entropy.** Shannon ≥4.5 base64 / ≥3.0 hex, 20-char floor, only
     in secret-shaped assignment context (FP discipline).
   - **Layer C — AST.** `@babel/parser` catches what regex misses: JSX-prop
     secrets (`<Stripe apiKey="..." />`) and `process.env.X = "literal"`
     overwrites.
4. **Re-classify and mask regardless of source.** Severity calibration is Vibe
   Sec's job either way. Raw secret values are always masked — never persist a
   live credential to findings.jsonl or the terminal.

## Full git-history scan (Decision 9)

Working tree is the present; the history is the rest. 64% of old leaked
credentials are still live, so the first run walks the **full git history** and
later runs go incremental from a cached HEAD boundary
(`.vibe-sec/state/history-scan.json`).

- **First run:** name the operation explicitly — "first run, scanning full git
  history, this takes a minute." Don't run it silently.
- **Shallow clone:** if the repo is shallow, surface the banner note — history
  may be truncated, findings are working-tree-plus-available-history only.
- **A secret found only in history** still matters: rotation is step zero. Git
  history rewrite (filter-repo / BFG) is an inline runbook, never executed.

## Verification (--verify, opt-in)

v0.2 is no-network by default. `--verify` defers to **trufflehog's** verifier to
confirm which keys are actually live. A verified secret is Critical, no tier
discount. If trufflehog isn't installed, say so and surface it as the Band-4
complement — don't silently skip.

## Running it

The detection is built TypeScript. Headless entry for a deterministic scan:

```
node ${CLAUDE_PLUGIN_ROOT}/dist/cli.js --root <project> --no-color
```

Exit codes (CI-safe): `0` clean / `1` findings at-or-above `--min-severity`
(default high) / `2` scanner error.

## Output (three channels)

- **Terminal banner** — severity counts + top findings, masked, tool credited.
- **JSON report** — `.vibe-sec/state/audit.json`.
- **findings.jsonl** — the append-only cross-plugin handoff sidecar.

## Special cases

- **Example/sample/mock paths** — critical-looking matches downgrade
  (critical→medium, high→low). Documentation, not live leaks.
- **Firebase web apiKey** — informational, not a blocker (public by design).
  Emits a config-posture companion: "audit your Security Rules — the rules are
  the real access control."

## What to tell the user

Lead with the verdict: clean, or N findings at severity X. Name which tool
produced them (gitleaks vs in-house) so they know what's underneath. If the
in-house fallback ran because gitleaks isn't installed, surface the complement
once: "install gitleaks to catch history leaks the working-tree scan misses."
Don't nag.
