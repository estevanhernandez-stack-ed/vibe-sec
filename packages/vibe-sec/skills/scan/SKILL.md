---
name: scan
description: >
  Fast secret scan. Use when the user says "/vibe-sec:scan", "scan for secrets",
  "check for leaked keys", "did I commit a secret", "scan my repo for
  credentials", or wants a quick secrets-only pass. Detects the tool of record
  (gitleaks, then trufflehog) and defers to it when present; falls back to the
  in-house Layer A regex baseline when absent. Writes findings to
  .vibe-sec/state/findings.jsonl. The promoted CLI lives behind this command.
---

# Vibe Sec — scan

Fast-path secret detection. Read `${CLAUDE_PLUGIN_ROOT}/skills/guide/SKILL.md`
for shared behavior, then run the scan.

## How it works (the orchestration contract)

This is the orchestration pattern's first concrete instance:

1. **Detect the tool of record.** Probe for `gitleaks`, then `trufflehog`, on PATH.
2. **Defer when present.** Shell out, parse the JSON report into the neutral
   finding shape, and credit the tool in the output. gitleaks beats the in-house
   regex — don't compete with it, re-frame it.
3. **Fall back when absent.** Run the in-house Layer A regex baseline (40-50
   provider patterns: AWS, GitHub PAT, Stripe, OpenAI, Anthropic, Slack, private
   keys, DB URLs with credentials, generic key/secret assigns).
4. **Re-classify and mask regardless of source.** Severity calibration is
   Vibe Sec's job either way. Raw secret values are always masked — never
   persist a live credential to findings.jsonl or the terminal.

Layer A (regex) is what Phase 1 ships in-house. Layer B (entropy) and Layer C
(AST) are Phase 2.

## Running it

The detection logic is built TypeScript. Run the headless entry for a
deterministic scan:

```
node ${CLAUDE_PLUGIN_ROOT}/dist/cli.js --root <project> --no-color
```

Exit codes (CI-safe, preserved from the original CLI):
- `0` — clean, or only findings below `--min-severity` (default: high)
- `1` — findings at or above `--min-severity`
- `2` — scanner error

Options: `--root <dir>`, `--output <file>`, `--min-severity <critical|high|medium|low>`,
`--json`, `--no-color`.

## Output

- **Terminal banner** — severity counts + the top findings, masked.
- **JSON report** — written to `.vibe-sec/state/audit.json` (legacy CLI parity).
- **findings.jsonl** — the cross-plugin handoff sidecar, append-only.

## What to tell the user

Lead with the verdict: clean, or N findings at severity X. Name which tool
produced them (gitleaks vs in-house) so they know what's underneath. If the
in-house fallback ran because gitleaks isn't installed, surface the Band 4
complement: "install gitleaks to catch git-history leaks the working-tree scan
misses." Don't nag — surface it once.

## Example/sample path handling

A critical-looking match inside an `example`/`sample`/`mock`/`fixture` path is
downgraded (critical → medium, high → low) — those are usually documentation,
not live leaks. The downgrade is preserved from the promoted CLI.
