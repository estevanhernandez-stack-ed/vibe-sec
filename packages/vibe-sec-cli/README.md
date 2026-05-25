# @esthernandez/vibe-sec-cli

**Headless secret scanner for vibe-coded apps — CI-safe, zero runtime dependencies.**

The standalone command-line surface of [Vibe Sec](https://github.com/estevanhernandez-stack-ed/vibe-sec). Scans a repo for leaked API keys, tokens, and credentials, classifies them by severity, masks every match, and emits a CI-friendly JSON report plus a terminal banner. Defers to `gitleaks` / `trufflehog` when they're on `PATH`; falls back to the in-house Layer A/B/C engine (provider regex + entropy + AST) when they're absent.

This package is a **self-contained bundle** — the detection engine and all of its dependencies are inlined into `dist/cli.js`, so it installs with no transitive npm packages. The richer ten-concern tier-aware audit (auth model, dependency CVEs, config posture, threat model, and so on) ships as the [Vibe Sec Claude Code plugin](https://github.com/estevanhernandez-stack-ed/vibe-sec) via the `/vibe-sec:*` slash commands. This CLI is the fast, no-LLM, CI-lane secret scan.

---

## Install

```bash
npm install -g @esthernandez/vibe-sec-cli
```

Or run without installing:

```bash
npx @esthernandez/vibe-sec-cli scan
```

---

## Usage

```bash
# Scan the current directory
vibe-sec scan

# Bare invocation is the same as 'scan'
vibe-sec

# Scan a different directory
vibe-sec scan --root ./some-repo

# Write JSON elsewhere
vibe-sec scan --output /tmp/audit.json

# Treat medium findings as CI-breaking (default is "high")
vibe-sec scan --min-severity medium

# Print only JSON (machine-readable, no banner)
vibe-sec scan --json
```

### Exit codes

- `0` — clean, or findings below `--min-severity`
- `1` — findings at or above `--min-severity`
- `2` — scanner error (unreadable tree, bad args)

Wire it into CI:

```yaml
- run: npx @esthernandez/vibe-sec-cli scan --min-severity high
```

When `gitleaks` or `trufflehog` is available on the runner, the CLI defers to it as the tool of record and re-classifies its findings; otherwise it runs the in-house engine. Either way, findings are masked and the exit-code contract is identical.

---

## What it detects

The in-house fallback engine covers the canonical provider-prefix catalog — AWS, GitHub PATs (classic + fine-grained), Stripe (live + test), OpenAI, Anthropic, Google, Slack, DB URLs with embedded credentials, private-key blocks, JWTs, and generic `api_key = "..."` / `secret = "..."` assignments — plus an entropy layer and an AST layer for structural matches. Context-aware downgrades apply for `example|sample|mock|fake|placeholder|dummy|template|fixture` paths, and documented placeholder keys are suppressed.

### What it skips

- `node_modules`, `.git`, `.venv`, `venv`, `dist`, `build`, `coverage`, `.next`, `.nuxt`, `.turbo`, `.cache`, `__pycache__`, `.vibe-sec`
- Binary files (png, jpg, pdf, zip, …)
- Files larger than 1 MB

---

## Output

The scanner writes two artifacts.

### Terminal banner

```
  vibe-sec scan · v0.2.0 · in-house
  342 files scanned · /path/to/repo

  Findings:
    CRITICAL   1
    HIGH       1

    critical AWS_ACCESS_KEY_ID            src/config.ts:1:17
    high     DATABASE_URL_WITH_CREDENTIALS src/config.ts:2:16

  → JSON report: .vibe-sec/state/audit.json
```

### JSON sidecar (`.vibe-sec/state/audit.json`)

```json
{
  "version": 1,
  "scanner": "vibe-sec",
  "scannerVersion": "0.2.0",
  "toolOfRecord": "in-house",
  "scannedAt": "2026-05-25T01:41:17.418Z",
  "rootDir": "/path/to/repo",
  "filesScanned": 1,
  "counts": { "critical": 1, "high": 1, "medium": 0, "low": 0 },
  "findings": [
    {
      "pattern": "AWS_ACCESS_KEY_ID",
      "severity": "critical",
      "file": "config.js",
      "line": 1,
      "column": 17,
      "match": "AKIAAB…4567",
      "preview": "const awsKey = \"AKIAAB…4567\";",
      "remediation": "Rotate this AWS access key in IAM. Move secrets to environment variables or AWS Secrets Manager."
    }
  ]
}
```

The `match` field is always masked — the scanner never prints full secrets to logs or JSON.

---

Part of [626 Labs](https://626labs.dev). MIT licensed.
