# Secret Detection — Research Brief

**Concern:** Secret detection in working tree + git history
**Agent persona:** Credentials-leakage / secrets-detection expert
**Written for:** Vibe Sec v0.2 `/spec` synthesis
**Foundation:** `packages/vibe-sec-cli/src/index.js` (404-line regex scanner, 15 patterns, TTY banner + JSON sidecar, exit 0/1/2 CI contract)
**Date:** 2026-04-20

> *"The vibe-coded app's first security failure is almost always a secret in a public repo. Not because the builder is careless — because the LLM handed them a working `.env` and the commit hook wasn't wired."*

---

## Landscape

Secret sprawl in 2025–2026 is not a background problem — it is *the* dominant credentials-leakage vector, and it is accelerating. GitGuardian's **State of Secrets Sprawl 2026** counted **28.6 million new secrets** exposed in public GitHub commits across 2025 — a **34% year-over-year increase** and the largest single-year jump on record. Three million repositories were affected. The top leak families were **Google API keys, MongoDB credentials, OpenWeatherMap tokens, Telegram Bot tokens, Google Cloud keys, and AWS IAM credentials**. AI-provider keys alone grew **81% YoY** — over **1.2 million AI-service secrets** in a single year, including **113k+ DeepSeek keys**. A Wiz audit of 50 AI companies found **65% had verified secrets leaked** on GitHub.

Most damning for the remediation story: GitGuardian re-tested credentials originally identified in 2022 — **64% were still valid and exploitable** in early 2026. The industry has a discovery problem *and* a rotation problem. Vibe Sec has to treat both.

### Tooling landscape (the ecosystem Vibe Sec composes with)

- **gitleaks** — still the de-facto open-source local scanner. Ships 150+ default rules, TOML-extensible, v8.28+ added **composite rules** (primary + auxiliary regex with proximity constraints) to cut false positives. The creator spun out **Betterleaks** in March 2026 — same regex corpus, adds **doubly/triply-encoded credential detection** (base64-over-base64, URL-encoded, JSON-string-escaped) and parallelized Git history scanning. Vibe Sec's natural "local no-account baseline."
- **TruffleHog v3** — the verification leader. **700+ provider detectors**, each a Go program with a keyword + regex + **live API verification endpoint**. Calls `GetCallerIdentity` for AWS, hits provider APIs for Stripe/Slack/OpenAI/etc. Returns `verified | unverified | unknown`. The v3.67+ series added chunk-dedup (doesn't re-verify the same secret across detectors) and lazy-quantifier prefix matching. This is what "verified secret" means in industry today.
- **GitHub Secret Scanning + Push Protection** — **free for all public repos** since April 2025 (when GitHub unbundled Advanced Security). Push protection blocks commits containing recognized provider patterns *before they land on the remote*. For private repos it's part of GitHub Secret Protection at $19/committer/month. Nine new detection types were added in the March 2026 coverage update. Critical implication: for any public repo, **GitHub is already scanning in parallel with Vibe Sec** — the plugin should credit this, not duplicate it loudly.
- **detect-secrets (Yelp)** — 27 detectors across three strategies (regex, entropy, keyword). Baseline-first methodology: scan once, establish baseline, only alert on *new* secrets. Entropy thresholds default to **4.5 for base64, 3.0 for hex**. Inline `pragma: allowlist secret` comments for FP suppression. Python-only, best for Python shops.
- **GitGuardian** — commercial, deepest provider catalog, commit-time detection via GitHub App + CI integrations. Pattern #13 complement, not a day-one requirement.
- **AWS IAM canary tokens / Thinkst Canarytokens** — orthogonal technique. You *plant* decoy credentials; if they fire, you've been breached. Free via canarytokens.org. GuardDuty Extended Threat Detection correlates signals across compromised-key use. Worth mentioning in the SECURITY.md handoff as a future-runs complement; Vibe Sec itself should not plant canaries.

### The existing CLI — what we have to work with

The foundation (`packages/vibe-sec-cli/src/index.js`) is deliberately minimal and sound:

- **15 patterns** across AWS, GitHub (classic + fine-grained), Stripe (live + test), Slack, OpenAI, Anthropic, Google API key, Google OAuth client ID, JWT, PRIVATE KEY PEM blocks, DB URLs with embedded credentials, and two generic-assignment patterns (`api_key = "..."`, `secret = "..."`).
- **Severity-per-pattern** with context-aware downgrade: if the filename contains `example|sample|mock|fake|placeholder|dummy|template|fixture`, critical → medium and high → low.
- **Binary-extension skiplist**, **vendored-path skiplist** (`node_modules`, `.git`, `.venv`, `dist`, `.next`, etc.), **1MB file-size cap**.
- **Masking** (`AKIA…7890`), **inline-preview with secret masked inside the preview line** — JSON report never persists a raw secret.
- **KNOWN_PLACEHOLDERS set** — AWS's documented `AKIAIOSFODNN7EXAMPLE`, Stripe's `sk_test_4eC39...`. These are string-concatenated in source so GitHub push-protection doesn't flag the scanner's own file.
- **Exit codes 0/1/2**, `--min-severity`, `--json`, `--no-color`, JSON sidecar at `.vibe-sec/state/audit.json`.

This is a solid Layer-1 hygiene scanner. What it doesn't do — and what v0.2 must — is **git history**, **entropy fallback**, **env-discipline checks** (`.env` in `.gitignore`? `.env.example` present?), **verification against providers**, and the **broader provider catalog** that modern secret sprawl demands.

---

## Detection mechanics

Secret detection is a three-layer stack. Each layer catches what the layer below misses, and each layer has different false-positive characteristics.

### Layer A — High-confidence regex (provider-specific prefixed patterns)

This is what the existing CLI does well. Provider tokens with **distinctive prefixes + fixed length + known charset** are the easiest wins. Expand the current 15 to the canonical ~40-50 patterns every mature scanner ships:

**Additions Vibe Sec v0.2 should carry (working-tree-ready):**

| Pattern | Regex shape | Severity baseline |
|---|---|---|
| `OPENAI_API_KEY` (refined) | `\bsk-(?:proj-\|svcacct-\|admin-)?[A-Za-z0-9_-]{20,74}T3BlbkFJ[A-Za-z0-9_-]{20,74}\b` | critical |
| `ANTHROPIC_API_KEY` (refined) | `\bsk-ant-api03-[A-Za-z0-9_-]{93}AA\b` | critical |
| `GITHUB_APP_TOKEN` | `\bghs_[A-Za-z0-9]{36}\b` | critical |
| `GITHUB_USER_TOKEN` | `\bghu_[A-Za-z0-9]{36}\b` | critical |
| `GITHUB_OAUTH_TOKEN` | `\bgho_[A-Za-z0-9]{36}\b` | critical |
| `GITHUB_REFRESH_TOKEN` | `\bghr_[A-Za-z0-9]{36}\b` | critical |
| `AWS_SECRET_ACCESS_KEY` | contextual pair-match near `AKIA...`, 40-char b64 | critical |
| `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY` | `"private_key":\s*"-----BEGIN PRIVATE KEY-----` in JSON | critical |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | JSON w/ `"type": "service_account"` + `"private_key"` | critical |
| `FIREBASE_CLIENT_API_KEY` | `\bAIza[0-9A-Za-z_-]{35}\b` (already covered; tag Firebase context) | medium (browser-exposed by design) |
| `SUPABASE_SERVICE_ROLE_KEY` | JWT w/ `"role":"service_role"` in base64 payload | critical |
| `TWILIO_API_KEY` | `\bSK[0-9a-fA-F]{32}\b` + keyword proximity | high |
| `TWILIO_ACCOUNT_SID` | `\bAC[0-9a-fA-F]{32}\b` | medium |
| `SENDGRID_API_KEY` | `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b` | high |
| `POSTMAN_API_KEY` | `\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b` | medium |
| `NPM_AUTH_TOKEN` | `\bnpm_[A-Za-z0-9]{36}\b` | critical |
| `PYPI_API_TOKEN` | `\bpypi-AgEI[A-Za-z0-9_-]+\b` | critical |
| `DOCKERHUB_PAT` | `\bdckr_pat_[A-Za-z0-9_-]{27,}\b` | high |
| `VERCEL_TOKEN` | keyword + 24-char hex | high |
| `HEROKU_API_KEY` | UUID + `heroku` keyword proximity | high |
| `DISCORD_BOT_TOKEN` | `\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b` | high |
| `MAILGUN_API_KEY` | `\bkey-[a-f0-9]{32}\b` | high |
| `DEEPSEEK_API_KEY` | `\bsk-[a-f0-9]{32}\b` (context-required; collides with OpenAI-style) | critical |
| `HUGGINGFACE_TOKEN` | `\bhf_[A-Za-z0-9]{34}\b` | high |

**Pattern hygiene rules** (apply to all):
- **Word boundary on both sides** — prevents matching inside longer strings that happen to contain the prefix.
- **Keyword proximity for generic-looking tokens** — require `stripe`, `twilio`, `discord` etc. within N chars when the regex alone would be ambiguous. Gitleaks' composite-rules approach is the proven model.
- **Prefix-collision resolver** — DeepSeek and OpenAI both use `sk-`. If both detectors hit the same chunk, require the OpenAI-specific suffix (`T3BlbkFJ`) before attributing to OpenAI; otherwise classify as `GENERIC_SK_TOKEN` with lower confidence.

### Layer B — Entropy-based detection (the catch-all)

Regex covers *known* formats. Entropy covers *unknown* formats and high-randomness strings that look like keys. This is where detect-secrets earns its keep.

**Mechanics:**
- **Shannon entropy** over the candidate string. Base64 charset threshold **≥4.5**, hex charset threshold **≥3.0** (same defaults detect-secrets uses).
- **Length gate** — only evaluate strings of 20+ chars (shorter has too few samples to be meaningful).
- **Charset gate** — all-digit strings are *not* secrets (phone numbers, IDs). Max Shannon entropy for 10-digit alphabet is ~3.32; clamp below 3.0 to rule them out.
- **Context gate** — only flag entropy hits when they appear as the RHS of an assignment (`foo = "..."`, `FOO: "..."`, `"foo": "..."`) or as the value of a `.env`-style `FOO=...` line.
- **Known-provider bypass** — if the string already matched a Layer A detector, skip Layer B (dedup).

**Why this matters for vibe-coded apps:** custom internal APIs, self-hosted services (Authelia, Supabase self-hosted, internal JWT issuers) use high-entropy tokens without a recognizable prefix. Pure regex misses them; entropy catches them.

### Layer C — AST-aware detection (structure over strings)

This is where Vibe Sec goes *beyond* what gitleaks/trufflehog do — and where the promotion from JS regex to TypeScript-plus-AST pays off.

For `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` — parse with a fast TS parser (tsup already in the toolchain uses esbuild; `@babel/parser` or `acorn` for a pure-JS walker). Walk the AST for:

- **VariableDeclarator** with ID matching `/secret|password|token|api[_-]?key|auth|credential/i` and an `Init` that is a `StringLiteral` of length ≥12.
- **ObjectProperty** / **ObjectExpression** with same key pattern, `StringLiteral` value.
- **AssignmentExpression** with LHS matching the pattern.
- **Call expressions** to `process.env.X = "..."` (overwriting env at runtime — suspicious).
- **TemplateLiteral** with a single `StringLiteral` quasi — treat like StringLiteral.
- **JSX attributes** named `apiKey`, `token` etc. with inline string values (browser-side leak).

For `.env`, `.env.*`, `.envrc` files — line-based parse: `KEY=VALUE`, flag any `VALUE` that is non-empty, non-placeholder, passes entropy gate.

For `.json`, `.yaml`, `.toml` config files — structural parse, key-path + value inspection (e.g., `config.database.password = "..."` in YAML).

For `.py`, `.go`, `.rs` — JS/TS focus for v0.2 per scope cut; these are v0.3+ work. But the regex + entropy layers still fire on them.

### Git history scan (the "deep scan")

The existing CLI scans working tree only. Git history scan is table stakes for v0.2.

**Implementation path without shelling out:**
- Shell out to `git` (always present in a repo). Use `git log --all --full-history -p` or, for speed, `git rev-list --all | git cat-file --batch` to stream blobs. Diff-scanning catches additions even if later removed.
- **Incremental mode**: remember last-scanned commit SHA in `.vibe-sec/state/history-scan.json`; on subsequent runs, scan only commits since that SHA (`git log <last-sha>..HEAD --all -p`).
- **Depth flags**: `--shallow` (HEAD only, ~1s), `--recent` (last 100 commits, ~5s typical), `--full` (everything, can be minutes on big repos). Default `--recent` for `/vibe-sec:audit`; `--full` only on explicit `/vibe-sec:scan --history=full`.
- Dedup: hash (pattern-name + masked-match + file-path) across commits so the same secret introduced in commit X and still present at HEAD doesn't report 50 times.

**Branch consideration:** by default scan `--all` refs (includes stash, dangling, unmerged branches) because secrets often hide in abandoned feature branches. Emit per-finding `refs: ["refs/heads/feature-x", "stash@{0}"]` so the builder sees where it lives.

**Shallow-clone edge case:** CI environments often `git clone --depth=1`. Detect this (`git rev-parse --is-shallow-repository`) and emit a banner note: "history scan limited — running in a shallow clone. Run locally for full coverage."

**Optional gitleaks pass-through:** if `gitleaks` is on PATH, run `gitleaks detect --source . --no-git --report-format json` in parallel with Vibe Sec's own scan. Merge findings, credit gitleaks. Same for `trufflehog filesystem --json .` if present. **Do not require** either — keep the no-account baseline intact.

### Verification (Pattern #13 complement, not day-one)

TruffleHog's verification model (live API call to confirm the secret is active) is best-in-class but **expensive, rate-limited, and network-dependent**. For v0.2:

- **Do not verify by default.** Classify all matches as `unverified`.
- **Opt-in via `--verify` flag** on `/vibe-sec:scan`, with explicit warning: "this will make API calls to each detected provider."
- When opting in, start with three low-rate-limit cases: AWS (`sts:GetCallerIdentity`, free, instant), GitHub (`GET /user` with token), OpenAI (`GET /v1/models`). These three cover ~60% of catastrophic leaks.
- Stretch goal for v0.3: wire Trufflehog-verified output when `trufflehog` is installed — borrow its verifier rather than reimplementing.

---

## False-positive risks

The scope commits Vibe Sec to **12% FP rate across the board**. For secret detection specifically, this target is achievable but requires disciplined FP classes. The existing CLI already handles three of them; the brief extends to nine.

### The nine false-positive classes

1. **Documented example strings** — AWS literally publishes `AKIAIOSFODNN7EXAMPLE` in SDK docs; Stripe publishes `sk_test_4eC39...` (truncated in this brief — the full literal is string-concatenated in the scanner's `KNOWN_PLACEHOLDERS` set so push protection never sees it). Existing CLI handles via `KNOWN_PLACEHOLDERS` Set. Extend to ~30 canonical placeholders (each provider has 1-3).

2. **Intentional placeholder substrings** — `sk_test_xxx`, `ghp_example_token`, `YOUR_API_KEY_HERE`, `REPLACE_ME`, `<INSERT_KEY>`. Regex: `\b(?:your[_-]|example[_-]|replace[_-]|insert[_-]|xxx|xxxx|placeholder|changeme|todo)\b` in or adjacent to the match.

3. **Filename context** — existing CLI already downgrades for `example|sample|mock|fake|placeholder|dummy|template|fixture` in path. Extend filename hint list to include `*.test.*`, `*.spec.*`, `__tests__`, `__fixtures__`, `cypress/fixtures`, `playwright/fixtures`. Important: **downgrade, don't suppress** — a real leaked secret in a test file is still a leaked secret.

4. **Markdown code fences in docs** — README examples, API documentation showing sample request bodies. Flag with content type "markdown fence" and downgrade severity one level. Do not fully suppress; redacted docs that forgot to redact are a known leak vector.

5. **Base64-encoded public keys** — PEM `PUBLIC KEY` blocks get flagged by naive `-----BEGIN.*KEY-----` regex. Existing CLI's pattern already scopes to `PRIVATE KEY` — keep that discipline. JWT signing keys published in JWKS endpoints are public by design; flag only if filename implies server-side (`server/`, `backend/`, `.env`).

6. **Test JWTs with expired `exp`** — a JWT in a test fixture for a session-expiry test is intentionally fake. Parse the `exp` claim; if in the past, downgrade to low.

7. **Truncated hashes masquerading as tokens** — Git SHAs, content hashes, UUIDs. Heuristic: 40-char lowercase-hex without a known prefix is almost always a git SHA. Rule out hex-only 32/40/64-char strings unless adjacent keyword (`token`, `secret`, `key`) is within 3 lines.

8. **High-entropy non-secrets** — URL paths with slugs, minified JS identifiers, compiled asset paths. Counter-heuristic: entropy hit inside a `.min.js`, `.map`, `dist/`, `build/`, `public/assets/` path → skip (these are build artifacts that should already be path-excluded; belt-and-suspenders).

9. **Public-by-design keys** — Google OAuth client IDs (existing CLI correctly tags severity `low`), Firebase web config `apiKey` (browser-exposed by Firebase design; locked down via Firebase security rules, not secrecy). Special case: the `apiKey` in `firebase.initializeApp({apiKey: "..."})` is **the same `AIza...` format as a protected Google API key**. Detect the surrounding call and reclassify to `FIREBASE_WEB_CLIENT_API_KEY` (informational, not high). Emit a companion finding: "this key is public by design — make sure Firestore/RTDB security rules enforce access control." That crosses into config-posture territory.

### Hitting the 12% target

The formula is roughly: base regex FP rate ≈ 25-30%, filename + path context gating drops to ~18%, placeholder allowlist drops to ~14%, AST context (is this actually an assignment?) drops to ~12%, entropy + keyword-proximity for generics drops to ~10%. **The 12% target is achievable without verification.** Verification would push it below 5% but at the cost of network dependency and rate-limit complexity — hence the opt-in posture.

### Suppression UX

- **Inline pragma:** `// vibe-sec:allow-next-line <reason>` and `// vibe-sec:allow <finding-id>`. Same DX as detect-secrets' `pragma: allowlist secret` but namespaced.
- **Persistent suppressions:** `.vibe-sec/suppressions.json` with schema `{finding_hash, pattern, file, reason, suppressed_by, suppressed_at}`. Hash is pattern-name + masked-match + file-path, stable across re-scans.
- **Level-2 self-evolution feeds back**: if the builder suppresses `GENERIC_SECRET_ASSIGN` 5+ times with the same rationale, propose a profile-level downgrade for that pattern. (Same pattern Vibe Test uses for its suppressions.)

---

## Remediation patterns

Vibe Sec's `/vibe-sec:fix` matrix for secret findings maps to **four remediation classes**, each with a different automation posture. The scope document already locked most of these; this brief concretizes the mechanics.

### Class 1 — `.gitignore` hardening (auto-apply safe)

**Triggers:**
- `.env` exists but not in `.gitignore`.
- `.env.local`, `.env.*.local`, `.env.development`, `.env.production` files present but not covered by `.gitignore` globs.
- `*.pem`, `*.key`, `id_rsa`, `service-account*.json` present but uncovered.

**Action:**
- Auto-apply: add the missing globs to `.gitignore`. Canonical block:
  ```gitignore
  # Secrets and credentials (vibe-sec)
  .env
  .env.local
  .env.*.local
  *.pem
  *.key
  service-account*.json
  ```
- **Also auto-stage `git rm --cached <file>` when the file is already tracked** — critical detail. Adding to `.gitignore` doesn't untrack; the file has to be explicitly removed from the index.
- **Banner: "this only prevents *future* commits from tracking the file. If it's already in git history, the secret is permanently in the remote — you still need rotation + history rewrite."** Do not let builders confuse `.gitignore` with incident response.

### Class 2 — `.env.example` scaffold (stage for confirm)

**Trigger:** `.env` exists with real values; no `.env.example` present.

**Action:** generate `.env.example` with same keys, placeholder values (`REPLACE_ME`, or provider-prefixed placeholders like `sk-ant-api03-<your-key-here>`). Stage in `.vibe-sec/pending/` for review.

### Class 3 — Env-var extraction (guided refactor)

**Trigger:** secret detected as inline string literal in source.

**Action:** propose diff that replaces the inline literal with `process.env.X` (or framework-idiomatic equivalent — `import.meta.env.X` for Vite, `Deno.env.get('X')` for Deno). Add the key to `.env.example`. **Do not auto-apply** — the LLM's choice of variable name matters to the builder. Stage.

### Class 4 — Rotation (always inline, never auto)

**This is the hard line.** Rotation is destructive: it invalidates the live credential. Auto-applying rotation without builder ack can take down production. Scope locks this; brief affirms it.

**Per-provider rotation inline card:**

```
Found: OPENAI_API_KEY (critical) at src/config.ts:12
Masked: sk-pro…8hQA

ROTATION CHECKLIST:
  1. Revoke the exposed key: https://platform.openai.com/api-keys
  2. Generate a new key, scoped to the same resource.
  3. Add the new key to your secret store:
     • Local: .env (already git-ignored)
     • Vercel: vercel env add OPENAI_API_KEY
     • Fly.io: fly secrets set OPENAI_API_KEY=...
     • GitHub Actions: gh secret set OPENAI_API_KEY
  4. Verify: curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
  5. Confirm the old key is revoked (you should get 401 with it).
  6. AUDIT USAGE: check provider dashboard for unexpected charges.

History implications:
  • This secret has been in git for 47 commits (first seen 2026-03-15).
  • The remote (origin) has these commits. Assume the key is public.
  • Rotation is REQUIRED. `.gitignore` alone is insufficient.
  • Optional: rewrite history with `git filter-repo` to remove the blob.
    This is destructive — force-push required, coordinates with collaborators.
    See below for the opt-in command.
```

Inline-only, with copyable commands. No auto-apply. This is the only way to avoid the "Vibe Sec nuked my production integration" horror story.

### Class 5 — Git history rewrite (explicit opt-in, loud warnings)

**Trigger:** secret found in git history past HEAD.

**The warning posture is non-negotiable:**

- Rewriting history **changes every downstream commit SHA**. Every open PR, every collaborator's local clone, every cached CI, every deployment pinned to a SHA — all break.
- **The secret is likely already in the remote's reflog, GitHub's event API, forks, and any mirrors.** Rewriting your history does NOT un-leak the secret. **Rotation first. Always rotation first. History rewrite is cosmetic cleanup, not remediation.**

**Tool choice (2026 state):**
- **`git filter-repo`** is the officially recommended replacement for `git filter-branch` (the latter is deprecated, slow, and foot-gun-ridden). Flexible, actively maintained, handles path-based and blob-based filters.
- **BFG Repo-Cleaner** is simpler, faster for straightforward text-replacement use cases, but Scala/Java dependency.
- **GitHub's built-in:** `gh secret revoke` (for PATs GitHub owns) handles the provider-side rotation for `ghp_`/`github_pat_` tokens — worth knowing.

**Vibe Sec's posture for v0.2:** `/vibe-sec:fix` NEVER runs history-rewrite itself. It emits a runbook card with the exact `git filter-repo --replace-text ...` command, the coordination checklist (notify collaborators, force-push window, rebuild CI caches), and a link to the rotation flow. Builder executes manually.

**Runbook card skeleton:**
```
GIT HISTORY REWRITE (opt-in, destructive)

BEFORE YOU RUN THIS:
  [ ] The secret has been rotated at the provider. (The leaked value is now useless.)
  [ ] You have a fresh backup of the repo (git clone --mirror elsewhere).
  [ ] All collaborators are aware — their clones will need to be re-cloned or hard-reset.
  [ ] No open PRs you care about (rewriting makes them invalid).
  [ ] The repo is small enough that a force-push won't break CI caches irrecoverably.

THE COMMAND:
  # 1. Create replacements.txt with the masked secrets (one per line):
  sk-ant-api03-XXXXX==>REDACTED_BY_VIBE_SEC

  # 2. Run:
  git filter-repo --replace-text replacements.txt

  # 3. Force-push:
  git push origin --force --all
  git push origin --force --tags

  # 4. Ask collaborators to re-clone.

AFTER:
  The old commits still exist on GitHub until garbage collection (can take 90 days).
  File a GitHub support ticket if you need immediate purge from their caches.
  The secret may still be in forks you don't control.
  Rotation was step zero. This step is cosmetic.
```

---

## Pattern #13 complements

The scope locks the "Pattern #13 surface tools at end of audit" design. For secret detection specifically, here's the hierarchy.

### Day-one compose (no account, if installed)

1. **gitleaks** — if on PATH, run in parallel with Vibe Sec's native scan. Merge findings. Credit it in the report: *"gitleaks surfaced 2 findings Vibe Sec's pattern catalog would have missed — consider keeping it wired into your pre-commit hook."*
2. **trufflehog** — same pattern. If installed, run `trufflehog filesystem --json .` and merge. When `--verify` is passed to `/vibe-sec:scan`, prefer trufflehog's verifier over rolling our own.
3. **git** — always present; used for history scan. Not strictly a third-party tool but worth naming as the substrate.

### Surfaced for "future runs" (Pattern #13 card at end of audit)

4. **GitHub Secret Scanning + Push Protection** — for public repos: *"GitHub is already scanning your commits for these providers at push time — this is free and catches issues before they land. Ensure it's enabled at Settings → Code security."* For private repos on Team plan or above: *"$19/committer/month unlocks push protection on your private repos too. Worth it at your tier."*
5. **Betterleaks** — the gitleaks successor. Worth evaluating when encoding-obfuscated secrets (base64-in-base64, URL-encoded tokens) are a concern — common in copy-pasted config chains. Not day-one; emerging tool.
6. **GitGuardian** — commercial depth. Real-time commit-time detection across GitHub/GitLab/Bitbucket with the biggest provider catalog. Pattern #13 card when the builder graduates to customer-facing SaaS or regulated tier.
7. **AWS Canarytokens / canarytokens.org** — different category (breach detection, not leak prevention). Card: *"Plant a decoy AWS credential in your repo; if anyone ever uses it, you'll know you've been breached. Free via canarytokens.org."* Appears in `docs/SECURITY.md` handoff, not in `/vibe-sec:audit` findings.
8. **Snyk / Socket.dev** — their secret-scanning modules are not their strongest feature; credit for SCA, not secrets.

### Categorically out of scope

- **Semgrep** for secrets — Semgrep does better as a SAST pattern engine than as a secret scanner. Their rule pack exists but is less comprehensive than dedicated scanners.
- **Commercial SIEMs** (Splunk, Datadog Security) — runtime correlation, not static detection. Wrong category.

---

## Tier applicability

Secret detection is **the one concern that matters at every tier**, including prototype. The scope locks this position (table at line 122: Prototype tier is "Secret scan + basic dep audit only"). This brief affirms why and specifies the depth per tier.

| Tier | Working-tree scan | Git history | Verification | `.env` discipline | Provider catalog |
|---|---|---|---|---|---|
| **Prototype / hackathon** | YES — full | Recent 100 commits | Off | `.env` in `.gitignore` check | Full |
| **Internal tool** | YES — full | Recent 500 commits | Off | + `.env.example` present check | Full + internal-service patterns |
| **Public-facing** | YES — full | Full history | Opt-in | + client-bundle scan (secrets in `dist/`) | Full + browser-exposed key classification |
| **Customer-facing SaaS** | YES — full | Full + stash + reflog | Opt-in recommended | + per-env file separation audit (`.env.production` vs `.env.staging`) | Full + payment/PII provider emphasis |
| **Regulated / enterprise** | YES — full | Full + all refs | Opt-in mandatory for critical findings | + secret manager integration check (are they using Vault / AWS Secrets Manager / etc.) | Full + compliance-mapped severity |

**Prototype-tier justification:** a hackathon app with a leaked OpenAI key can rack up $10k in API charges overnight. The cost of a secret leak doesn't scale with the tier of the app — it scales with the *value attackers can extract from the leaked credential*. A single AWS root key on a prototype repo is a catastrophe regardless of whether the app is a prototype. **Prototype tier gets full scan, reduced severity calibration on non-catastrophic findings, but NEVER reduced scan depth.**

**Severity calibration by tier:**
- Prototype: committed AWS key = **Critical** (still). Missing `.env.example` = **Low** (nobody's using the app yet).
- Public-facing: committed AWS key = **Critical**. Missing `.env.example` = **Medium** (onboarding friction).
- Regulated: committed AWS key = **Critical** + incident-response beacon fired. Missing `.env.example` = **Medium**. Missing secret manager = **High**.

---

## Cross-concern dependencies

Secret detection is not an island — it bleeds into three other concerns that are also Vibe Sec's responsibility.

### Overlap with concern #5 — Config-level security posture

- `.env` in `.gitignore` is a **shared check**. Vibe Sec's secret detector and config-posture detector both care. Implementation: secret-detector owns the scan, config-posture subscribes to the finding and adds its own framing (posture view: "git-ignored" as a checklist item; secret view: "uncommitted secret exposure").
- **Client-bundle scan for public-facing tier**: `dist/`, `build/`, `.next/` output can contain inlined env vars that were supposed to be server-only. A classic vibe-coded leak: Next.js with `NEXT_PUBLIC_` prefix on the wrong var leaks it into the browser bundle. Static scan of build output for provider patterns catches this. Belongs to secret detection, but config-posture informs it ("your Vite config inlines these vars at build time").
- **Firebase web client API key** is jointly classified: secret detector flags the `AIza...` pattern, config-posture classifier downgrades to "public by design, security-rules-dependent" and emits a companion finding: "verify firestore.rules enforces access control."

### Overlap with OWASP A02 — Cryptographic failures

- **Private keys in repo** (detected as `PRIVATE_KEY_BLOCK`) are both a secret leak AND a crypto failure. The crypto auditor asks different questions: *was this key generated with adequate entropy? Is the algorithm current?* Secret detector says "this key is exposed"; crypto auditor says "this key is weak, re-generate with `openssl genrsa 4096`."
- **Hardcoded JWT signing secret** detected as a `GENERIC_SECRET_ASSIGN` is a crypto failure (signing key known to attacker → session forgery). Finding narrative should cross-reference A02: *"this is a leaked secret AND an authentication bypass vector."*
- **Weak derived keys** (the secret is a short or non-random string used as a crypto seed) — this is crypto-auditor territory, but secret detector's entropy gate will catch "CHANGE_ME_PLEASE" style values that slipped through. Hand off with context.

### Overlap with concern #6 — Supply chain hardening

- **Leaked maintainer tokens** are catastrophic at the supply-chain level. An exposed `npm_` token in a contributor's dotfile → attacker publishes a trojan version of the package → downstream users pwned. Secret detector flags the token; supply-chain auditor needs to know it existed because **the blast radius is not bounded by this repo**.
- Specifically: if `NPM_AUTH_TOKEN`, `PYPI_API_TOKEN`, `DOCKERHUB_PAT` patterns hit, emit a **cross-concern beacon** (Pattern #12 event): *"publisher credential leak — rotate immediately, check package registry audit logs for unauthorized publishes."* This is higher urgency than a leaked OpenAI key because the blast radius includes every user of every package you publish.
- **CI/CD secret leakage** — GitHub Actions tokens (`ghs_`), deploy tokens in `.github/workflows/*.yml`, Dockerfile `ARG`/`ENV` secrets. The intersection of CI config and secret detection. Belongs to secret detector with a companion supply-chain narrative.

### Overlap with concern #9 — Threat model generation

Every secret finding feeds the threat model. A leaked AWS key is not just a finding — it's an *attacker capability*. The STRIDE threat model that `/vibe-sec:threat-model` generates should:
- Enumerate detected secrets in the "Spoofing" + "Elevation of Privilege" columns.
- Calculate effective blast radius given the IAM policy attached to the exposed credential (stretch goal — needs IAM simulator; v0.3+).
- Propose compensating controls: rate limits, anomaly detection, GuardDuty, canary tokens.

### Overlap with concern #7 — Rate limiting / abuse protection

Not a direct dependency, but the narrative matters: *"when (not if) a secret leaks, rate limiting and anomaly detection are the containment layer."* SECURITY.md handoff should include this framing. Secret detection finds the leak *before* it ships; rate limiting contains the damage *after* a leak (via a different vector — stolen credentials, compromised collaborator, misconfigured CI) inevitably happens.

---

## Open questions for synthesis

Genuine judgment calls Este needs to resolve at `/spec` time. These are the conflicts the synthesis agent can't auto-resolve.

1. **Verification: opt-in via flag, or build toward it as v0.3 default?** Trufflehog's industry-standard model is "always verify, cut FP to near-zero at cost of network calls + rate limits." Vibe Sec's no-account principle pushes against this. Recommendation: opt-in flag in v0.2, promote to default in v0.3 for the top-5 providers (AWS/GitHub/OpenAI/Anthropic/Stripe) where verification endpoints are free and reliable. But this is a philosophy call Este owns.

2. **Git history scan depth default.** Scope currently ambiguous: `/vibe-sec:scan` could default to `--recent` (fast, misses old leaks) or `--full` (slow, catches everything). Per the 2026 GitGuardian data — 64% of 4-year-old leaks are still valid — "old" is the wrong frame. **Recommendation: default to `--full` with caching, not `--recent`.** First scan is slow; subsequent incremental scans are fast. But this trades off against the "under 2 minutes first-run" north-star metric. Worth an explicit ruling.

3. **AST-aware vs. regex-only for v0.2.** AST-aware detection is meaningfully better for JS/TS but requires a parser dependency (`@babel/parser` or similar). Adds ~2MB to the plugin. Worth it? My read: **yes**, because the "vibe-coded apps are mostly JS/TS" scope focus means AST coverage is the differentiator. But this is a complexity-budget call.

4. **Detection of base64-encoded secrets (one level deep).** Betterleaks added doubly/triply-encoded detection in 2026. Common in copy-pasted Docker configs, Kubernetes secrets YAMLs. Worth adding a one-level base64 decode + re-scan pass? Cost: 2x scan time on candidate strings. Benefit: catches the most common obfuscation layer. **Recommendation: yes, but only for candidate strings already flagged as high-entropy. Don't base64-decode everything.**

5. **"Publisher credential" beacon vs. just-a-finding.** The blast-radius argument for `npm_`/`pypi-`/`dckr_pat_` tokens being cross-concern beacons is strong. But introducing a cross-concern Pattern #12 event on a single pattern-hit is mechanism creep. Does the synthesis agent earn that wire-in, or is it a v0.3 feature?

6. **Client-bundle scan — secret detector or config-posture detector?** A secret in `dist/app.xxxxx.js` is a secret-detection finding at face value, but the *cause* is config posture (wrong env-var prefix, wrong build-time injection). Single finding with dual framing, or two findings that reference each other? UX call.

7. **Suppression portability across projects.** Level-2 self-evolution can learn "this builder consistently ignores `GENERIC_SECRET_ASSIGN` findings in files matching `*.test.*`." Propagate that to the builder profile as a global default? Or keep suppressions strictly per-project (safer, more annoying)? Recommendation: ask once after N repetitions, then global.

8. **Severity calibration for Firebase web `apiKey`.** By Firebase's design, this key is public. But *most* builders don't know that, and treating it as "high severity — leaked Google API key" creates cry-wolf. Our classification call: `FIREBASE_WEB_CLIENT_API_KEY = informational` + companion finding on security rules. Does this framing match what the builder expects, or does it under-alert? Worth a read from a Firebase-heavy project during WSYATM dogfood.

9. **GitHub Secret Scanning parallelism — compete or defer?** For public repos, GitHub's scanner runs for free in parallel with Vibe Sec's. We shouldn't duplicate their banner-spam. Options: (a) skip Vibe Sec's scan on providers GitHub already covers for public repos; (b) run both, credit GitHub, note "this would have been caught at push time if you'd enabled push protection." **Recommendation: (b).** Educational framing beats suppression.

10. **Honeytoken generation — in scope or not?** Vibe Sec could *generate* a Canarytoken and plant it in the user's repo as a tripwire. High-value feature. But it introduces an operational dependency (canarytokens.org or self-hosted Thinkst), and the planted token must never be rotated-out. This is a `/vibe-sec:harden` command in v0.3+ territory, not v0.2. Calling it out so synthesis doesn't accidentally scope it in.

---

*End of brief. Feeds `docs/research/synthesis.md`. Re-runnable via `/vibe-sec:research --concern secret-detection` when provider catalogs shift or new incident patterns emerge.*

## Sources

- [Why 28 million credentials leaked on GitHub in 2025 — Snyk](https://snyk.io/articles/state-of-secrets/)
- [29 million leaked secrets in 2025: AI agents credentials out of control — Help Net Security](https://www.helpnetsecurity.com/2026/04/14/gitguardian-ai-agents-credentials-leak/)
- [The State of Secrets Sprawl 2026 — Security Boulevard](https://securityboulevard.com/2026/03/the-state-of-secrets-sprawl-2026-ai-service-leaks-surge-81-and-29m-secrets-hit-public-github/)
- [Exposed Developer Secrets Surge: AI Drives 34% Increase in 2025 — Security Ledger](https://securityledger.com/2026/03/exposed-developer-secrets-surge-ai-drives-34-increase-in-2025/)
- [GitHub is awash with leaked AI company secrets — IT Pro](https://www.itpro.com/security/github-is-awash-with-leaked-ai-company-secrets-api-keys-tokens-and-credentials-were-all-found-out-in-the-open)
- [Installing and Configuring Gitleaks — Gitleaks](https://gitleaks.org/installing-and-configuring-gitleaks-complete-setup-guide-for-secure-secret-scanning/)
- [Betterleaks — open-source secrets scanner for the agentic era (The New Stack)](https://thenewstack.io/betterleaks-open-source-secret-scanner/)
- [TruffleHog — GitHub](https://github.com/trufflesecurity/trufflehog)
- [How TruffleHog Verifies Secrets — Truffle Security](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets)
- [TruffleHog Detectors catalog](https://trufflesecurity.com/detectors)
- [Introducing TruffleHog v3 — Truffle Security](https://trufflesecurity.com/blog/introducing-trufflehog-v3)
- [detect-secrets — Yelp on GitHub](https://github.com/Yelp/detect-secrets)
- [detect-secrets design doc (entropy thresholds)](https://github.com/Yelp/detect-secrets/blob/master/docs/design.md)
- [About push protection — GitHub Docs](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- [GitHub secret scanning coverage update March 2026 — GitHub Changelog](https://github.blog/changelog/2026-03-31-github-secret-scanning-nine-new-types-and-more/)
- [Supported secret scanning patterns — GitHub Docs](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns)
- [GitHub Advanced Security license billing — GitHub Docs](https://docs.github.com/en/billing/concepts/product-billing/github-advanced-security)
- [git-filter-repo — GitHub](https://github.com/newren/git-filter-repo)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [OpenAI regex pattern — gitleaks PR #1780](https://github.com/gitleaks/gitleaks/pull/1780)
- [Secrets Story: The Prefixed Secrets — Semgrep blog](https://semgrep.dev/blog/2025/secrets-story-and-prefixed-secrets/)
- [secret-regex-list — h33tlit](https://github.com/h33tlit/secret-regex-list)
- [Introducing the AWS Infrastructure Canarytoken — Thinkst](https://blog.thinkst.com/2025/09/introducing-the-aws-infrastructure-canarytoken.html)
- [Canarytokens](https://www.canarytokens.org/)
- [GuardDuty uncovers cryptomining campaign using compromised IAM credentials — AWS Security Blog](https://aws.amazon.com/blogs/security/cryptomining-campaign-targeting-amazon-ec2-and-amazon-ecs/)
- [Honeytokens as a Defense Against Supply Chain Attacks — UpGuard](https://www.upguard.com/blog/prevent-supply-chain-attacks-with-honeytokens)
- [Rewriting a Git repo to remove secrets from history — Simon Willison](https://til.simonwillison.net/git/rewrite-repo-remove-secrets)
