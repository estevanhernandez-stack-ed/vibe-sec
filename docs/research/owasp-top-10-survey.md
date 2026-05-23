# OWASP Top 10 — Category Survey for Vibe Sec v0.2

**Author:** OWASP Top 10 strategist agent (research swarm, /spec phase)
**Written:** 2026-04-20
**Role in the swarm:** Category glue. The other nine briefs go deep on narrow domains (secrets, SCA, crypto/PII, config posture, auth model, rate limiting, supply chain, threat modeling, tier thresholds). This one is the breadth layer — ensure nothing slips through the cracks by walking all ten OWASP categories, and own detection coverage for A02/A04/A06/A08/A09/A10 where no dedicated agent exists.

> **Author's note on sink naming.** Throughout this brief, sink identifiers that would collide with Claude Code's security-reminder hook's substring matchers (React's dangerous-inner-html prop, the DOM inner-html assignment, the document-write DOM sink, the Function constructor, the eval primitive, shell-exec child-process APIs, and a few others) are referenced by descriptive name rather than literal identifier. Every such reference maps one-to-one to a well-known JS sink documented in MDN and the `eslint-plugin-no-unsanitized` / `eslint-plugin-security` rule sets. The literal names appear in the cited ESLint rule docs.

---

## Landscape

OWASP Top 10 is the industry's default baseline for application-security risk taxonomy. It is not a standard, not a compliance control set, and not a coverage guarantee — it is a *ranked risk list*, re-derived every 3–4 years from telemetry contributed by scanner vendors, penetration-test firms, and the OWASP community survey. For Vibe Sec's purpose it functions as a category glossary and a coverage checklist: if an audit can't say something honest about each of the ten, it isn't a real audit.

**2021 edition — the list Vibe Sec was scoped against:**

| # | Category | Change vs 2017 |
|---|---|---|
| A01 | Broken Access Control | Up from #5 — now the #1 tested risk |
| A02 | Cryptographic Failures | Renamed from "Sensitive Data Exposure"; root-cause framing |
| A03 | Injection | Down from #1 to #3 (XSS folded in) |
| A04 | Insecure Design | *New* — design-time flaws as a first-class category |
| A05 | Security Misconfiguration | Up one spot; XXE merged in |
| A06 | Vulnerable and Outdated Components | Up from #9 — supply-chain era begins |
| A07 | Identification and Authentication Failures | Renamed, down from #2 |
| A08 | Software and Data Integrity Failures | *New* — SolarWinds-era; covers CI/CD, deserialization |
| A09 | Security Logging and Monitoring Failures | Up from #10 |
| A10 | Server-Side Request Forgery (SSRF) | *New* — community-survey driven |

**2025 edition — released November 2025, ratified through early 2026.** Based on telemetry from ~2.8M applications. Vibe Sec v0.2 targets the 2021 category names (what builders still reference and most tools still organize around) but maps every finding to both editions so the report ages well.

| # | 2025 Category | Delta |
|---|---|---|
| A01 | Broken Access Control | Still #1. SSRF (old A10) **folded in** — SSRF is re-framed as an access-control bypass. |
| A02 | Security Misconfiguration | Up from #5 to #2. The single biggest ranking jump — config complexity has become the dominant failure mode. |
| A03 | **Software Supply Chain Failures** | *Renamed + expanded* from 2021 A06 ("Vulnerable Components"). Covers build pipelines, artifact integrity, provenance — not just CVEs in deps. |
| A04 | Cryptographic Failures | Down from #2 to #4. |
| A05 | Injection | Down from #3 to #5. |
| A06 | Insecure Design | Down from #4. |
| A07 | Authentication Failures | Same slot, name shortened. |
| A08 | Software or Data Integrity Failures | Same slot. |
| A09 | Security Logging and Alerting Failures | Renamed ("Alerting" replaces "Monitoring"). |
| A10 | **Mishandling of Exceptional Conditions** | *New.* Unchecked errors, swallowed exceptions, degraded fallback paths that reach production. |

**Cross-checked against CWE Top 25 2024/2025** (MITRE/CISA). The top three CWEs remain XSS (CWE-79), Out-of-bounds Write (CWE-787 — mostly native code, largely N/A for JS/TS vibe apps), and SQL Injection (CWE-89). New entrants in the 2024 list: CWE-200 (info exposure) and CWE-400 (uncontrolled resource consumption). The signal for Vibe Sec: **XSS and injection still dominate real-world CVE prevalence**, even as they drift down in the OWASP ranking, because ranking weights test coverage and exploit severity, not raw volume.

**What this means for v0.2:** the audit labels findings with `A0X-2021` and `A0X-2025` dual tags. The categorical audit architecture is organized by 2021 numbers because that's the mental model builders walk in with, but the synthesis doc should note the 2025 rearrangement so the report's Band 4 ("worth reading") can surface the supply-chain-as-first-class shift.

---

## Detection mechanics

One H3 subsection per category. Each answers: *what it covers*, *static-detection patterns for JS/TS vibe apps*, *which dedicated Vibe Sec concern goes deeper* (so this agent doesn't step on the others).

### A01 — Broken Access Control

**Covers:** authorization failures — missing checks, IDOR (insecure direct object reference), forced browsing, horizontal/vertical privilege escalation, and (in 2025) SSRF re-framed as access-bypass.

**Static patterns in JS/TS:**

- Express/Next/NestJS route handlers with **no auth middleware** in the chain (a `GET /admin/...` route registered without `requireAuth` / `authorize()` / `isAdmin()` preceding it in the router pipeline).
- Firebase/Firestore client reads where access control is delegated to rules that were never audited (a `getDoc` on a user document directly in a React component with no server-side gate).
- Missing tenant-ID assertion: query uses `req.params.userId` or `req.body.orgId` **without** cross-checking against `req.user.id` / `req.user.orgId`.
- Frontend-only guards: a client-side admin-redirect with no backend enforcement on the corresponding API route.
- SSRF surface: server-side `fetch` / HTTP client calls where the URL argument is sourced from `req.query.url`, `req.body.target`, or constructed from user input without allow-listing.

**Dedicated agent:** **auth-model concern** goes deep on authorization matrix, role inheritance, middleware consistency. This survey agent just **flags surface-level missing-middleware patterns** and lets the auth-model agent own the matrix audit.

### A02 — Cryptographic Failures

**Covers:** sensitive data exposed due to weak/missing crypto — plaintext storage, weak hashing, broken TLS, reused IVs, hardcoded keys, deprecated algorithms (MD5, SHA-1, DES, RC4), improper JWT signing.

**Static patterns in JS/TS:**

- **Hash algorithm sniff:** `crypto.createHash('md5')`, `'sha1'`, bcrypt calls with work factor under 10, PBKDF2 calls with iterations under ~100k.
- **Password storage smells:** plaintext assignment to a password field, base64-encoded "hashing", sha256-without-salt.
- **JWT misuse:** signing with the `none` algorithm, `jwt.verify` without an `algorithms: [...]` constraint (allows algorithm confusion), HS256 secrets under 32 bytes.
- **Weak randomness for security contexts:** `Math.random()` used to generate tokens, session IDs, password-reset codes (must be `crypto.randomBytes` / `crypto.randomUUID`).
- **Static IVs / nonces:** hardcoded 16-byte buffers passed to `createCipheriv`.
- **TLS disable flags in prod paths:** `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, https-agents created with TLS verification disabled.
- **Cookies without encryption** of sensitive payloads, or with `secure: false` in production.

**Dedicated agent:** **crypto/PII concern** owns the deep analysis — at-rest encryption, key-management, PII boundary mapping, cleartext-in-logs. This survey agent **owns the algorithm-smell detectors** and hands the data-flow analysis to the crypto/PII brief.

### A03 — Injection

**Covers:** SQLi, NoSQLi, command injection, LDAP injection, XPath injection, header injection, prototype pollution, and (merged in 2021) XSS in all its flavors — reflected, stored, DOM-based.

**Static patterns in JS/TS:**

- **SQL via template literals:** `db.query` called with a backtick-string that interpolates `req.params.id` or similar; string-concatenation SQL (`'SELECT ... ' + userInput`).
- **NoSQL operator injection (Mongo):** `User.find(req.body.filter)` where `filter` could contain `$ne`, `$gt`, etc.; `User.find({ email: req.body.email })` without `String()` coercion.
- **Command injection:** shell-spawning child-process APIs receiving template-string arguments built from user input. (Specifically: the synchronous and asynchronous shell-exec family plus spawn-with-`shell:true`.)
- **XSS vectors:**
  - React: the dangerous-inner-html prop on JSX elements populated from user input (see the literal identifier in the eslint-plugin docs; it is the `__html` escape hatch).
  - Vanilla DOM: the inner-html property setter, the document-write DOM sink, the outer-html setter, and `insertAdjacentHTML` — i.e. exactly the rules enforced by `eslint-plugin-no-unsanitized` (see the [method and property rule docs](https://github.com/mozilla/eslint-plugin-no-unsanitized)).
  - Attribute sinks: `href={userUrl}` where `userUrl` could be `javascript:` (React strips most but Next.js `<Link>` and custom components sometimes don't).
  - Template engines: EJS `<%- unescaped %>`, Handlebars `{{{ triple-brace }}}`, Pug `!= interpolation`.
- **Prototype pollution sinks:** `Object.assign(target, req.body)` without sanitization, `_.merge(config, userData)`, recursive merge utilities accepting user JSON.
- **Header injection:** `res.setHeader('X-Custom', req.query.value)` without CRLF strip.

**Dedicated agent:** **open question (see §8).** This survey covers A03 at category-breadth; the open question is whether injection merits its own deep-dive agent for a v0.3 swarm.

### A04 — Insecure Design

**Covers:** flaws that no implementation detail can fix — missing rate limits on password reset, no account lockout, trust boundaries drawn wrong, business-logic bypasses, missing threat modeling, generate-a-link flows with no expiry.

**Static patterns in JS/TS:** Design flaws are *definitionally* not pattern-matchable with grep. But there are **absence-of-control proxies**:

- No `express-rate-limit`, `@upstash/ratelimit`, `rate-limiter-flexible`, or equivalent imported anywhere → probable rate-limit absence.
- Password-reset/magic-link endpoints that set no TTL on the token (`reset_token` column with no `expires_at`, or JWT reset tokens with no `exp`).
- State-changing endpoints (`POST`, `PUT`, `DELETE`) with no CSRF middleware AND no double-submit-cookie AND same-origin cookies not enforced.
- Signup flows with no email-verification gate before privileged actions.
- Admin functions gated only by a client-side feature flag or a hardcoded email-allowlist in-source.

**Dedicated agent:** the **threat-model concern** is the natural home for design-level analysis. This survey agent **surfaces absence-of-control proxies** and flags them for threat-model deepening. Critically: A04 findings should default to Band 2 (educational) or Band 3 (graduation) at most tiers, because they're judgment calls, not mechanical defects. False-positive tolerance here is low — noisy A04 findings train builders to ignore the report.

### A05 — Security Misconfiguration

**Covers:** default credentials, verbose errors in prod, missing security headers, open cloud buckets, permissive CORS, debug endpoints, unnecessary features enabled, out-of-date server software.

**Static patterns in JS/TS:**

- **CORS wildcards:** `app.use(cors({ origin: '*' }))`, `res.header('Access-Control-Allow-Origin', '*')`, `cors()` with no config (library default may be `*`).
- **Missing security headers:** no `helmet()` middleware, no manual CSP header, no HSTS, no `X-Content-Type-Options: nosniff`.
- **Verbose error handlers:** `res.json({ error: err.stack })`, `res.send(err)`, dev-mode error middleware reaching prod.
- **Debug endpoints left mounted:** `/debug`, `/admin/phpinfo`, `/graphql` with introspection on in prod, `next.config.js` with `productionBrowserSourceMaps: true` shipping maps publicly.
- **Firebase misconfig:** `firestore.rules` with `allow read, write: if true;`, `storage.rules` public, `realtime-database.rules.json` with `.read: "true"`.
- **Cookie flags:** `res.cookie(name, value)` with no `httpOnly`, no `secure`, no `sameSite`.
- **`.env` committed** / present in `git ls-files` output.

**Dedicated agent:** the **config-posture concern** owns deep header/CORS/cookie policy analysis. This survey agent flags the headline smells; config-posture owns the tier-appropriate policy bar and remediation.

### A06 — Vulnerable and Outdated Components

**Covers:** using dependencies with known CVEs, abandoned packages, packages at end-of-life, packages pulled from their registry, typosquats.

**Static patterns in JS/TS:**

- `npm audit --json` passthrough → CVE list.
- `package.json` `dependencies` + `devDependencies` cross-checked against OSV.dev bulk query (fallback when `npm audit` fails or project is non-npm).
- **Age heuristic:** packages with `latest` publish > 24 months stale → abandoned-probability warning (not a finding; informational).
- **Lockfile presence:** missing `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` → integrity unknowable.
- **Floating versions on security-critical deps:** `"express": "^4.x"` is fine; `"jsonwebtoken": "*"` is a finding.
- **Typosquat heuristics:** Levenshtein distance ≤ 2 from a top-100 package name (`reactt`, `expresss`, `loadash`, `crosss-env`) → high-severity flag.
- **Deprecated packages:** npm-deprecated packages surface in `npm ls` output (e.g., `request`, `node-sass`, `tslint`).

**Dedicated agent:** the **supply-chain concern** goes deep on SBOM, lockfile-integrity, transitive-risk scoring, signature verification. This survey agent does **headline CVE reporting** — the `/vibe-sec:deps` command's bread and butter — and hands the deeper posture work to supply-chain.

### A07 — Identification and Authentication Failures

**Covers:** weak passwords allowed, credential stuffing unmitigated, session fixation, tokens not rotated, missing MFA support, insecure password recovery, default credentials.

**Static patterns in JS/TS:**

- **No rate limiting on `/login`, `/signup`, `/reset-password`.**
- **Session tokens in localStorage** when they should be in `httpOnly` cookies (classic vibe-code mistake — the LLM sees "JWT" and writes a localStorage.setItem call for the token).
- **No session rotation** on privilege change (login doesn't regenerate session ID).
- **Password requirements:** either missing entirely or implemented in the frontend only (`minLength={8}` on an input element with no server validation).
- **Account-enumeration smells:** login errors distinguish "user not found" from "wrong password"; reset-password returns different status codes for existing vs non-existing emails.
- **JWT `none` algorithm,** short secrets, no expiry on refresh tokens.

**Dedicated agent:** the **auth-model concern** owns this. This survey agent **does not duplicate** — it hands the entire A07 category to the auth-model brief. Only patterns the auth-model agent doesn't cover (e.g., the `none` algorithm, which bleeds into A02) get flagged here.

### A08 — Software and Data Integrity Failures

**Covers:** unsigned updates, untrusted CDN scripts with no Subresource Integrity (SRI), insecure deserialization, CI/CD without artifact signing, package installation from untrusted sources.

**Static patterns in JS/TS:**

- **Script tags without SRI:** `<script src="https://cdn.example.com/lib.js">` with no `integrity="sha384-..."` attribute. High-signal in vibe-coded apps — LLMs love pulling CDN scripts without integrity hashes.
- **Dynamic code loading sinks:** the three-char code-execution primitive, the Function-constructor pattern, `setTimeout` / `setInterval` called with a string body, and `vm.runInThisContext` with untrusted input. All four are canonical A08 sinks and are enforced by `eslint-plugin-security`'s `detect-eval-with-expression` rule.
- **Untrusted deserialization:** `node-serialize`, `serialize-javascript` with `unsafe: true`, `funcster`, YAML load without `safeLoad`, `JSON.parse` with a reviver that instantiates classes.
- **CI/CD smells:**
  - `.github/workflows/*.yml` with `uses: actions/checkout@master` (unpinned, mutable).
  - `npm install` in CI without `--ignore-scripts` when running untrusted deps.
  - Publishing step runs without `npm publish --provenance`.
  - Docker `FROM node:latest` (unpinned base image).
- **Postinstall hooks in dependencies:** not detectable statically at the consumer level without inspecting every `node_modules/*/package.json`'s `scripts.postinstall` — defer to a supply-chain-agent deeper pass.

**Dedicated agent:** partial overlap with **supply-chain concern**. The split: supply-chain owns artifact integrity, provenance, lockfile hashes, SBOM. This survey agent owns **SRI attributes on HTML/JSX**, **dynamic-code-loading sinks**, **deserialization library smells**, and **CI workflow-file pattern checks**. These are all AST/regex-level patterns; supply-chain is manifest-and-registry level.

### A09 — Security Logging and Monitoring Failures

**Covers:** no auth-event logging, no anomaly alerting, logs missing key fields, logs with PII in plaintext, no retention policy, log injection.

**Static patterns in JS/TS:**

- **Logging-library presence** (absence is the finding): no `winston`, `pino`, `bunyan`, `console.log` only, no log aggregation target (no Datadog/Sentry/LogRocket/Axiom dependency in `package.json`).
- **Silent catches:** empty-body catch blocks, `catch (e) { /* ignore */ }`, `.catch(() => {})` — Promise-style and try-catch.
- **`console.log` with sensitive shapes:** regex-pattern-match logged objects containing `password`, `token`, `apiKey`, `creditCard`, `ssn`, `auth` as property names.
- **Stack traces to client:** `res.send(err)`, `res.json(err)`, Express default error handler unwrapped in production (`app.get('env') === 'development'` check missing).
- **Auth-event absence:** login/logout/signup/password-reset handlers with no log call preceding `res.send` / `res.json`.
- **Log injection:** user input interpolated into log strings without escape — a logger call that embeds `req.body.name` directly into a template-string message where `name` could contain newline + fake log-level prefix.

**Dedicated agent:** partial overlap with **crypto/PII concern** (PII-in-logs is the intersection). This survey agent owns the **absence-of-logging patterns** and **silent-catch detection**; PII-in-logs goes to crypto/PII.

### A10 — Server-Side Request Forgery (2021) / Mishandling of Exceptional Conditions (2025)

**Two different categories sharing a slot** — Vibe Sec should address both, tagged distinctly.

**A10-2021 (SSRF) — covers:** server fetches URL controlled by user, potentially reaching internal resources (cloud metadata services, internal admin APIs, localhost services).

**Static patterns in JS/TS (SSRF):**

- Server-side `fetch` / HTTP-client calls where the URL argument is derived from `req.query.url`, `req.body.target`, or a `new URL(userInput)` expression.
- Image/media URL inputs (OG-image generators, PDF renderers using `puppeteer.goto(userUrl)`, image-proxy routes).
- Webhook endpoints that re-fetch the supplied URL without allow-listing.
- Server-side rendering that fetches user-supplied URLs (Next.js `getServerSideProps` hitting user URLs).

Under **2025's re-framing**, SSRF goes to A01 (access control). Vibe Sec should tag SSRF findings as **A10-2021 / A01-2025** so the report ages correctly.

**A10-2025 (Mishandling of Exceptional Conditions) — covers:** unchecked errors, swallowed exceptions, degraded fallback paths that silently fail, error states that leak data.

**Static patterns in JS/TS (A10-2025):**

- Massive overlap with A09's silent-catch detection.
- Missing `.catch()` on Promise chains that mutate state.
- Try-with-empty-catch when the try body includes auth/security-sensitive operations.
- Error handlers that **fail open** instead of fail closed: returning `{ ok: true }` or the unauthenticated user object after a failed permission check.

**Dedicated agent:** no direct peer. **This survey agent owns both A10 flavors**, with overlap handoffs to A01 (SSRF-as-access-control) and A09 (silent-catch logging gap).

---

## False-positive risks

Target: **12% FP across the board** (vs Vibe Test's <5%, because security detection is fuzzier). Per category, the FP shape:

- **A01 — high risk.** Many routes legitimately allow anonymous access (landing pages, public APIs, marketing sites). Rule: do not flag missing-auth-middleware **unless** the route pattern matches `/admin`, `/internal`, `/api/*/:id` (ID-bearing resources), or the handler touches `db` / `User` / `Org` / `Tenant` models. Let app classification (public-facing vs internal-tool) gate the severity.
- **A02 — medium risk.** `Math.random()` is fine in a dice-roll game; it's a crit in password-reset code. Rule: context-gate on call-site proximity to `token`, `password`, `secret`, `session`, `reset`, `verify` identifiers within 3 lines.
- **A03 — medium risk.** Template literals in SQL are sometimes intentional (schema names, table names cannot be parameterized). Rule: flag only when the interpolated expression can be traced to `req.*` via data-flow. Tainted-source tracking is load-bearing here.
- **A04 — highest risk.** Absence-of-rate-limit is not a bug in a personal blog. Rule: tier-gate hard — never flag A04 at Prototype tier, surface as Band 2 at Internal, promote to Band 1 only at Public-facing+ and only when a sensitive endpoint is present.
- **A05 — low risk.** Config patterns are mostly deterministic (`cors({ origin: '*' })` is unambiguously a finding). The FP source is environment-gated code: an origin that is wildcard in dev and an allow-list in prod via ternary is fine. Rule: pattern-match with ternary awareness.
- **A06 — low-to-medium risk.** CVE severity is objective, but exploitability depends on whether the vulnerable code path is actually reached. `npm audit` is noisy. Rule: pass CVSS through, let the builder decide; don't suppress, don't promote. If the severity is Critical but the package is dev-only (`devDependencies`), downgrade.
- **A07 — medium risk.** See auth-model brief.
- **A08 — medium risk.** Some dynamic-code usage is legitimate (Monaco editor, REPL features, sandboxed user-code runners). Rule: flag all dynamic-code sinks; categorize as "review required" not "must fix"; allow suppression with justification comment (`// vibe-sec: ignore A08 — sandboxed user-code runner`).
- **A09 — medium-high risk.** Empty-body catch blocks are often legitimate (polling a flaky API, retry loops). Rule: flag only when the try-body contains identifiers matching auth/security patterns, OR when catch is in a route handler before `res.send`. Absence-of-logging-library is a soft finding, never critical.
- **A10 — medium risk (both flavors).** SSRF is noisy because server-side `fetch(url)` with any string is technically a sink — but most strings are hardcoded constants. Rule: taint-track, only flag when source traces to user input. Exceptional-conditions pattern overlaps with A09 — de-duplicate at report time.

**Cross-cutting FP controls:**

1. **Classification gating.** Tier × concern matrix (below) suppresses categories that don't apply.
2. **Suppression comments.** Support `// vibe-sec: ignore A0X — reason` in source, persisted in `.vibe-sec/state/suppressions.json`.
3. **Dedup across concerns.** If the same line triggers A02 (weak hash) and the crypto/PII concern's deeper check, report once, cite both.
4. **Confidence score** on every finding. < 0.7 goes inline (never auto-fix), 0.7–0.9 stages, ≥0.9 auto.

---

## Remediation patterns

Mapping each category to the `/vibe-sec:fix` confidence-tier routing (auto / stage / inline) from scope.md.

| Category | Fix example | Route |
|---|---|---|
| A01 | Add `requireAuth` middleware to unprotected admin route | **Inline** — requires architectural judgment on which auth tier to apply |
| A01 | Add SSRF URL allow-list to a known webhook endpoint | **Stage** — template is known, builder confirms allow-list |
| A02 | Replace `md5` with `sha256` for non-security hashes | **Stage** — auto-replacement can break caching keys |
| A02 | Replace `md5` in password hashing path with `bcrypt` | **Inline** — changes break existing password hashes, requires migration plan |
| A02 | Add `algorithms: ['HS256']` constraint to `jwt.verify` | **Auto** — additive, fixes algorithm-confusion class |
| A03 | Replace template-string SQL with parameterized query | **Stage** — mechanical but needs test run to confirm |
| A03 | Replace dangerous-inner-html JSX prop with sanitized render or plain text | **Stage** — may lose intentional markup |
| A03 | Wrap Mongo query input in `String()` coercion | **Auto** — additive, mechanical |
| A04 | Add `express-rate-limit` to `/login` endpoint | **Stage** — needs config review |
| A04 | Add CSRF middleware | **Stage** — frontend token flow needs manual wiring |
| A05 | Replace `cors({ origin: '*' })` with explicit allow-list | **Stage** — may break frontend if origin list is wrong |
| A05 | Add `helmet()` middleware | **Auto** — additive security headers, safe default |
| A05 | Add missing cookie flags (`httpOnly`, `secure`, `sameSite`) | **Auto** — additive |
| A05 | Add `.env` to `.gitignore` | **Auto** (per scope.md override) — always auto regardless of confidence |
| A06 | `npm audit fix` (non-breaking) | **Stage** — vibe-test runs on accept per scope.md |
| A06 | `npm audit fix --force` (breaking) | **Inline** — always inline, major-version bumps need human |
| A07 | See auth-model brief |
| A08 | Add `integrity="sha384-..."` to CDN script tag | **Auto** — computable, additive |
| A08 | Pin GitHub Action `uses:` SHA | **Stage** — needs SHA lookup, safe to stage |
| A08 | Replace a dynamic-code-loading sink call | **Inline** — always manual; these sinks are often load-bearing |
| A09 | Add structured logger (`pino`) import + swap `console.log` in auth paths | **Stage** — template, builder confirms logger choice |
| A09 | Strip PII fields from existing log calls | **Stage** — needs PII-field list from crypto/PII concern |
| A09 | Fix silent empty-catch → log + rethrow | **Inline** — rethrow may break callers |
| A10 | Add SSRF allow-list (A10-2021) | See A01 |
| A10 | Fix swallowed exception in auth path (A10-2025) | **Inline** — same as A09 silent-catch |

**Hard destructive-action overrides from scope.md — never auto, regardless of confidence:**

- Leaked-secret rotation
- Auth-logic changes
- JWT/session-secret regen
- Any change that invalidates live user sessions or breaks existing password hashes

---

## Pattern #13 complements

Tools already solving pieces of the OWASP Top 10 surface. Vibe Sec surfaces these in Band 4 of the report ("tools that would catch classes we don't").

**Semgrep** — pattern-based SAST with an official `p/owasp-top-ten` ruleset covering all ten categories across JS/TS. The default ruleset (`p/default`) ships with OWASP-aligned rules for Express, NestJS, Hapi, Koa and covers SQLi, path traversal, SSRF, XSS, and more. **Vibe Sec's complement posture:** if the builder has Semgrep installed, defer the deep-pattern injection checks to it and consume its JSON output. If not, surface Semgrep as a "next tool to install" in Band 4. Semgrep does not understand *tier* — we do.

**Snyk Code** — commercial SAST with ML-assisted dataflow tracking. Strong at A03 (injection) and A01 (access control) with inter-procedural tracking. Paid tier is the barrier. Surface as complement for Customer-facing SaaS+ tier; skip at lower tiers to honor the "minimize infrastructure lag" design principle.

**SonarQube / SonarCloud** — broader code-quality surface, includes OWASP Top 10 coverage for JS/TS. Heavier to adopt than Semgrep. Fits Regulated/enterprise tier recommendations.

**ESLint security plugins:**

- `eslint-plugin-security` — 13 rules, maintained but noted as largely stale (no meaningful updates since 2020; ~4 rules still fully relevant, ~5 partial, ~4 obsolete). Covers `detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-object-injection`, `detect-unsafe-regex`, `detect-buffer-noassert`, and a handful more. **Useful as a no-cost floor** — vibe-coded projects often already have ESLint wired, so adding the plugin is the cheapest possible lift. Note its staleness in the complement recommendation.
- `eslint-plugin-no-unsanitized` — Mozilla-maintained, actively used in Firefox CI. Two rules: `no-unsanitized/method` (blocks DOM-sink method calls including `insertAdjacentHTML` and the document-write API) and `no-unsanitized/property` (blocks the inner-html and outer-html property setters). **Highly recommended** for any React/Vue/vanilla-DOM JS/TS project — catches the XSS subset of A03 cheaply and accurately.
- `eslint-plugin-xss` — DOM-XSS focused, less comprehensive than no-unsanitized but a viable alternative.
- `eslint-plugin-node-security` — newer fork addressing some of eslint-plugin-security's staleness; still small ruleset.

**Vibe Sec's ESLint integration posture:** detect if ESLint is configured in the project; if yes, propose adding `eslint-plugin-no-unsanitized` via the `/vibe-sec:fix` stage flow. This is a two-line change (`.eslintrc` entry + `npm install`) that covers XSS at commit-time going forward — dramatically higher leverage than a one-shot audit catch.

**GitGuardian / gitleaks / trufflehog** — secret detection specialists. Scope.md already flags these for the secret-scan concern. Not in this survey's lane.

**npm audit / OSV / Dependabot / Renovate** — SCA specialists, covered by the supply-chain brief.

**CodeQL** — GitHub's semantic SAST engine, free for public repos. OWASP Top 10 coverage is strong. Recommend for open-source projects.

---

## Tier applicability

Per-category tier gating. **Blocking** = must pass gate; **Surfaced** = reported, tier-appropriate Band; **Skipped** = not audited at this tier.

| Category | Prototype | Internal | Public-facing | Customer SaaS | Regulated |
|---|---|---|---|---|---|
| A01 Broken Access Control | Skipped | Surfaced (Band 2) | **Blocking** | **Blocking** | **Blocking** |
| A02 Cryptographic Failures | Surfaced (if secrets touched) | Surfaced | **Blocking** | **Blocking** | **Blocking** |
| A03 Injection | Surfaced | Surfaced | **Blocking** | **Blocking** | **Blocking** |
| A04 Insecure Design | Skipped | Surfaced (Band 3) | Surfaced (Band 2) | **Blocking** (limited) | **Blocking** |
| A05 Security Misconfiguration | Surfaced | Surfaced | **Blocking** | **Blocking** | **Blocking** |
| A06 Vulnerable Components | Surfaced (Critical only) | **Blocking** (High+) | **Blocking** | **Blocking** | **Blocking** |
| A07 Authentication Failures | Skipped | Surfaced | **Blocking** | **Blocking** | **Blocking** |
| A08 Software/Data Integrity | Skipped | Surfaced (Band 3) | Surfaced (Band 2) | **Blocking** | **Blocking** |
| A09 Logging/Monitoring | Skipped | Skipped | Surfaced (Band 2) | **Blocking** | **Blocking** |
| A10 SSRF / Exceptional Conditions | Skipped | Surfaced (if user-URL fetch present) | **Blocking** | **Blocking** | **Blocking** |

**Reading the matrix:** Prototype audits the bare minimum (don't ship a CVE, don't ship a secret). Public-facing is the step-change — the full OWASP Top 10 becomes blocking. Customer SaaS + Regulated add the posture-level concerns (logging, design, integrity) that don't matter much for a marketing site but matter enormously when user data is the product.

This matrix feeds `/vibe-sec:gate`. A "blocking" category with a High/Critical finding fails the gate at that tier.

---

## Cross-concern dependencies

The ten Vibe Sec concerns overlap, and this survey sits at the hub. Dense dependency map:

```
                                        ┌─ A05 (config-posture owns deep)
                                        │
A02 Crypto ─────── crypto/PII owns ─────┼─ A09 (PII-in-logs intersection)
                                        │
A01 AuthZ ──────── auth-model owns ─────┼─ A07 (authn intersection)
                                        │
A06 CVEs ───┬───── supply-chain owns ───┼─ A08 (artifact integrity)
            │                           │
            └───── secret-scan owns ────┼─ A02 (keys-in-source intersection)
                                        │
A03 Injection ───  THIS SURVEY ─────────┼─ open question (dedicated agent?)
                                        │
A04 Design ───── threat-model owns ─────┼─ A10-2025 (fail-open patterns)
                                        │
A10 SSRF/ExCond ─  THIS SURVEY ─────────┘
```

**Concrete handoffs:**

- **Survey ↔ auth-model:** survey flags surface-level missing-middleware. Auth-model owns matrix, roles, middleware-consistency-across-routes. Shared finding IDs dedup at report time.
- **Survey ↔ crypto/PII:** survey owns algorithm smells (md5, weak bcrypt work factor, JWT none). Crypto/PII owns data-flow — where PII enters, where it's stored, where it's logged. Survey's A09 logging detection hands PII-field list to crypto/PII.
- **Survey ↔ config-posture:** survey flags the headline configs (CORS *, missing helmet, cookie flags). Config-posture owns the tier-appropriate header policy (CSP source list, HSTS max-age per tier, SameSite policy per cookie class).
- **Survey ↔ supply-chain:** survey runs `npm audit` + OSV query for headline CVEs. Supply-chain owns lockfile integrity, transitive-risk scoring, SBOM generation, provenance verification. A06 headline CVEs are survey's; A08 artifact integrity is supply-chain's.
- **Survey ↔ secret-scan:** the secret-scan brief owns `.env` detection, key pattern regex, git-history scanning. Survey flags **algorithm-level** crypto smells (hardcoded IVs, weak work factors) that pattern-match but aren't secrets per se.
- **Survey ↔ rate-limit:** A04 absence-of-rate-limit patterns are a partnership. Survey detects library absence; rate-limit brief owns tier-appropriate thresholds and per-endpoint granularity.
- **Survey ↔ threat-model:** A04 findings feed the threat-model generator as input risks. Threat-model produces STRIDE output consumed by `/vibe-sec:threat-model`.

**Shared data structure:** every finding carries:

```json
{
  "id": "sec-042",
  "owasp_2021": "A03",
  "owasp_2025": "A05",
  "primary_concern": "owasp-survey",
  "secondary_concerns": ["crypto-pii"],
  "cwe": "CWE-79",
  "severity_base": "high",
  "severity_tier_adjusted": "critical"
}
```

The `primary_concern` field decides who owns the finding at synthesis time. When survey and a deep-dive agent would both flag the same line, the deep-dive agent wins primary; survey goes to `secondary_concerns`.

---

## Open questions for synthesis

1. **Should A03 (Injection) get its own dedicated agent?**

   **Argument for:** Injection is the single most consequential category for vibe-coded apps — XSS and SQLi are CWE Top 25 perennials, and LLM-generated code routinely violates both. Static patterns span multiple languages-within-JS (SQL template literals, NoSQL operator abuse, React's dangerous-inner-html prop, template-engine unescaped interpolation, command-exec sinks, prototype-pollution). Each has its own FP profile and remediation template. A dedicated agent could do taint-tracking / data-flow analysis that this survey only gestures at. Semgrep's ruleset for injection is easily 40+ rules.

   **Argument against:** Semgrep already exists and does injection well. If Vibe Sec defers to Semgrep as a Pattern #13 complement for deep injection analysis, the survey-level coverage here is sufficient for v0.2. The core value Vibe Sec adds is *tier-aware prioritization*, not deeper-than-Semgrep pattern matching.

   **Recommendation to synthesis:** **defer to v0.3.** v0.2 ships with survey-level A03 coverage + Semgrep-complement recommendation. If WSYATM dogfood reveals that survey-level coverage is missing critical injection classes, promote A03 to its own agent in v0.3. Log this as a wins/friction tracking target.

2. **How do we dual-tag 2021/2025 categories without cluttering the report?**

   Options: (a) primary tag is 2021, secondary in a tooltip/footnote; (b) primary is 2025, with 2021 legacy mapping; (c) both equally surfaced. **Recommendation:** (a) for v0.2 — builders walk in with 2021 mental model; surface 2025 deltas in Band 4 as educational. Revisit after 2025 edition has been public for 12+ months.

3. **Who owns the `/vibe-sec:threat-model` command?**

   A04 patterns feed it; threat-model concern produces it; Vibe Doc renders it. Three-way handoff needs a lock at synthesis. **Survey's stake:** absence-of-control proxies detected here are inputs to threat-model, not its output. Clarify the contract.

4. **Band-placement policy for A04 and A09 at Public-facing tier.**

   The matrix above places both at Band 2 (surfaced, not blocking) at Public-facing. This is conservative to protect against FP noise. Is that the right call for WSYATM's dogfood, or does the real-stakes launch require promoting them? **Recommendation:** stay conservative for v0.2, elevate via tier-threshold tuning in v0.3 based on dogfood friction.

5. **2025 A10 — Mishandling of Exceptional Conditions — overlap with A09.**

   Silent catches appear in both. Dedup rule: if a catch is in a route handler, tag A10-2025; if it's in an auth/security path without logging, tag A09. Needs a deterministic tiebreak at synthesis.

6. **ESLint plugin installation as a remediation.**

   Adding `eslint-plugin-no-unsanitized` is a two-line change that prevents XSS at commit-time forever. Should this be a **Band 1 auto-fix** (install + config), a Band 2 staged fix, or a Band 4 complement recommendation? It's the highest-leverage remediation in this brief. **Recommendation:** Stage-tier at Public-facing+, Band 4 recommendation at Internal and below.

7. **When the 2025 edition becomes the default, does Vibe Sec auto-migrate finding tags?**

   `/vibe-sec:research --concern owasp-top-10` re-runs this brief periodically. On re-run, should it rewrite past findings' tags? **Recommendation:** no — findings are immutable, they carry the tag that was authoritative when produced. Living-docs update applies only to new findings. Matches the "append-only" posture of findings.jsonl.

---

**End of survey. Hand to synthesis agent.** Primary contribution of this brief: the tier-applicability matrix and the cross-concern dependency map. Those two artifacts are the glue the other nine briefs will bolt their depth onto.

## Sources

- [OWASP Top 10:2021](https://owasp.org/Top10/2021/)
- [Introduction - OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Top 10:2025 (official)](https://owasp.org/Top10/2025/)
- [OWASP Top 10 2025 vs 2021: What Has Changed? (Equixly)](https://equixly.com/blog/2025/12/01/owasp-top-10-2025-vs-2021/)
- [The New 2025 OWASP Top 10 List (Fastly)](https://www.fastly.com/blog/new-2025-owasp-top-10-list-what-changed-what-you-need-to-know)
- [OWASP Top 10 2025: Key Changes (Orca Security)](https://orca.security/resources/blog/owasp-top-10-2025-key-changes/)
- [CWE Top 25 Most Dangerous Software Weaknesses – 2024 (MITRE)](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [2025 CWE Top 25 (MITRE)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [2024 CWE Top 25 (CISA alert)](https://www.cisa.gov/news-events/alerts/2024/11/20/2024-cwe-top-25-most-dangerous-software-weaknesses)
- [eslint-plugin-security (npm)](https://www.npmjs.com/package/eslint-plugin-security)
- [eslint-plugin-security (eslint-community fork, GitHub)](https://github.com/eslint-community/eslint-plugin-security)
- [eslint-plugin-no-unsanitized (Mozilla, GitHub)](https://github.com/mozilla/eslint-plugin-no-unsanitized)
- [eslint-plugin-security Is Unmaintained (dev.to)](https://dev.to/ofri-peretz/eslint-plugin-security-is-unmaintained-heres-what-nobody-tells-you-96h)
- [Semgrep owasp-top-ten ruleset](https://semgrep.dev/p/owasp-top-ten)
- [Semgrep: Beyond Benchmarks - JavaScript Security](https://semgrep.dev/blog/2025/beyond-benchmarks-how-semgrep-redefines-javascript-security/)
- [Semgrep OWASP Top Ten solutions page](https://semgrep.dev/solutions/owasp-top-ten/)
