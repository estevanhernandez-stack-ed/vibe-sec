# Config-Level Security Posture — Research Brief

**Concern area:** OWASP A05 (Security Misconfiguration) applied to HTTP response headers, cookie flags, CORS, CSRF, debug exposure, default credentials, and framework-specific security defaults.

**Scope calibration:** v0.2 ships with JS/TS focus. The detection substrate is *static configuration + AST walks over middleware chains*. Runtime verification of headers is explicitly a Pattern #13 deferral (securityheaders.com, Mozilla Observatory) — Vibe Sec asserts emission, not receipt.

**Author persona:** Security-headers + web-app-configuration architect. Voice: opinionated, specific, bias toward detection patterns that survive adversarial refactoring of the host app.

---

## Landscape

The 2026 baseline for HTTP security headers has stabilized around the OWASP Secure Headers Project's recommendation set, and — importantly for a vibe-coded-app auditor — the baseline has hardened. Three shifts in the 2025–2026 window are load-bearing for Vibe Sec:

**1. CSP Level 3 is effectively the target, not the frontier.** Chrome 52+, Edge 79+, Firefox 52+, and Safari 15.4+ all support `strict-dynamic` and nonce/hash-based source expressions. The modern "strict CSP" pattern — nonce + `strict-dynamic` + `'unsafe-inline'` as a backward-compatibility fallback ignored by CSP3 browsers — is the posture a public-facing app should be measured against. The 2026 OWASP Secure Headers adoption study still finds **48.8% of sites with CSP use `unsafe-inline`** and **42.5% use `unsafe-eval`**, which means the dominant real-world CSP is a CSP in name only. Vibe-coded apps are overrepresented in that 48.8% — an LLM will happily emit `script-src 'self' 'unsafe-inline' 'unsafe-eval'` because it makes the demo work.

**2. HSTS preload has gotten more dangerous, not safer.** The preload list is a one-way commitment; removal is months-long and not guaranteed. OWASP and hstspreload.org both now recommend `max-age=63072000` (two years) with `includeSubDomains; preload` — but the same guidance pairs with a hard warning: preload applies to all subdomains including internal/non-public ones, and a mistake can render internal tooling unreachable. For Vibe Sec this means HSTS detection must be **tier-aware**: an Internal tier app should not be nudged toward preload at all; a Customer-facing SaaS tier should see it as a graduation recommendation, not a v1 fix.

**3. Permissions-Policy replaced Feature-Policy and grew teeth.** The recommended posture for a vibe-coded app that doesn't use those features is the opt-out-everything form: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), interest-cohort=()`. The `unload=()` directive is now a bfcache performance win worth surfacing; its absence is not a vulnerability but an optimization gap, and Vibe Sec should not inflate severity.

**Recent attack vectors worth naming in the brief:**

- **CVE-2025-29927** (Next.js middleware bypass via `x-middleware-subrequest` header injection). An external actor adding this header makes Next.js skip middleware — which means any app relying on Next.js middleware for auth *or* for security-header emission had a window where both were trivially bypassable. Any Vibe Sec audit of a Next.js app must call the Next.js version and flag anything unpatched.
- **CORS credential-reflection attacks** remain the dominant header-adjacent finding in bounty programs. A 2025 study of 100k+ web apps found **35% had an exploitable CORS misconfiguration**. The signature is `Access-Control-Allow-Origin` reflecting the request's `Origin` header with `Access-Control-Allow-Credentials: true` — effectively same-origin-policy disabled.
- **SameSite=Lax is not CSRF protection.** Chrome's Lax-by-default carries a 120-second post-set window in which top-level POSTs are treated as Lax (unrestricted); `method-override` middleware can turn a CSRF-protected POST into an unprotected GET; and GET-based state-changing endpoints (the classic "build me a CRUD app fast" LLM anti-pattern) are unprotected by SameSite entirely. Vibe Sec must treat SameSite as *defense in depth*, never as a substitute for CSRF tokens on state-changing endpoints.
- **Firebase security rules in `allow read, write: if true`** remain the #1 cause of Firebase data breaches in 2025, with ~150 popular-app endpoints found publicly accessible via APK-extracted project IDs. For a vibe-coded-app auditor this is arguably *the* highest-signal finding on a Firebase stack.

**The baseline header set Vibe Sec measures against** (OWASP Secure Headers, 2026 recommendation consolidation):

| Header | Recommended value (public-facing) | Critical at tier |
| --- | --- | --- |
| `Content-Security-Policy` | Strict: `default-src 'self'; script-src 'nonce-{N}' 'strict-dynamic'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` | Public-facing |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (preload at regulated tier) | Public-facing |
| `X-Content-Type-Options` | `nosniff` | Internal |
| `X-Frame-Options` | `DENY` (or CSP `frame-ancestors 'none'`) | Internal |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Public-facing |
| `Permissions-Policy` | Opt-out starter: `camera=(), microphone=(), geolocation=(), payment=()` | Public-facing |
| `Cross-Origin-Opener-Policy` | `same-origin` | Customer-facing SaaS |
| `Cross-Origin-Resource-Policy` | `same-origin` | Customer-facing SaaS |
| `Cross-Origin-Embedder-Policy` | `require-corp` (only if isolation needed) | Regulated |

`X-XSS-Protection` is intentionally absent from the baseline: all major browsers have removed or disabled the legacy XSS auditor, and the header is now considered deprecated noise. Vibe Sec should **not** recommend adding it; if present and set to `1; mode=block`, surface as an informational finding (harmless but stale).

---

## Detection mechanics

Detection for this concern is a mix of (a) config-file parsing, (b) AST walks over middleware-registration chains, (c) route-level inspection for header emission, and (d) a small pile of string-pattern scans for defaults and debug flags. The framework-specific substrate drives everything.

### Framework-config-file parsing

**Next.js (`next.config.js` / `next.config.mjs` / `next.config.ts`)**
- Look for the `headers()` async function. Parse the returned array; each entry has `source` + `headers: [{ key, value }]`. Enumerate which of the baseline-set headers are emitted, with what values, on which `source` patterns.
- Check `async headers()` coverage: a common LLM mistake is setting headers only on `source: '/(.*)'` but omitting `source: '/api/(.*)'` or vice versa — API routes unprotected while pages are protected.
- Detect presence of a `middleware.ts` / `middleware.js` file at project root. If present, parse `export const config = { matcher: ... }` to understand which paths the middleware covers.
- If middleware is emitting headers via `NextResponse.next()` + `response.headers.set(...)`, enumerate those emissions and cross-check the `matcher`. The CSP-with-nonce pattern (Next.js-recommended) lives here.
- **CVE-2025-29927 check:** read `package.json` for `next` version. Flag if the version is in the vulnerable range (pre-14.2.25 / pre-15.2.3 / etc. — pin to published advisory table).

**Vite (`vite.config.ts` / `vite.config.js`)**
- Vite itself doesn't emit headers in production (that's the deploy target's job). In dev mode, `server.headers` and `preview.headers` can be set. Parse these; absence is expected, not a finding.
- The real Vite signal is the *stack inference*: Vite + React typically means the app is served by something else in production (Vercel, Netlify, Cloudflare Pages, nginx). Vibe Sec must detect that target (look for `vercel.json`, `netlify.toml`, `_headers`, `nginx.conf`, `Dockerfile`) and shift header audit there.
- If none of those exist in a Vite-frontend repo, that's a finding: "frontend has no detectable production header-emission config — headers will default to whatever the hosting platform provides, which is often nothing."

**Express (`app.js` / `server.js` / `src/app.ts`)**
- AST-walk the middleware chain: look for `app.use(...)` calls. Detect `helmet()`, `helmet({...})`, `cors()`, `cors({...})`, and raw header-setting via `res.setHeader(...)` or `res.set({...})`.
- `helmet()` with no arguments is the best-baseline default. `helmet({ contentSecurityPolicy: false })` is a common degradation — flag it. `helmet.contentSecurityPolicy({ directives: {...} })` with explicit directives needs per-directive audit against the strict-CSP baseline.
- Order matters: `app.use(helmet())` must come *before* route handlers. Detect out-of-order registration (helmet after routes).
- Raw `res.setHeader('X-...', ...)` inside a route handler is a yellow flag — per-route overrides are legitimate but usually mean the global posture is being relaxed.

**Fastify (`server.ts` / `app.ts`)**
- `@fastify/helmet` is registered via `fastify.register(helmet, { ... })`. Detect the registration, parse the options. `{ global: false }` means per-route opt-in — enumerate which routes opt in.
- `@fastify/cors` has its own registration. Parse `origin`, `credentials`, `methods`.
- `enableCSPNonces: true` is the Fastify-native pattern for strict CSP with nonces; its presence is a positive signal at Customer-facing SaaS tier.

**Firebase (`firebase.json`, `firestore.rules`, `database.rules.json`, `storage.rules`)**
- `firebase.json` can set headers via the `hosting.headers` array. Parse it the same way as Next.js `headers()`.
- **`firestore.rules` / `database.rules.json` / `storage.rules` are the highest-signal files in any Firebase project.** Detect the literal patterns:
  - `allow read, write: if true;` — Critical at any tier above Prototype
  - `allow read, write: if request.auth != null;` — High (authentication without authorization; any logged-in user can touch everything)
  - `allow read: if true;` — High (anonymous read; may be intentional for public content, but needs per-tier adjudication)
  - Absence of `match /{document=**} { allow ...: if false; }` catch-all at the end — Medium (implicit-deny is fine, explicit-deny is better)
- Storage rules default-open (`allow read, write: if request.auth != null;` on `/b/{bucket}/o`) is the Firebase Storage equivalent of a public S3 bucket.

**Hosting-platform header files**
- `vercel.json` → `headers` array
- `netlify.toml` → `[[headers]]` sections, or `public/_headers` for the file-based form
- Cloudflare Pages `_headers` file
- `static.json` for Heroku buildpack
- `nginx.conf` `add_header` directives
- Apache `.htaccess` `Header set` directives

For each, detect whether the baseline header set is emitted and flag gaps.

### Header-emission detection via route middleware inspection

The subtlety is that a single `app.use(helmet())` doesn't prove every response carries the headers — a subsequent `res.setHeader` or a route-level override can strip them. Full-fidelity detection would require runtime probing, which is out of scope for v0.2.

**Static approximation Vibe Sec v0.2 uses:**
- Walk the middleware chain in registration order.
- For each `app.use` / `router.use` / `app.METHOD` call, record what it mounts, at what path, and in what order.
- Build an emission-matrix: for each route path prefix, list the middlewares that touch it.
- Flag routes where `helmet` / equivalent header middleware is not in the chain.
- Flag per-route handlers that call `res.removeHeader(...)` or `res.setHeader(...)` with a baseline-header name (potential override).
- Confidence on this finding is *medium*, not high — the chain may be correct in ways static analysis doesn't see (e.g., a custom middleware that re-emits headers). Stage the fix, don't auto-apply.

### Cookie-setting call inspection

Detect every callsite that sets a cookie and validate flags:

**Express / Node**
- `res.cookie(name, value, options)` — parse `options` object. Look for `httpOnly: true`, `secure: true`, `sameSite: 'strict' | 'lax'`, `maxAge` / `expires`.
- `res.setHeader('Set-Cookie', ...)` and `res.append('Set-Cookie', ...)` — parse the cookie string for `HttpOnly`, `Secure`, `SameSite=...`.
- `express-session` config: `cookie: { secure, httpOnly, sameSite, maxAge }`.
- `cookie-parser` / `cookie-session` config.

**Next.js**
- `cookies().set({...})` from `next/headers` in server components / route handlers.
- `NextResponse.cookies.set({...})` in middleware.
- Parse the options object same as Express.

**Detection rules:**
- Auth/session cookie missing `HttpOnly` → High (credential theft via XSS).
- Auth/session cookie missing `Secure` in a production config → High.
- Auth/session cookie missing `SameSite` entirely → Medium (defaults to Lax in modern browsers, but explicit is better, and older browsers differ).
- `SameSite=None` without `Secure` → browser-rejected; flag as bug, not security posture (the cookie won't be sent).
- `SameSite=Strict` on a cookie the frontend needs cross-site → flag as likely-broken (symptom: login redirect flows fail).

**Identifying "auth/session" cookies vs. preference cookies** is itself fuzzy. Heuristic list for v0.2: name matches `/session|sid|auth|jwt|token|csrf|user|remember/i`. Surface as "suspected auth cookie" when confidence is ambiguous.

### CORS config detection

The signature to detect is **`origin: '*' || true` combined with `credentials: true`**.

**Express (`cors` package)**
- `app.use(cors())` — no args = `Access-Control-Allow-Origin: *`, no credentials. Low severity, flag as "permissive CORS, explicit allowlist recommended at Public-facing tier and above."
- `app.use(cors({ origin: '*', credentials: true }))` — browser will block in theory, but any server emitting this is misconfigured; treat as High.
- `app.use(cors({ origin: true, credentials: true }))` — the `origin: true` reflects the request Origin. With credentials this is the classic catastrophic misconfiguration. **Critical.**
- `app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }))` — the programmatic form of origin reflection. Same severity as above.
- `app.use(cors({ origin: /.*/, credentials: true }))` — regex that matches everything. Same severity.

**Next.js / Fastify / raw Node**
- Parse `Access-Control-Allow-Origin` emission the same way. Look for dynamic echoing of the request `Origin` header.
- Check `Access-Control-Allow-Methods` for over-broad method sets (e.g., including `TRACE`, `CONNECT`, arbitrary custom verbs).
- Check `Access-Control-Allow-Headers: *` — the wildcard-with-credentials rule applies here too; when credentials are enabled, `*` is treated as the literal string, not a wildcard.

### Env-based debug-mode detection

**Canonical patterns:**
- `NODE_ENV !== 'production'` branches that emit detailed errors / stack traces / SQL query strings / request bodies.
- `DEBUG=*` / `DEBUG=app:*` in a `.env` that lacks an equivalent `.env.production` override.
- Framework-specific debug flags: `NEXT_PUBLIC_DEBUG`, `VITE_DEBUG`, `FASTIFY_LOG_LEVEL=debug`, `EXPRESS_DEBUG`.
- Error-handling middleware that returns `err.stack` in the response body (Express default 5xx handler does this in dev).
- `app.set('env', 'development')` in server entry files that ship to production.

**Detection approach:**
- Grep for the canonical patterns.
- Parse `.env.example` / `.env.production` if present and diff against base `.env` patterns.
- Walk error-handler middleware for `res.send(err)`, `res.json(err)`, `res.send(err.stack)`.
- Framework-specific: Next.js `reactStrictMode: false` in `next.config` isn't a security finding but is often paired with debug-leftover patterns; use as a correlation signal, not a primary finding.

### Hardcoded credential detection in default configs

This overlaps heavily with the secrets-detection concern and should defer to it for working-tree/git-history scans. The *config-posture* slice is narrower:

- `.env.example` / `.env.sample` containing values that look like real credentials (not placeholders like `YOUR_KEY_HERE`).
- `config/default.js` / `config.yaml` / `application.yml` with literal-string defaults for `password`, `secret`, `apiKey`, `jwtSecret`, `dbPassword`.
- Docker-compose files with `POSTGRES_PASSWORD=postgres`, `MONGO_INITDB_ROOT_PASSWORD=admin`, etc.
- Default admin-credential patterns: `admin/admin`, `root/root`, `admin/password`, `admin/changeme`, `user/user` as literals in seed scripts / migrations / fixtures.
- JWT secret defaults: `secret`, `jwt-secret`, `my-secret-key`, `changeme`, `development-key`.
- Framework defaults shipped and unchanged: Keycloak `admin/admin`, Kong admin API default, Grafana `admin/admin`.

---

## False-positive risks

The 12% FP commitment means Vibe Sec must be explicit about the legitimate patterns that look like findings. The big ones for this concern:

**1. Intentionally relaxed headers on specific endpoints.**
- Embed pages (OG previews, oEmbed endpoints, video-player embed routes) legitimately need `X-Frame-Options: ALLOWALL` or CSP `frame-ancestors` that include trusted parents. Don't flag the absence of `DENY` on routes matching `/embed/*`, `/player/*`, `/oembed/*` by path convention.
- Health-check endpoints (`/health`, `/ready`, `/_status`) typically have relaxed CORS for monitoring tooling. Don't elevate.
- Static-asset CDN routes (`/_next/static/*`, `/assets/*`) often ship with different caching/CORS posture by design.

**2. Legitimate wildcard CORS.**
- Public read-only APIs (weather, currency, public catalog endpoints) legitimately set `Access-Control-Allow-Origin: *` *without* `credentials`. This is safe and intentional. The finding only fires when credentials are also enabled.
- Public CDN endpoints for fonts, SDKs, and embedding widgets.

**3. Development-mode middleware that ships to production.**
- `morgan('dev')`, `pino-pretty`, `error-overlay` — these look like debug leaks but often have explicit `if (process.env.NODE_ENV !== 'production')` gates. Only flag when the gate is missing.

**4. Frameworks that emit headers the audit can't see.**
- Rails / Django / Spring Boot middleware is out of scope for v0.2, but a Node app calling out to a Rails backend may have headers set at a layer Vibe Sec can't parse. If a reverse proxy config (nginx, HAProxy) is present, *that* is the header-emission surface; don't double-count.
- Cloudflare / Fastly / CloudFront edge rules. No repo signal unless the config is checked in.

**5. Third-party SDK-added headers.**
- Auth SDKs (Auth0, Clerk, Supabase Auth) set their own cookies with their own flag choices. If those flags violate the baseline, the finding belongs to the SDK version / config, not the host app. Surface as "Auth SDK X v$VERSION sets $COOKIE with missing $FLAG — this is the SDK default; upgrade or override at SDK init."

**6. SameSite=Strict on cookies that intentionally need cross-site.**
- OAuth callback flows require `SameSite=None; Secure` on the state cookie by design. Flagging this as a missing-Strict-flag finding is a false positive.
- Embedded-checkout and SSO-via-iframe flows likewise.

**7. Rate-limiting absence on endpoints that aren't candidates for it.**
- Static asset routes, health checks, and endpoints fronted by a CDN with rate-limiting at the edge don't need app-level rate limiting. Defer rate-limiting findings to the dedicated rate-limiting agent; this concern only flags the *total absence* of any rate-limit middleware on auth/state-changing endpoints.

---

## Remediation patterns

Confidence-tier routing from the scope doc:

| Fix | Tier | Rationale |
| --- | --- | --- |
| Add missing security header (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) via `headers()` in `next.config`, `vercel.json`, `_headers`, or equivalent | **AUTO (≥0.9)** | Purely additive. Browsers ignore headers they don't understand; new headers don't break existing behavior. Exception: CSP — see below. |
| Install and register `helmet()` with defaults on an Express/Fastify app that has none | **STAGE (0.7–0.9)** | Mostly safe but `helmet`'s default CSP *can* break apps that load inline scripts. Stage the diff with a rationale note. |
| Add a strict CSP with nonces on a Next.js app | **STAGE** | Template the middleware change. Strict CSP + `strict-dynamic` breaks any app that has undeclared inline scripts. Builder must verify. |
| Tighten `helmet` CSP from default to strict-with-nonce | **STAGE** | Same reason. |
| Replace CORS wildcard with explicit allowlist | **STAGE** | May break frontend if the allowlist is wrong. Generate the diff, ask the builder to confirm the allowed origins. |
| Add `HttpOnly`, `Secure`, `SameSite=Lax` to an auth cookie | **STAGE** | Safe in most cases but `Secure` breaks local HTTP dev; surface the `process.env.NODE_ENV === 'production'` guard pattern. |
| Change `SameSite=None` → `Strict` | **STAGE** | Risks breaking intentional cross-site flows. Builder-only. |
| Add CSRF token middleware (`csurf`, `@fastify/csrf-protection`, `next-csrf`) | **STAGE** | Requires frontend changes to send the token. |
| Remove `unsafe-inline` / `unsafe-eval` from existing CSP | **STAGE** | High breakage risk. Use `Content-Security-Policy-Report-Only` as the staged form — deploy report-only first, collect violations, then tighten. |
| Add `helmet.js` to an Express app with no header middleware | **STAGE** | Small but real risk of breaking endpoints that rely on specific browser defaults (rare). |
| Fix Firebase rule `allow read, write: if true` | **NEVER-AUTO / INLINE** | Authorization logic change. Builder must think through who should be able to do what. Provide a template. |
| Fix `admin/admin` default credential | **NEVER-AUTO / INLINE** | Credential rotation is ops-critical and touches live systems. Provide rotation playbook. |
| Remove debug-mode config in production branch | **STAGE** | May break a currently-relied-on diagnostic path. Stage with rationale. |

**Auto-apply criteria (≥0.9):** the fix is strictly additive, behavior-preserving for conformant clients, and cannot be weaponized. Adding `X-Content-Type-Options: nosniff` on a route that doesn't have it is the archetype. Adding CSP is *not* in this category — CSP is blocking by design.

**The "report-only" escape hatch.** For CSP specifically, the right auto-apply pattern is not the enforcing header but `Content-Security-Policy-Report-Only` with a `report-to` / `report-uri` endpoint. This can be auto-applied: it never blocks, only reports. A subsequent manual review promotes to enforcing. Surface this as the default remediation on Public-facing-tier CSP gaps.

---

## Pattern #13 complements

Vibe Sec v0.2 ships baseline detection. When the builder has better tools installed, defer.

- **`helmet.js`** — when detected in `package.json`, Vibe Sec's auto-add-headers fix becomes "tighten helmet config" instead of "install helmet." Defer the baseline-header suggestions to helmet defaults and focus on the delta.
- **`@fastify/helmet`** — same for Fastify.
- **Mozilla Observatory** (observatory.mozilla.org) — runtime header scanner. Pattern #13 surface: "Once the app is deployed, run Observatory for a runtime score. Our audit covers emission config; Observatory covers what browsers actually receive." Surface as a post-deploy recommendation, not a pre-deploy dependency.
- **securityheaders.com** — same positioning; simpler single-URL scanner. Both are no-account services.
- **CSP Evaluator** (csp-evaluator.withgoogle.com) — Google's CSP static analyzer. When Vibe Sec detects a CSP, surface the CSP Evaluator link with the policy pre-populated as a query param. At Customer-facing-SaaS tier and above, this is a mandatory "paste your policy here" step in the remediation narrative.
- **next-safe-middleware** — a Next.js community package for strict CSP with nonces. If detected, Vibe Sec defers CSP-config generation and focuses on `matcher` coverage audit.
- **`helmet-csp`**, **`lusca`** — older Express security middlewares. If present, note as "legacy security middleware detected; modern `helmet()` is the current recommended default."
- **Snyk / Socket.dev** — out of scope for this concern but catch CVEs in the framework-config dependencies (Next.js CVE-2025-29927 being the archetypal example).
- **`csrf-csrf`** / **`@fastify/csrf-protection`** / **Next.js route-handler CSRF patterns** — when present, Vibe Sec should check they are actually *applied* to state-changing routes, not just installed.

**The deferral heuristic:** if a tool in the target project's `package.json` covers a finding class better than Vibe Sec's static detection, downgrade Vibe Sec's finding severity one tier and surface the delegation. Don't double-notify the builder.

---

## Tier applicability

The tier × concern matrix for config-level security posture:

| Tier | Required checks | Additional checks | Graduation-only |
| --- | --- | --- | --- |
| **Prototype / hackathon** | None required. Surface Firebase `if true` rules as a warning only. | — | Everything else |
| **Internal tool** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP `frame-ancestors`), cookie `HttpOnly` on auth cookies, no `admin/admin` defaults, Firebase rules not `if true`. Basic debug-mode leakage check. | `Referrer-Policy`, non-wildcard CORS if API is called cross-origin by design | HSTS preload, strict CSP |
| **Public-facing (non-regulated)** | Full baseline header set (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy), `Secure` + `SameSite` on all cookies, explicit-origin CORS with `credentials`, CSRF tokens on state-changing endpoints, no debug-mode in production | `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, CSP `report-uri` configured | Regulated-tier-only checks |
| **Customer-facing SaaS** | Everything above + strict CSP (nonce-based, no `unsafe-inline`/`unsafe-eval`), HSTS `max-age ≥ 1 year`, full Permissions-Policy opt-out posture, SameSite=Strict on session cookies | HSTS preload, COOP/COEP, CSP enforcing (not report-only) | Compliance-specific checks |
| **Regulated / enterprise** | Everything above + HSTS preload, CSP with no wildcards anywhere, formal CSP review checklist, cookie prefixes (`__Host-`, `__Secure-`), `Expect-CT` or equivalent certificate-transparency enforcement | Subresource Integrity on all third-party scripts, CAA DNS records audit | — |

The matrix is driven by the principle that **each tier adds requirements, never removes them.** A finding that's Critical at Regulated tier must not be Informational at Prototype tier — it may be deferred, but the severity itself is tier-invariant. What *changes* with tier is whether the finding blocks a `/vibe-sec:gate` run.

---

## Cross-concern dependencies

This concern has the densest overlap map of any of the ten. Named intersections:

**Rate limiting (separate agent).** Rate-limit headers (`X-RateLimit-*`, `Retry-After`) are emitted by rate-limit middleware. Config-posture's detection of *middleware registration* overlaps with rate-limiting's concern. **Handoff contract:** config-posture detects and inventories the middleware; rate-limiting audits the thresholds, bypass paths, and endpoint coverage. Config-posture must not fire a "no rate limiting" finding — defer to the rate-limiting agent's output. If the rate-limit agent says "rate limiting is absent on /api/auth/*," config-posture can *reference* that finding when ranking the auth-surface exposure, but not duplicate it.

**Auth (auth-model-static-analysis agent).** Cookie flags (HttpOnly, Secure, SameSite) are fundamentally a session-handling concern, and the auth agent owns session-lifecycle findings (expiry, rotation, revocation). **Handoff contract:** config-posture owns the *flag-level* findings ("this cookie lacks HttpOnly"). The auth agent owns *lifecycle* findings ("this session cookie has no expiry"). When both agents touch the same cookie, merge in the report under auth's surface, with config-posture's flag finding as a sub-item.

**OWASP A05 (meta-audit agent).** A05 is the category this concern maps to by name. The A05 agent does a broader structural audit (default-deny architecture, principle-of-least-privilege at the infrastructure level, error-handling posture). Config-posture is the "headers and cookies and CORS" slice. **Handoff contract:** A05 cross-references config-posture's findings and elevates severity if they appear alongside structural-misconfiguration signals (e.g., debug-mode plus default-creds plus missing headers = systemic misconfig, not three independent findings).

**Crypto / PII handling (separate agent).** HTTPS enforcement (HSTS, `Secure` cookie flag, `Strict-Transport-Security`) is both a config-posture concern and a crypto-in-transit concern. **Handoff contract:** config-posture owns the *header-level* enforcement. Crypto owns the *cipher-level* and *cert-level* audit (TLS version, cipher suite, cert validity, HSTS preload-list status). HSTS presence is a shared finding; absence of TLS 1.3 is crypto-only.

**Secrets detection (separate agent).** Hardcoded credentials in config files is the overlap. **Handoff contract:** secrets-detection does the working-tree + git-history scan for any credential pattern. Config-posture only does the narrow "default admin/admin in a seed or config file" pattern and *defers the rest.* A finding of a real credential in `.env.example` is secrets-detection's; a finding of `admin/admin` in `docker-compose.yml` is config-posture's.

**Dependency audit (separate agent).** The CVE-2025-29927 Next.js advisory is the exemplar: config-posture cares because it affects middleware-based header emission; dep-audit cares because it's a package-version CVE. **Handoff contract:** dep-audit reports the CVE; config-posture *reads* dep-audit's findings and elevates the severity of middleware-dependent findings when a dep-audit CVE touches the middleware framework.

---

## Open questions for synthesis

These are the questions the synthesis agent needs to resolve before the config-posture checks can land in v0.2:

**1. Where does "Firebase security rules" live — config-posture, auth, or both?** Rules are literally a config file, but they encode authorization logic. This brief's position: config-posture owns the *existence and syntactic permissiveness* audit (`allow read, write: if true;` is a config-posture finding). Authorization-model audit (does the rule match the intended role hierarchy?) belongs to the auth agent. Synthesis decision: confirm or overrule.

**2. Is the CSP-report-only auto-apply acceptable?** The brief argues yes — it's strictly non-blocking and produces the data for tightening. But it does add a `report-to` endpoint, which means Vibe Sec is implicitly recommending an endpoint the builder may not have. Do we ship a default report-to target (626Labs-hosted? stdout? file-based?), or do we stage until the builder picks one?

**3. CVE-checked framework-version advisories: ours or dep-audit's?** The Next.js CVE-2025-29927 case. This brief's position: dep-audit reports the raw CVE; config-posture *annotates* findings that depend on the vulnerable code path. Synthesis should confirm the annotation contract.

**4. How does config-posture handle monorepos / multi-app repos?** A repo can have `apps/web/next.config.js` + `apps/api/server.ts` + `apps/admin/server.ts`, each with its own header posture. The current detection patterns assume single-app. We need a per-app emission-matrix output, not a flat one. Synthesis should lock the state-file schema for this.

**5. Runtime-header-probe as an optional Pattern #13 surface.** securityheaders.com has a free URL-based API. Should `/vibe-sec:audit` take an optional `--url` argument and fetch the runtime headers for cross-reference with the static findings? This is scope-creep toward active scanning, but the signal is high. Defer or include?

**6. What's the false-positive budget per sub-category?** The overall 12% commitment is global. Config-posture is a high-precision sub-domain (baseline headers are present or absent — little judgment) but CORS and CSP-directive audits are fuzzy. Synthesis should allocate FP budget per sub-domain, not per concern.

**7. Tier × cookie-type severity matrix.** Cookie-flag findings need multi-dimensional severity: *which cookie* (auth vs. preference) × *which flag* (HttpOnly vs. SameSite=Strict) × *which tier*. The brief sketches this inline but the matrix should be a structured artifact the fix engine reads directly, not prose.

**8. Embed/oEmbed/iframe-parent detection heuristics.** The false-positive section hand-waves "routes matching `/embed/*` by path convention." Synthesis should lock the detection rule: is it path-based, is it explicit annotation (`// vibe-sec:allow-frame`), is it config-file-driven? The answer affects both FP rate and the remediation-template shape.

**9. Does the synthesis brief ship a canonical "strict CSP for Next.js" template, or generate per-project?** Generating per-project needs resource-inventory of what the app actually loads (Google Fonts, Stripe, YouTube embeds, etc.). Shipping a canonical one means every app gets the same CSP, which will over-restrict or under-restrict. The research-swarm's A03 (injection) agent may have a view on inventory detection that feeds this.

**10. Report-only CSP → enforcing CSP promotion UX.** Report-only is trivially auto-apply. The promotion to enforcing is the dangerous step. Should `/vibe-sec:fix` learn a "promote CSP" subcommand that reads accumulated violation reports and generates an enforcing policy from them? That's a v0.3 feature candidate but worth flagging now so the v0.2 report-only-emission is designed to be a step on that path, not a dead end.

---

**Brief status:** Durable reference. Re-run `/vibe-sec:research --concern config-posture` quarterly or when (a) a new CVE in a major JS/TS framework affects header emission, (b) the CSP Level 3 spec advances to Recommendation, (c) a new header reaches Baseline browser support (`Cross-Origin-Embedder-Policy` transitions, `Expect-CT` successors, etc.), (d) OWASP Secure Headers Project publishes a new adoption study.

## Sources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Security Headers Adoption Study 2026 — AppSec Santa](https://appsecsanta.com/research/security-headers-study-2026)
- [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [Google Strict CSP guide](https://csp.withgoogle.com/docs/strict-csp.html)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy)
- [MDN: CSRF Attacks](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF)
- [PortSwigger: Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [Pulse Security: SameSite: Hax — Exploiting CSRF With The Default SameSite Policy](https://pulsesecurity.co.nz/articles/samesite-lax-csrf)
- [HSTS Preload List Submission](https://hstspreload.org/)
- [HackTricks: CSP Bypass](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)
- [Vaadata: CSP Bypass Techniques and Security Best Practices](https://www.vaadata.com/blog/content-security-policy-bypass-techniques-and-security-best-practices/)
- [Averlon: CVE-2025-29927 Next.js Header Injection](https://www.averlon.ai/blog/nextjs-cve-2025-29927-header-injection)
- [Next.js CSP Guide](https://nextjs.org/docs/app/guides/content-security-policy)
- [@next-safe/middleware — Strict CSP for Next.js](https://next-safe-middleware.vercel.app/)
- [helmet.js](https://helmetjs.github.io/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [fastify/fastify-helmet](https://github.com/fastify/fastify-helmet)
- [Intigriti: CORS Misconfigurations Advanced Exploitation Guide](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)
- [Outpost24: Exploiting Permissive CORS Configurations](https://outpost24.com/blog/exploiting-permissive-cors-configurations/)
- [Firebase: Avoid insecure rules](https://firebase.google.com/docs/rules/insecure-rules)
- [DEV: Top 10 Mistakes Developers Still Make with Firebase in 2025](https://dev.to/mridudixit15/top-10-mistakes-developers-still-make-with-firebase-in-2025-53ah)
