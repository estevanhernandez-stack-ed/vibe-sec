# Rate Limiting + Abuse Protection — Durable Research Brief

**Concern #7 of 10 · Vibe Sec v0.2 research swarm**
**OWASP mapping:** A04 Insecure Design · A09 Security Logging & Monitoring Failures
**Written:** 2026-04-20
**Author persona:** Abuse-protection / API-security expert, architect voice
**Audience:** Vibe Sec's `/spec` synthesis agent + future re-runs of `/vibe-sec:research --concern rate-limiting`

---

## Landscape

The 2025–2026 abuse landscape has three defining shifts from the 2022-era playbook: **AI-force-multipliered attacks**, **LLM-backed endpoints as a new budget-exhaustion target**, and **authenticated abuse eclipsing anonymous abuse** as the dominant pattern. Vibe Sec cannot assume the old "rate limit the login page" heuristic covers the threat model anymore.

**Credential stuffing is now AI-augmented.** Attackers pair leaked-credential corpora with LLM-inferred variants — surname-plus-year, company-name-plus-2024, email-pattern inference across a target's full username space. Wallarm's 2026 API ThreatStats reports credential stuffing still accounts for more than 30% of API attacks, with bot-driven traffic making up 60%+ of malicious API volume. The detection signature — "auth failures with high username cardinality" — is the rate-limiting-adjacent signal security tools should surface. Static rate-limit middleware that only caps requests-per-IP misses this entirely when attackers rotate residential proxies; what catches it is per-identity (not per-IP) failure tracking.

**LLM-API token-burning is a new attack primitive.** An endpoint that proxies OpenAI or Anthropic calls without a per-user budget is a direct line to the builder's credit card. Arcjet explicitly markets against this class ("stop bots from burning your AI budget"). Anthropic itself had to roll out weekly rate limits in August 2025 after Claude Code power-users caused cost spikes — which is the tell: *even the vendors* didn't have sufficient budget-protection telemetry. Any vibe-coded app with a `/api/chat` or `/api/generate` route that forwards prompts to an LLM provider and has no per-user token cap is a ticking invoice. This class of finding deserves its own severity band; it's not "might get DDoSed", it's "will get a $40k bill."

**Authenticated abuse > anonymous abuse.** 95% of API attacks now originate from authenticated sources — stolen API keys, session tokens, or legitimate-looking accounts created en masse. Rate limiting that *only* guards anonymous surfaces (the classic `/login`, `/signup`) is now insufficient; authenticated endpoints need per-token, per-user, per-tenant limits too. This is a structural gap Vibe Sec should name explicitly in its tier-applicability matrix.

**Scraping at AI-agent scale.** Agentic AI consuming APIs — not humans with browsers — is the new baseline. Resource-consumption attacks (OWASP API4:2023 "Unrestricted Resource Consumption") moved from 7th to 4th place in 2025 category rankings. Expensive reads (search, list-with-filter, GraphQL nested queries) are prime targets.

**Framework-level best-practice has matured.** The 2025 consensus on sensible defaults:
- Login: 5 attempts per 15-minute window, tracked per-identity (email) OR per-IP OR both
- Signup: 3 per hour per-IP, plus CAPTCHA on suspicious signals
- Password reset: 3 per hour per-identity
- Public API: 100 req/min per-IP with token-bucket smoothing
- Authenticated API: tiered per-plan (e.g., 1000 req/min free, 10000/min paid)
- AI-backed endpoints: explicit token budget per user per day, not just request count

The `express-rate-limit` package (10M+ weekly downloads), `@fastify/rate-limit`, Upstash Ratelimit (for serverless/edge), and Arcjet (AI-native) are the dominant Node/TS implementations. Platform-level rate limiting — Vercel WAF, Cloudflare WAF — has become the recommended *first* line; application-level middleware is the second. Cloudflare deprecated its legacy rate-limiting API in June 2025 in favor of the Ruleset Engine, so older configs may be stale.

---

## Detection mechanics

Vibe Sec's detection runs in four passes. The order matters: cheap wins first, deeper inspection only when the cheap pass misses.

### Pass 1 — Middleware inspection (cheap, high signal)

Scan for imported-and-applied rate-limit middleware. The detection signatures:

- **Express:** `import rateLimit from 'express-rate-limit'` AND `app.use(rateLimit(...))` or `router.use(rateLimit(...))` on an auth-adjacent route. AST-walk the route tree, flag any router mounting `/login`, `/signup`, `/password-reset`, `/auth/*`, `/api/auth/*` that does NOT have a `rateLimit()` call in its middleware chain.
- **Fastify:** `fastify.register(import('@fastify/rate-limit'), ...)` at app level, OR per-route `config.rateLimit` on sensitive endpoints. Flag routes tagged as auth/signup that lack a route-level config.
- **Next.js:** `middleware.ts` at project root with rate-limit logic (usually Upstash `@upstash/ratelimit` + `@upstash/redis`), OR per-route-handler guards. No middleware file + auth API routes present = high-priority finding.
- **NestJS:** `@Throttle()` decorator or `ThrottlerGuard` registration. Absence on auth controllers = finding.
- **Hono:** `hono-rate-limiter` or custom middleware.
- **tRPC:** procedure-level middleware wrapping `publicProcedure` — often absent; flag.

**Global vs per-endpoint signal:** a single `app.use(rateLimit({ max: 100, windowMs: 60000 }))` at the root is **weak** — it's a request-count floor, not an abuse-posture. Flag as "global-only rate limiting; auth routes share budget with static assets." The fix is per-route mounting with tighter limits on auth.

### Pass 2 — Route-by-route high-risk endpoint analysis

Build the route inventory (Vibe Sec already owns this from OWASP A01 audit work), then classify each route:

| Route pattern / shape | Risk class | Expected protection |
|---|---|---|
| `/login`, `/signin`, `/auth/*` | Brute-force | Per-identity + per-IP limits; lockout after N failures |
| `/signup`, `/register` | Account creation abuse | Per-IP limit + CAPTCHA + email-verification gate |
| `/password-reset`, `/forgot` | Enumeration + abuse | Per-identity limit; constant-time response |
| `/api/search`, `/api/*?q=` | Resource exhaustion | Per-user + global limits; query-complexity cap |
| `/api/chat`, `/api/generate`, `/api/ai/*` | LLM token burn | Per-user token budget; per-request token cap |
| `/api/upload`, multipart POST | Bandwidth abuse | Per-user bandwidth budget; size cap |
| `/api/webhook/*` (inbound) | Amplification | Per-source signed + rate-limited |
| `/api/export`, `/api/report` | CPU/memory abuse | Low per-user limit; queue rather than sync |
| `/graphql` | Query complexity | Depth/complexity limits + per-op rate limits |
| `/api/admin/*` | Privilege abuse | Per-admin-identity; alerting on anomaly |

For each route matched: does the middleware chain (from Pass 1) actually apply to *this* route? Express's `app.use(path, middleware)` order matters; middleware mounted after the route registration doesn't fire. This is a subtle false-negative risk if Vibe Sec only checks "middleware exists" without checking "middleware is reachable for this path."

### Pass 3 — AI-powered endpoint detection (new primitive)

Flag any file that imports `openai`, `@anthropic-ai/sdk`, `@google/generative-ai`, `@aws-sdk/client-bedrock-runtime`, `cohere-ai`, `replicate`, or `groq-sdk`. For each route handler that instantiates or calls one of these clients:

1. Is this route gated by auth? (If anonymous → **Critical** — unauthenticated LLM proxy is an open wallet.)
2. Is there a per-user token accounting layer? Grep for `tiktoken`, token-counting calls, user-scoped usage tables.
3. Is there a request-level `max_tokens` / `maxTokens` cap in the call options? Unbounded completions let a single request drain quota.
4. Is the streaming response tied to a per-user budget check that can interrupt mid-stream?

The conservative heuristic: **any LLM SDK import + Express/Fastify/Next.js route handler within 2 imports of that import = AI-backed route requiring budget protection.** The finding copy should name the specific risk: "this route forwards to OpenAI with no per-user budget; a single authenticated attacker can exhaust your monthly LLM spend."

### Pass 4 — Deployment-platform detection

Platform-level rate limits are often invisible to code-scanning. Vibe Sec needs a deliberate "platform posture" pass:

- **Vercel:** presence of `vercel.json` with `firewall` config, or references to `@vercel/firewall`. Absence of Firewall rules does NOT mean unprotected (Vercel has a default Pro-plan challenge layer), but the finding should note "no explicit Vercel WAF rate-limit rules detected; relying on platform defaults only."
- **Cloudflare:** `wrangler.toml` (Workers) or documentation hints in README/deploy scripts. Check for `_headers` files, Ruleset references. Flag legacy `rate_limiting` configs as outdated (deprecated 2025-06-15).
- **AWS / API Gateway:** `serverless.yml` or CDK/CloudFormation with `throttle:` / `usage plans`. Absence with Lambda-deployed API routes = finding.
- **Netlify:** Edge Functions + Netlify Blobs pattern, or Netlify's Rate Limiting rules in `netlify.toml`.
- **Fly / Railway / Render:** typically no platform rate limiting; *must* have app-level middleware. If deploy target is one of these and middleware is absent, severity elevates.

The signal Vibe Sec reports: the **combination** of (platform detected) + (platform-rate-limit config absent) + (app-middleware absent) = genuine gap. Any one of the three present = partial coverage, note in the "worth reading" band.

### Pass 5 — Abuse-monitoring presence (A09 hook)

This is the under-covered half of the concern. Rate limiting without logging is like a fire alarm with no speaker. Check for:

- Structured logging on rate-limit rejections (429 responses tagged in logs)
- Metrics emission (Prometheus counters, OpenTelemetry spans) on auth failures
- Alerting config (`sentry`, `datadog`, pager integrations) scoped to auth-failure spikes
- Any API-key / token usage tracking — does the app even know which key called which endpoint?

Absence is an A09 finding, not an A04 one. Vibe Sec should tag both categories on the same underlying gap when that's what the evidence supports.

---

## False-positive risks

Rate-limit detection has a higher FP rate than secret detection — the 12% target Vibe Sec committed to is the right ceiling for this concern. Classes to explicitly filter:

**Intentionally unrestricted endpoints.** Health checks (`/health`, `/healthz`, `/api/status`, `/_health`), metrics endpoints (`/metrics`), readiness probes. These SHOULD be unrate-limited; flagging them is noise. Build a config-aware allowlist by naming convention AND by content (returns `{ status: 'ok' }`-shaped body, no DB call).

**Platform-level limits invisible to code.** A Cloudflare-fronted app with tight WAF rate-limit rules doesn't need `express-rate-limit`. Vibe Sec's code-only scan will flag it anyway. The mitigation: Pass 4 platform detection lowers severity when platform evidence is present, and the finding copy explicitly says "no code-level protection; platform-level posture not verifiable from repo — confirm your Vercel/Cloudflare config is set."

**Dev-vs-prod middleware differences.** Many apps conditionally apply rate limiting with `if (process.env.NODE_ENV === 'production')`. AST-walk needs to resolve these — the middleware IS present in prod, it just doesn't fire in dev. Flag at informational severity only, with the note "rate limit is production-only; verify production deployment applies it."

**Internal-only services.** An API behind a VPN, Tailscale, or AWS PrivateLink / VPC-internal boundary has network-level access control that substitutes for app-level rate limiting at the Internal tier. Vibe Sec's tier classification should lower severity when the deploy context is Internal.

**Already-queued workloads.** A route that enqueues to BullMQ / SQS / Inngest with downstream worker concurrency limits has abuse protection via the queue, not the HTTP middleware. Detect queue-enqueue patterns and treat as compensating control.

**Custom rate limiting.** Builders occasionally roll their own (Redis + lua, Postgres advisory locks). The AST pattern won't match known middleware imports, but the logic is present. Mitigation: look for `INCR`, `EXPIRE`, `redis.incr`, sliding-window-keyed patterns near auth routes. Mark as "custom rate limiting detected; not verified for correctness" rather than missing.

**CAPTCHA-gated endpoints.** A signup route behind Turnstile/hCaptcha has abuse protection even without a numeric rate limit. Detection: import of `@marsidev/react-turnstile`, `next-hcaptcha`, or a `/siteverify` call in the handler = compensating control. Lower severity accordingly.

---

## Remediation patterns

Vibe Sec's fix routing (per scope `/fix` confidence-tier rules) for this concern:

### INLINE (advisory, never auto-applied) — destructive or behavior-changing

- **Adding rate limiting to an existing auth route.** Threshold calibration is a judgment call. Set too tight, real users get locked out; too loose, doesn't stop attackers. Vibe Sec proposes a middleware stub with research-informed defaults (5/15min on login, 3/hour on password-reset) AND annotates "verify these against your actual legit-traffic baselines." Stage in `.vibe-sec/pending/fixes/rate-limit-auth-routes.diff`, builder reviews before applying.
- **Platform-level WAF rule authoring** (Vercel Firewall, Cloudflare Ruleset). Plugin generates a config snippet with the recommended rule shape and explicit TODO markers for the builder to decide thresholds. The config write is inline, not auto.
- **CAPTCHA integration on signup.** Proposes the Turnstile component + `/siteverify` handler, but the builder has to register the Cloudflare site key. Inline with setup checklist.
- **LLM token-budget middleware.** Introduces a new concept (per-user daily token accounting); never auto-apply. Generate the reference implementation (Redis-backed, tiktoken-aware), stage for review.

### STAGED (pending/, builder opts in)

- **Widening an existing global rate limit into per-route tiered limits.** Mechanically safe but may change which 429s get emitted. Stage the diff.
- **Upgrading `express-rate-limit` from in-memory to Redis/Upstash backing** when the app has multiple instances. High confidence the change is correct; risk is misconfigured connection string. Stage.
- **Replacing deprecated Cloudflare legacy rate-limiting config** with Ruleset Engine equivalent. Deterministic translation, but touches prod traffic routing.

### INLINE (guidance, not code)

- **Platform-level rate-limit configuration suggestions** for Vercel / Cloudflare / AWS API Gateway. These are dashboard/config-file changes the builder makes outside the repo. Plugin provides the exact values + instructions; doesn't try to write them.
- **Signup-abuse-specific CAPTCHA guidance.** Which provider (Turnstile free + unlimited, hCaptcha, reCAPTCHA v3), which endpoints to gate, what "suspicious signal" thresholds to use.
- **Monitoring / alerting setup** for 429 spikes and auth-failure anomaly detection. Cross-tool guidance (Sentry alert rule shape, Datadog monitor query, OpenTelemetry metric name conventions).

### AUTO-APPLIED (rare in this concern)

- Adding `standardHeaders: true` / `legacyHeaders: false` to an existing `rateLimit()` call where neither is set. Additive, safer defaults, no behavior regression.
- Adding `trust proxy` setting when the app is behind a known reverse proxy and rate-limit middleware uses IP. Necessary for correct per-IP accounting.

---

## Pattern #13 complements

Tools Vibe Sec explicitly defers to for depth it doesn't attempt to replicate. Each surfaced in the "tools that belong in your toolbelt" band of the report.

- **Cloudflare WAF + Turnstile.** Free tier covers most vibe-coded-app needs. Recommended *before* app-level middleware for any Public-facing or higher tier. Vibe Sec's role: detect its absence and recommend; not configure it.
- **Vercel Firewall.** Native for Vercel-deployed apps. The `@vercel/firewall` SDK bridges dashboard-configured rules to in-code enforcement. Vibe Sec recommends this as default when Vercel deployment is detected.
- **Upstash Ratelimit** (`@upstash/ratelimit` + `@upstash/redis`). The serverless-native choice — HTTP-based Redis, pay-per-request, works in edge functions where persistent connections don't. Vibe Sec's default recommendation for Next.js middleware and Vercel/Netlify edge deployments.
- **Arcjet.** Newer (2024-era), AI-native — bundles rate limiting, bot detection, and AI budget control. Strongest recommendation for apps with any `/api/chat` or LLM-proxy routes. Ships with Express, Fastify, Next.js, Hono, NestJS, SvelteKit adapters. Per-user AI token budgets are a first-class primitive.
- **express-rate-limit** / **@fastify/rate-limit.** In-process, well-maintained, right for single-instance or Redis-backed multi-instance deploys. No external service.
- **rate-limiter-flexible.** More algorithmic options (leaky bucket, sliding window with Redis), useful when apps outgrow `express-rate-limit`.
- **Casbin** for authz-integrated rate limiting — per-role quotas enforced alongside permission checks. Relevant for multi-tenant SaaS at Customer-facing or Regulated tier.
- **Cloudflare Turnstile** (CAPTCHA — free + unlimited), **hCaptcha**, **Google reCAPTCHA v3.** Signup/login bot gating. Turnstile is the 2025 default for new implementations.
- **AWS WAF rate-based rules, GCP Cloud Armor.** Relevant when cloud-deployed; deep-platform protection.
- **Fingerprint (formerly FingerprintJS Pro)** — device-fingerprint-based rate limiting for hard-to-identify abuse. Commercial; Regulated-tier territory.

The synthesis agent should resolve: when detecting platform (Vercel / Cloudflare), does Vibe Sec recommend the *platform-native* tool first, or the *framework-generic* tool first? Current research lean: platform-native first at Public-facing and above (one less moving part, lower latency), framework-generic first at Prototype / Internal (portable, no account setup). The synthesis document should lock this.

---

## Tier applicability

The applicability gradient for Vibe Sec's 5-tier model:

| Tier | Rate-limit posture expected | Vibe Sec action |
|---|---|---|
| **Prototype / hackathon** | None required | Do not flag. Informational note only if there's an LLM-backed endpoint exposed to the public internet (that's a wallet-drain risk even at prototype tier — the only prototype-tier critical finding in this concern). |
| **Internal tool** | Light — global rate limit + platform defaults acceptable | Flag absence of ANY rate limiting if exposed beyond VPN. No requirement for per-route tuning. |
| **Public-facing** | Required — per-route rate limits on auth (`/login`, `/signup`, `/password-reset`); global + identity tracking on APIs | Flag missing middleware on auth routes as **Critical**. Missing global limits = **High**. Missing platform-level posture = **Medium**. |
| **Customer-facing SaaS** | Mandatory — per-tenant quotas, per-user budgets on expensive routes, LLM token budgets if applicable, abuse monitoring (A09 half) | All of Public-facing plus: LLM token burn without budget = **Critical**. Missing per-tenant rate limits = **High**. No metrics/alerting on auth failures = **Medium**. |
| **Regulated / enterprise** | Full — per-user, per-tenant, per-API-key quotas; anomaly detection; abuse logging integrated with SIEM; CAPTCHA on all account-creation flows; platform + app-level defense in depth | All above plus: missing anomaly detection / SIEM integration = **High**. Missing CAPTCHA on signup = **High**. Missing per-API-key quotas on authenticated endpoints = **High**. |

Cross-concern note: the tier-calibrated applicability here is tighter than several other concerns because rate limiting at scale is a *compounded* concern — it gets more mandatory, not just higher-severity, as tiers graduate. A prototype with no rate limiting is fine; a SaaS with no per-tenant limits is a breach waiting to happen.

---

## Cross-concern dependencies

This concern overlaps meaningfully with four other Vibe Sec concerns. Synthesis needs to resolve ownership and avoid duplicate findings.

**Concern #8 — Auth model static analysis.** Login brute-force protection is *both* a rate-limiting finding and an auth-posture finding. Proposed split: **rate-limiting** owns the middleware-presence detection and the per-route limit tuning; **auth-model** owns the account-lockout-after-N-failures logic and credential-storage hardening. A joint finding (both concerns flag) emits once to the report with both category tags. The `findings.jsonl` schema should permit multi-category tagging.

**Concern #3 — OWASP Top 10 (A04, A09).** Rate limiting is the primary surface for A04 Insecure Design and a major A09 Logging/Monitoring surface. The OWASP concern's audit rolls up this concern's findings under A04 / A09 when writing its category-level summary. Avoid double-counting in the tier weighted score.

**Concern #5 — Config-level security posture.** Platform-level rate-limit config (Vercel / Cloudflare / AWS) lives at the boundary between this concern and config-posture. Proposed split: **config-posture** owns detection of "is the config file present and sane"; **rate-limiting** owns "does the config actually protect the routes that need it." Two different questions, both matter.

**Concern #4 — PII handling audit.** Abuse monitoring that logs too much — full request bodies, user-identifying tokens in plain logs — is a PII leak surface. If Vibe Sec recommends "add structured logging to 429 responses", it must coordinate with the PII concern to ensure the recommended log shape doesn't create a new leak. The synthesis agent should lock a shared "safe log shape" for abuse events.

**Vibe Test composition.** When `.vibe-test/state/covered-surfaces.json` shows behavioral tests exist for `/login`, Vibe Sec de-prioritizes "is the limit correct" but still audits "is the limit present in code." Conversely, when Vibe Sec flags a missing rate limit on a route, the `findings.jsonl` entry carries `test_recommendation: "behavioral test: 429 returned after N auth failures"` so Vibe Test's next `/generate` run elevates that edge-case.

---

## Open questions for synthesis

Questions the synthesis agent must resolve, or surface to Este at `/spec` time as explicit architect-questions:

1. **Platform-vs-framework recommendation order.** When Vercel is detected, recommend Vercel Firewall first or Upstash Ratelimit first? (Research lean: Firewall for Public+ tiers, Upstash for Prototype/Internal. Confirm.)

2. **LLM-token-burn severity floor.** Is an unauthenticated LLM-backed endpoint a **Critical** finding even at Prototype tier? (Argument for yes: the financial risk is real even at prototype. Argument for no: prototype tier is "YOLO" by design. Suggested resolution: yes, critical — this is the one concern that overrides tier gating because dollars-at-risk is concrete.)

3. **Custom rate-limiting detection confidence.** How confident does Vibe Sec get on Redis-INCR-pattern rate limits? False-positive risk is high (lots of Redis use is not rate limiting). Suggested resolution: flag as "custom rate limiting detected; not verified for correctness" at informational severity, do not count against tier score.

4. **CAPTCHA-as-compensating-control weight.** Does Turnstile on signup fully substitute for numeric rate limiting on signup, or is it a compensating control that reduces but doesn't eliminate the finding? Suggested resolution: reduces severity by one band, does not eliminate.

5. **Rate-limit headers detection.** Should Vibe Sec check for `RateLimit-*` standard headers in responses (requires running the app) or only for `standardHeaders: true` in middleware config (static)? Suggested: static only in v0.2 — runtime probing is out of the static-audit positioning.

6. **Dev-vs-prod middleware gating.** Should `if (NODE_ENV === 'production')` gated middleware count as present or absent for the tier score? Suggested: count as present with a note; downgrade to absent only if the entire middleware file is conditionally imported (the common footgun).

7. **A09 split.** Does "rate limiting without monitoring" produce two findings (one A04, one A09) or one finding with dual category tags? Suggested: one finding with dual tags — the underlying gap is singular, the taxonomy mapping is duplicative. Schema must support it.

8. **Per-tenant rate limits at Customer-facing SaaS tier.** How does Vibe Sec detect "multi-tenant" without behavioral testing? Static signals: `tenant_id` column in schema, `orgId` in auth claims, `@auth/prisma-adapter` with organization relations, Clerk/WorkOS multi-org wiring. Confidence will be moderate; resolution likely: elevate tier expectation if multi-tenant signals are present, don't downgrade if they aren't (could still be multi-tenant via other means).

9. **Arcjet vs Upstash recommendation split.** Both are strong; they solve slightly different problems (Arcjet = AI-aware abuse protection suite, Upstash = rate-limiting primitive). Recommend both in complementary bands, or pick one as default per tier? Suggested: Arcjet when LLM-backed routes are detected; Upstash as the default primitive otherwise.

10. **Monitoring recommendations — tool-neutral or opinionated?** Does Vibe Sec say "add monitoring" or "add Sentry/Datadog/OpenTelemetry"? Suggested: tool-neutral with examples; let the builder pick. Vibe Sec's job is to surface the gap, not sell a vendor.

---

*End of brief. Feeds `/spec` synthesis. Living doc — re-runnable via `/vibe-sec:research --concern rate-limiting-abuse-protection`.*

## Sources

- [Inside Modern API Attacks: What We Learn from the 2026 API ThreatStats Report — Wallarm](https://lab.wallarm.com/inside-modern-api-attacks-what-we-learn-from-the-2026-api-threatstats-report/)
- [AI-Automated Credential Stuffing — TCM Security](https://tcm-sec.com/ai-automated-credential-stuffing/)
- [APIs: Your Weakest Link — Why API Attacks Are Exploding in 2025](https://medium.com/@jsocitblog/apis-your-weakest-link-why-api-attacks-are-exploding-in-2025-705139fa9a2e)
- [API Security in 2026: JWT Attacks, OAuth Abuse, and GraphQL Exploitation — Hive Security](https://hivesecurity.gitlab.io/blog/api-security-jwt-oauth-graphql-attacks/)
- [Arcjet rate limiting docs](https://docs.arcjet.com/rate-limiting)
- [arcjet/arcjet-js GitHub](https://github.com/arcjet/arcjet-js)
- [Upstash Ratelimit (upstash/ratelimit-js)](https://github.com/upstash/ratelimit-js)
- [Rate Limiting Next.js API Routes using Upstash Redis — Upstash Blog](https://upstash.com/blog/nextjs-ratelimiting)
- [express-rate-limit GitHub](https://github.com/express-rate-limit/express-rate-limit)
- [fastify/fastify-rate-limit GitHub](https://github.com/fastify/fastify-rate-limit)
- [10 Best Practices for API Rate Limiting in 2025 — Zuplo](https://dev.to/zuplo/10-best-practices-for-api-rate-limiting-in-2025-358n)
- [Vercel WAF Rate Limiting docs](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting)
- [Cloudflare WAF rate-limiting best practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/)
- [Anthropic unveils new rate limits to curb Claude Code power users — TechCrunch](https://techcrunch.com/2025/07/28/anthropic-unveils-new-rate-limits-to-curb-claude-code-power-users/)
- [Anthropic API Rate limits docs](https://docs.anthropic.com/en/api/rate-limits)
- [OpenAI API Rate limits guide](https://platform.openai.com/docs/guides/rate-limits)
- [Cloudflare Turnstile in Next.js (nextjs-turnstile)](https://github.com/davodm/nextjs-turnstile)
- [Better Auth Captcha plugin](https://better-auth.com/docs/plugins/captcha)
