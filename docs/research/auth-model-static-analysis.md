# Auth Model Static Analysis — Vibe Sec v0.2 Research Brief

> **Concern:** Auth model static analysis (OWASP A01 Broken Access Control + A07 Identification and Authentication Failures)
> **Author:** Domain research agent (Auth + AuthZ architecture persona)
> **Written:** 2026-04-20
> **Status:** Durable research brief — living doc, re-runnable via `/vibe-sec:research --concern auth-model`
> **Consumers:** `/vibe-sec:audit` (tier-calibrated detection + severity), `/vibe-sec:fix` (remediation-stage routing), `/vibe-sec:threat-model` (actor/privilege enumeration), `/vibe-sec:gate` (CI thresholds)

---

## Landscape

The 2025–2026 auth landscape is in the middle of a slow-motion shift that vibe-coded apps are almost uniformly sleeping through. Three forces are shaping what "secure auth" actually means right now, and Vibe Sec has to read against this landscape — not against a 2018 mental model.

**Force 1: Passkeys cross the chasm.** As of Q1 2026, 69% of consumers have adopted passkeys, 74% are aware of them, and 87% of surveyed U.S./UK companies report either deploying passkeys or actively planning deployment. 48% of the top 100 websites offer passkey login. Dashlane's observed passkey authentications doubled from 2024 to 2025 to ~1.3M/month. Gartner now projects passkeys as the primary consumer authentication method by 2027. Microsoft auto-enables passkeys for millions of personal accounts; Apple and Google sync passkeys across their platform clouds by default. **What this means for static analysis:** "has the app implemented WebAuthn/passkey support?" is no longer an advanced concern — it's a public-facing-tier baseline question. An app launching in 2026 with password-only auth and no passkey path is tier-regressing, not tier-standard.

**Force 2: OAuth 2.1 is effectively the new OAuth 2.0.** The IETF draft (`draft-ietf-oauth-v2-1-15`) is late-stage but technically stable and already adopted by major authorization servers. The load-bearing changes: PKCE is now required for *all* authorization code flows (not just public clients), the Implicit grant is gone, the Resource Owner Password Credentials grant is gone, redirect URIs must match by exact string (no wildcards), and RFC 9700 (OAuth 2.0 Security BCP, published January 2025) is rolled in by reference. **What this means for static analysis:** finding an app using `response_type=token` (implicit), missing PKCE, or wildcarded redirect URIs is now a concrete finding against a stable spec — not a "nice to have."

**Force 3: Zero trust shifts authorization from perimeter to per-request.** NIST SP 800-207 has been normative since 2020, but 2025 saw it crystallize into app-layer patterns: policy decision points (PDPs) split from policy enforcement points (PEPs), continuous authorization (not just one session check at login), policies expressed as code (Cerbos, OPA/Rego, Casbin), and decisions driven by user identity + device posture + context signals rather than roles alone. ETSI TS 104 102 (Sept 2025) codified a methodology. **What this means for static analysis:** "role === 'admin'" string comparisons scattered across route handlers is an *architectural* finding, not a stylistic one — the industry has moved on from hardcoded roles to policy-expressed authorization and vibe-coded apps that haven't gotten the memo score worse at higher tiers.

**The JWT vs session cookies debate has resolved into nuance.** The honest summary: both are fine if configured correctly; both are dangerous if not. The 2025 consensus:
- **HttpOnly + Secure + SameSite cookies** with server-side session storage is the safest default for browser apps. CSRF is a solvable problem (SameSite=Lax plus explicit CSRF tokens for state-changing requests).
- **JWTs in localStorage is an XSS grenade** — the conversation has largely moved past "localStorage JWTs are fine for SPAs" to "localStorage JWTs are a finding."
- **Access token + refresh token rotation** with short-lived access tokens (5–15 min) and HttpOnly-cookie-stored refresh tokens is the modern compromise when JWTs are used. Token rotation on each refresh is the newer expectation (per RFC 9700 BCP).
- **Session revocation is a first-class concern.** Pure-stateless JWTs that can't be invalidated mid-lifetime are increasingly treated as insufficient for Customer-facing-SaaS and above. Hybrid patterns (JWT + server-side blocklist on logout/password change) are the baseline expectation.

**Vibe-coding platform defaults — what Bolt, Lovable, v0 actually generate.** This matters because it tells Vibe Sec what it will predictably find in the wild:

- **v0 (Vercel):** Frontend-only scaffolding. *No built-in auth, no database.* v0 generates beautiful React/Next.js UI but emits route handlers with no middleware chain, no session checks, and no authorization logic. Builders plugging v0 output into a Next.js app ship pages with auth decoration (Clerk `<SignIn />` component in the layout) but unprotected route handlers and Server Actions underneath. **Expected finding pattern:** "UI gates present, backend enforcement missing" — the classic frontend-only access control failure mode.
- **Lovable:** Full-stack, Supabase-backed by default. Auth is Supabase Auth (email + magic link + OAuth). *Critical predictable pattern:* Lovable reliably scaffolds the auth UI and the Supabase client, but RLS policies are inconsistent — tables are frequently created without RLS enabled, or with permissive `true` policies ("just get it working"). The auth works; the authorization doesn't. **Expected finding pattern:** "authenticated but not authorized" — every logged-in user can read/write every row because RLS was never configured.
- **Bolt:** Bolt Cloud has native database support with automatic schema management. Auth scaffolding varies by prompt — if the builder asks for "user accounts," Bolt wires something (often Supabase or Clerk); if they don't, auth is absent entirely. **Expected finding pattern:** bimodal — either reasonable scaffolding or total absence.
- **Cursor / Claude Code / Windsurf / Copilot (IDE-embedded):** These defer to whatever library the builder names. The dominant pattern in 2026 is NextAuth v5 / Auth.js (OSS Next.js apps), Clerk (commercial Next.js), Supabase Auth (full-stack Supabase), Firebase Auth (Firebase projects), and Auth0 (enterprise/regulated). The AI tends to generate middleware but **often forgets Server Actions and API routes** — a critical gap given Next.js's mutation model.
- **CVE-2025-29927** (Next.js middleware authorization bypass, March 2025) is a reminder that even middleware-based enforcement has had foundational CVEs in the last year. Vibe Sec should flag Next.js projects pinned to vulnerable versions as a CVE passthrough *and* note middleware-only enforcement as architecturally fragile.

**The composite picture Vibe Sec needs to hold:** the average vibe-coded app in 2026 is a Next.js 14+/15+/16 app with Clerk or Supabase Auth for login, inconsistent middleware coverage, zero RLS in Supabase cases or permissive Firestore rules in Firebase cases, hardcoded `role === 'admin'` string comparisons in three files, and routes accepting `userId`/`orderId`/`documentId` params without ownership checks. That *is* the fingerprint. Static analysis that knows this fingerprint can do real work.

---

## Detection mechanics

The static-analysis surface for auth is six distinct probes. Each one answers a different question. Running them together produces the authorization matrix Vibe Sec ultimately surfaces.

### 1. Route inventory with auth-middleware attachment

**The question:** For every exposed route, does an auth check actually execute before the handler runs?

**Framework-specific detection:**

- **Next.js App Router:** Walk the `app/` tree to enumerate route handlers (`route.ts`, `page.tsx`, Server Actions as `"use server"` exports). Detect middleware.ts / proxy.ts (renamed in Next.js 16) and parse its `matcher` config to compute the protected-route set. For each route, classify: (a) middleware-protected, (b) inline `auth()` checked, (c) Server Action with no auth() invocation (HIGH risk — middleware doesn't cover Server Actions), (d) API route excluded from middleware matcher, (e) unprotected.
- **Next.js Pages Router:** `pages/api/*` route detection + HOC / `getServerSideProps` session check detection.
- **Express / Fastify / Hono / Elysia:** AST-walk app/router definitions. Enumerate `.get() .post() .use()` calls. Track which middleware is attached globally vs per-route. Identify `passport`, `express-session`, `cookie-session`, `jsonwebtoken`, `clerkMiddleware`, `withAuth`, `requireAuth` patterns.
- **Firebase Functions / Cloud Functions v2:** Each exported function is a route. Detect `functions.https.onCall` (auth context provided automatically) vs `functions.https.onRequest` (manual token verification required — common gap site).
- **tRPC:** Detect `publicProcedure` vs `protectedProcedure` vs `adminProcedure` usage per router.

**Output shape per route:**
```
{ path, method, handler_file, auth_mechanism: "middleware"|"inline"|"none",
  middleware_chain: [...], detected_auth_library, tier_sensitivity }
```

**Heuristics for "protected":**
- Route appears in an auth middleware's matcher config
- Route handler body invokes `auth()`, `getSession()`, `requireAuth()`, `verifyToken()`, `currentUser()`, `getServerSession()`, `clerkClient.users.getUser()`, `supabase.auth.getUser()`, `admin.auth().verifyIdToken()`, or similar before any data access
- Route is a Firebase `onCall` function (auto-populated `context.auth`)

**Heuristics for "unprotected":**
- None of the above, AND route handler body accesses DB, filesystem, env secrets, or invokes external side-effectful APIs
- Route is explicitly listed in a `publicRoutes` array of the auth config

### 2. Admin-endpoint protection

**The question:** Are `/admin/*`, `/dashboard/*`, `/internal/*`, `/api/admin/*`, and similar privileged URL namespaces *both* behind auth *and* role-gated?

**Detection:**
- URL pattern match: `/admin`, `/administrator`, `/root`, `/su`, `/internal`, `/manage`, `/console`, `/dashboard/admin`, `/api/admin`, `/api/internal`, `/api/users/*/role` (role-mutation endpoints), `/api/users/*/impersonate` (assume-role patterns)
- For each matched route: check auth middleware attachment (from probe 1), AND check for role assertion in the handler body or a role-gating middleware
- **Role assertion patterns:** `user.role === 'admin'`, `user.roles.includes('admin')`, `hasPermission(user, 'admin')`, `requireRole('admin')`, Casbin `enforcer.enforce()`, Cerbos `check()`, Supabase RLS policy referencing an admin role, Firebase custom claim check (`token.admin === true`)

**Severity escalation:** An admin-pattern URL with auth-but-no-role-gate is more dangerous than an unprotected non-admin URL. Any authenticated user reaching `/api/admin/*` is a privilege escalation path.

### 3. Tenant-isolation query-pattern detection

**The question:** Does every data-access call that reads or writes tenant-scoped data filter by `userId` / `tenantId` / `organizationId`?

**This is the Lovable / Supabase finding.** It's also the silent killer in Firebase apps and the reason tenant bleed-through is the most common Customer-facing-SaaS critical.

**Supabase / Postgres detection:**
- Parse SQL migrations + `supabase/migrations/*.sql` for `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`. Tables that exist in migrations but never get `ENABLE RLS` are findings.
- For tables with RLS enabled: parse policy definitions. Flag policies with `USING (true)` or `WITH CHECK (true)` — these are "RLS enabled but totally permissive," which is worse than disabled because it creates a false sense of safety.
- Cross-reference: tables referenced in `supabase.from('table_name')` client calls that don't have RLS enabled are *critical* (every authenticated user gets full table access).
- Detect service-role key usage in client-side code (`SUPABASE_SERVICE_ROLE_KEY` in browser-bundled code = game over).

**Firestore detection:**
- Parse `firestore.rules`. Flag: `allow read, write: if true;`, `allow read, write: if request.auth != null;` (authenticated-equals-authorized — the Firebase classic), missing rules for collections referenced in code, rules that don't compare `request.auth.uid` or `request.auth.token.tenantId` to `resource.data.*`.
- AST-walk Firestore queries in JS/TS. Flag `db.collection('items').get()` calls with no `.where('userId', '==', user.uid)` filter (relying on rules, OK) OR no rules (critical).
- Detect custom-claim-based multi-tenancy: look for `setCustomUserClaims({ tenantId })` in admin code and corresponding `request.auth.token.tenantId` checks in rules.

**Prisma / Drizzle / raw SQL detection:**
- AST-walk queries. Flag `prisma.document.findMany({ where: { id } })` with no `userId:` or `tenantId:` clause. Cross-reference the route handler — if the route is authenticated and the model has a `userId` column, a missing filter is a likely IDOR.
- Raw SQL: regex for `SELECT/UPDATE/DELETE FROM <table>` patterns with no `WHERE user_id = ` or `WHERE tenant_id = ` clause.

**The "every query filters by tenant" invariant is the right mental model.** Vibe Sec should produce a per-table report: "of N queries against `documents`, M filtered by user/tenant, K did not." K > 0 on a multi-tenant table is a finding.

### 4. IDOR risk scoring

**The question:** Which routes accept user-supplied IDs (`userId`, `orderId`, `documentId`, `projectId`, `fileId`) as path params or query params, and do they verify ownership before returning the resource?

**Detection pipeline:**
1. Enumerate routes whose path contains `:id`, `[id]`, `{id}`, `/:userId`, `/[orderId]`, etc. (Next.js dynamic segments, Express params, tRPC input schemas with id fields).
2. For each such route, walk the handler AST to find the DB call using that parameter.
3. Check whether the DB call *also* filters by the authenticated user's ID/tenant.

**IDOR risk tiers:**
- **Critical:** Route accepts `:id`, DB query uses `:id` directly (`findById(id)`), no ownership filter, no centralized authz. Classic horizontal IDOR.
- **High:** Route accepts `:id`, handler delegates to a service function — ownership check may or may not be there (static analysis can't always trace deep call graphs; surface as "needs review").
- **Medium:** Route accepts `:id`, handler has a permission check but it's role-based not ownership-based (`if (user.role === 'admin' || ...)` with an unclear else branch).
- **Low / informational:** Route accepts `:id` but the ID is opaque (UUID, not sequential integer) AND there's some authz check in the chain. Still worth flagging.

**False-positive risk is real here.** Centralized authz (Casbin enforcer called once, ownership baked into RLS, Prisma extensions that inject `userId` into every query) will look like "no ownership check in the handler" but actually enforce one. Vibe Sec needs to detect these patterns and suppress.

### 5. Session-management pattern classification

**The question:** Which auth library is this, and is it configured correctly?

**Library detection from `package.json` + config files:**
- `next-auth` / `@auth/*` → NextAuth v4 or Auth.js v5. Check `authOptions` / `auth.ts` for session strategy (`"jwt"` vs `"database"`), cookie config, callback presence.
- `@clerk/nextjs`, `@clerk/clerk-sdk-node` → Clerk. Check for `clerkMiddleware()` in middleware.ts and `<ClerkProvider>` in root layout. Flag missing `auth()` usage in Server Actions.
- `@supabase/ssr`, `@supabase/auth-helpers-*` → Supabase Auth. Check cookie setup, SSR helper usage, and crucially — **check RLS** (probe 3) since Supabase's auth without RLS is authenticated-but-not-authorized.
- `firebase/auth`, `firebase-admin` → Firebase Auth. Check custom-claim usage, admin SDK usage in server code, client-side auth-state listeners, and `firestore.rules` (probe 3).
- `@auth0/nextjs-auth0`, `auth0`, `express-openid-connect` → Auth0. Check callback URL config, audience/scope configuration.
- `passport`, `passport-*` → Passport.js. Check strategies in use, session serialization, and — given Passport's age — flag deprecated strategies (`passport-facebook` with v1 Graph API, etc.).
- `jsonwebtoken`, `jose` directly + manual implementation → Custom auth. **Elevate scrutiny.** Manual JWT implementations are where the worst findings live.

**Per-library correctness checks:**
- **NextAuth/Auth.js:** `NEXTAUTH_SECRET` present and not default. Cookie `secure: true` in prod. JWT callback doesn't leak sensitive data into the token (e.g., full user record with `passwordHash`). `session.maxAge` set.
- **Clerk:** `<ClerkProvider>` wraps the app. `clerkMiddleware` configured. Admin-gated routes use `auth().has({ role })` or `auth().has({ permission })`, not frontend-only role rendering.
- **Supabase Auth:** Not using anon key for authenticated operations. Service role key only in server code. RLS enabled on all user-scoped tables.
- **Firebase Auth:** ID tokens verified server-side with Admin SDK, not trusted from client. `onAuthStateChanged` listener for client state. Custom claims used for role/tenant.
- **Custom/manual JWT:** Signing algorithm not `none`. Secret not hardcoded. Expiration set. Refresh token rotation implemented. Token revocation mechanism exists (blocklist, version-bumped signing key, etc.).

### 6. Role-hardcoding detection

**The question:** Is the authorization model string-comparison-based (brittle, scattered, unreviewable) or policy-based (centralized, declarative, auditable)?

**Detection:**
- Grep/AST for: `role === 'admin'`, `roles.includes('admin')`, `role == "admin"`, `user.role === 'super_admin'`, `isAdmin`, `if (user.admin)`.
- Count unique admin role strings across the codebase: `admin`, `administrator`, `super_admin`, `superuser`, `root`, `owner`, `manager`. **Inconsistent strings for the same concept is itself a finding** — the author couldn't decide, which means the enforcement is probably inconsistent too.
- Detect role-enum/constant definitions (`const ROLES = { ADMIN: 'admin', USER: 'user' }`). Their presence is a mild positive signal — the builder tried to centralize.
- Detect policy-library presence: Casbin (`casbin` / `node-casbin`), Cerbos (`@cerbos/sdk`), OPA (`@open-policy-agent/opa-wasm`), Oso (`oso`), Permit (`permitio`). Presence = much better architecture; absence + scattered role-strings = architectural finding.

**Output for the authz matrix view:**
Vibe Sec's signature artifact for this concern is a *matrix*: rows are routes, columns are role/tenant/ownership dimensions, cells are "enforced here / not enforced / unknown." This is the "role/permission matrix audit" that the scope doc calls out as Vibe Sec's unique contribution vs. Vibe Test's behavioral tests.

---

## False-positive risks

Auth static analysis has a higher FP ceiling than almost any other Vibe Sec concern. The 12% across-the-board FP commitment in the scope doc is appropriately loose — this domain is where that slack gets used. Industry data on IDOR-like findings shows FP rates exceeding 50% in general-purpose SAST tools; Vibe Sec's job is to be smarter than that baseline.

**Classes of expected false positives:**

1. **Intentionally public endpoints.** Landing page (`/`), marketing routes (`/about`, `/pricing`), public blog posts (`/blog/*`), health checks (`/api/health`, `/health`, `/readyz`, `/livez`), webhooks (`/api/webhooks/stripe`, `/api/webhooks/*` — these use signature verification, not session auth), OAuth callbacks (`/api/auth/callback/*`), sitemap/robots (`/sitemap.xml`, `/robots.txt`), OpenGraph image generation (`/api/og/*`). **Mitigation:** ship a defaults suppression list; allow builder-configurable `public_routes` in `.vibe-sec/config`.

2. **Admin-like URL namespace that isn't actually admin.** `/admin-guide` is documentation. `/administrators` might be a list of team leads in a hobby app. `/internal` might be a UI-internal-state page, not authorization-internal. **Mitigation:** URL pattern is a weak signal; always cross-reference with whether the handler accesses admin-class operations (role mutation, user listing, destructive ops, etc.).

3. **Centralized authorization that static analysis can't trace.** Casbin enforcer at the middleware layer, Prisma client extensions that inject `userId`, RLS doing the work invisibly, Cerbos called via a wrapper. The route handler will look unprotected in isolation but is actually protected at a different layer. **Mitigation:** detect the presence of centralized patterns and treat their presence as a global signal — if Casbin is configured and middleware calls it, don't IDOR-flag every handler that accepts an id parameter.

4. **Legitimate user-supplied IDs with ownership baked in.** `/profile/[username]` for public-facing profiles where the point is *lookup-by-id* and the data returned is intentionally public (username, avatar, public bio). **Mitigation:** detect public-data-exposure handlers (small, non-sensitive response shapes, no PII beyond already-public data).

5. **Development-only unprotected routes.** Many apps have `/api/dev/*` or debug endpoints gated by `NODE_ENV === 'development'`. **Mitigation:** detect the env-gate; flag only if the gate is missing or misconfigured (e.g., checks `NEXT_PUBLIC_DEBUG` — client-controllable!).

6. **RSC / server-component data fetching in Next.js.** A server component that fetches data without an explicit auth check may actually be protected by the page-layer middleware. **Mitigation:** trace from the middleware matcher down to the route tree; only flag when the server component does a mutation or accesses multi-tenant data.

7. **GraphQL and tRPC procedure-level auth.** Individual resolvers/procedures may appear unprotected but inherit from a base `protectedProcedure`. **Mitigation:** detect the tRPC router composition or GraphQL middleware chain before flagging.

**FP-budget discipline:** findings in this concern should carry a `confidence` field (0.0–1.0). Findings below 0.5 confidence should be demoted to "worth reviewing" rather than surfaced as actionable. Findings above 0.9 confidence should gate tier compliance. The confidence number drives which report band (Critical/High → Worth reading → If you graduate) each finding lands in.

---

## Remediation patterns

Auth fixes are unusually dangerous. Unlike adding a security header or escaping an output, auth fixes can lock users out, break active sessions, or — worst case — introduce a new vulnerability while closing another. The scope doc's destructive-action overrides list specifically calls out "Auth logic changes — Never auto — always inline, detailed rationale." Good rule. Here's how each remediation class should be routed.

**STAGE (pending/ review; destructive-ish but mechanical):**
- **Adding auth middleware to an unprotected admin route.** Risk: if the route was intentionally public for operational reasons (emergency access, incident recovery), suddenly gating it locks out legitimate users. Stage the fix with a prominent "this may lock out users currently relying on this route being open — verify before applying" warning. Generate the fix as a diff against `middleware.ts` / `proxy.ts` matcher config, not as an inline handler edit.
- **Adding RLS policies to a Supabase table without RLS.** Stage because: (a) RLS enabled + no policies = total lockout for non-service-role clients, (b) adding policies requires understanding the actual access pattern (per-user vs per-tenant vs role-based), and (c) the fix should be applied as a migration, not a live-table change.
- **Tightening Firestore rules from permissive to scoped.** Stage — same reasoning; rules changes can break production reads/writes immediately.
- **Rotating/setting `NEXTAUTH_SECRET` or equivalent JWT secret.** Stage and warn: "this invalidates all active sessions." Scope doc says JWT/session secret regen is "never auto" — agree. Inline with ops-checklist for coordination.

**INLINE (detailed architectural proposal; never auto):**
- **IDOR fix requiring ownership-check insertion.** Must be inline because: the correct ownership check is context-specific (is it `userId`, `tenantId`, `ownerId`, nested through an organization table?), and getting it wrong creates a new vulnerability. Vibe Sec should propose the check with a clear rationale, show the exact AST-level diff, explain which tests should exist before merging, and route to `/vibe-test:generate` for the corresponding authorization behavioral tests.
- **Role-hardcoding refactor to a permission system.** Architectural. This is a multi-file change that touches every authorization site. Vibe Sec should propose: (a) the permission model (Casbin model+policy files, or Cerbos resource+policy YAML, or a centralized `hasPermission(user, action, resource)` helper), (b) the list of sites to refactor, (c) a migration path (refactor incrementally, not all-at-once), and (d) the tests to add. Offer the builder the choice of policy library.
- **Migrating from JWT-in-localStorage to HttpOnly-cookie-session.** Architectural. Affects the auth flow, the client, the server, and likely the deployment config.
- **Adding refresh-token rotation to an access-token-only JWT setup.** Architectural. Needs a revocation mechanism and a rotation policy.
- **Adding passkey/WebAuthn support.** Architectural at the "if you graduate" tier band. Not something Vibe Sec auto-fixes — it points the builder at a migration path and the right library (SimpleWebAuthn is the reference implementation for Node; most auth providers now have native support).

**AUTO (high-confidence, non-destructive):**
- **Adding a missing `auth()` call inside a Next.js Server Action.** When Vibe Sec detects a Server Action that mutates data but never invokes `auth()`, and the surrounding file already imports from `@/auth` (i.e., the pattern is established elsewhere), auto-add the check. Still surface the diff clearly; never silently patch.
- **Setting cookie `Secure` / `HttpOnly` / `SameSite` flags in an auth config.** These are additive hardening; auto-apply at production-config level.
- **Removing a hardcoded JWT secret fallback.** When config shows `process.env.JWT_SECRET || 'dev-fallback-insecure'`, auto-remove the fallback and add a clear runtime assertion that the env var must be set.
- **Setting session `maxAge` when missing from config.** Auto-add a sensible default (24h for access, 30d for refresh) with a comment explaining the choice.

**DEFERRED (never Vibe Sec's job):**
- **Actual secret rotation.** Vibe Sec detects stale/leaked secrets and surfaces the rotation runbook; it does not execute the rotation (that involves cloud console actions, coordination with deployed services, and rollout sequencing).
- **Breaking session storage changes.** Never auto — always an architectural conversation.

---

## Pattern #13 complements

The scope doc's "plays well with" list is where Vibe Sec admits it's not going to re-implement the world. For auth specifically, the complements matter because authz is the domain where specialist tools have the most value and Vibe Sec's job is to recommend the right one.

**For login/session/user management (replace manual auth entirely):**
- **Clerk** — best when: Next.js SaaS, want pre-built UI, speed-to-market matters, <10K MAU (generous free tier), builder values DX. Clerk gets auth working in 1–3 days with ~20 lines of code. Vibe Sec should recommend Clerk when it detects (a) Next.js project, (b) custom auth being scaffolded manually, (c) no enterprise SSO requirement, (d) no strict data-residency constraint.
- **Auth0 (Okta)** — best when: enterprise/regulated, SAML SSO needed, HIPAA/SOC2 compliance documentation needed, strict audit-log requirements. $0.07/MAU ceiling matters at scale. Vibe Sec should recommend Auth0 when it detects regulated-tier indicators (compliance mentions in docs, HIPAA-adjacent data patterns, enterprise customers).
- **Supabase Auth** — best when: already using Supabase, want auth bundled with RLS-based authorization, lean toward Postgres as the authorization engine. Cheapest at scale ($0.00325/MAU after 50K). Vibe Sec should recommend Supabase Auth when `@supabase/*` is already in `package.json`.
- **Firebase Auth** — best when: Firebase project, mobile-first, Google ecosystem. Still widely deployed but losing relative share to Supabase in new builds.
- **NextAuth/Auth.js v5** — best when: Next.js, want OSS/self-hosted, OK with more plumbing responsibility, DIY UI acceptable. No MAU cost. Vibe Sec should recommend Auth.js when the project is Next.js + already-custom auth that's broken; the migration is more mechanical than to Clerk.

**For authorization / policy engines (add on top of whatever auth library):**
- **Casbin** — best when: need flexibility across RBAC/ABAC/ReBAC, want the policy as code in files (GitOps), running on Node/Go/Python/Java/Rust, want embedded not API-based. File-based policy config is a strength for auditability.
- **Cerbos** — best when: want policy as a deployed service (not embedded), need centralized policy management across multiple services, ABAC-heavy use case, value hot-reloading of policy without redeploy. Weaker at ReBAC (hierarchical org trees).
- **OPA (Open Policy Agent) + Rego** — best when: polyglot stack (not just Node.js), already using OPA for infrastructure/Kubernetes policy, want the industry-standard policy language.
- **Oso** — simpler than OPA, good DX for app-layer authz; commercial-lean.
- **Permit.io / WorkOS FGA** — hosted policy-as-a-service, spanning RBAC/ABAC/ReBAC. Vibe Sec should recommend for teams that want authz-as-a-service rather than running their own policy engine.
- **Zanzibar-style (SpiceDB, Permit)** — best when: need Google-Drive-style sharing/ReBAC (fine-grained relationships between users and resources).

**For multi-tenant isolation specifically:**
- **Postgres RLS via Supabase or Neon** — the default recommendation for new multi-tenant Postgres apps. Enforces at the DB layer, defense in depth.
- **Firestore security rules with custom claims** — the default for Firebase multi-tenancy; recommend tenant-ID custom claims + rules that check `request.auth.token.tenantId == resource.data.tenantId`.
- **Prisma with Row-Level Security extensions / client extensions** — pattern-layer tenant injection for Prisma users who want RLS behavior without writing raw policies.

**For secret-based auth hardening:**
- **WebAuthn / SimpleWebAuthn** — passkey/passkey support reference implementation for Node.
- **Ory Kratos + Keto** — self-hosted IDP + authz combo; more operational weight than Clerk/Auth0 but full control.

**Vibe Sec's role here is curatorial, not comprehensive.** Recommend one or two options per situation with a clear "pick this one if X" rationale. The scope doc's design brief is "curated + boundary-expanding," not "exhaustive catalog."

---

## Tier applicability

Auth model static analysis is the single most tier-dependent concern Vibe Sec runs. The depth of the audit and the severity of findings both scale sharply with tier.

| Tier | Depth of auth audit | Critical findings vs. informational |
|---|---|---|
| **Prototype / hackathon** | Minimal. Is there any auth at all? If yes, rough-check library. No matrix audit. | Committed JWT secret → critical. Everything else → informational. |
| **Internal tool** | Moderate. Route inventory, basic admin-route check, library configuration basics. Matrix audit optional. | Unprotected admin route → high. Missing session timeout → medium. IDOR on internal routes → medium (internal network reduces blast radius). |
| **Public-facing** | Full. Route inventory + admin audit + session management + OAuth config review + basic IDOR scan. Threat model input. | Unprotected admin route → critical. Role-hardcoding → high. IDOR → high. Missing PKCE → high. |
| **Customer-facing SaaS** | Full + tenant isolation is *mandatory*. Every multi-tenant table must have RLS or rules. Every query must filter by tenant. | Tenant bleed → **critical**. IDOR → critical. Missing RLS on tenant tables → critical. Role-hardcoding → high. Missing refresh-token rotation → high. Missing MFA option → high. |
| **Regulated / enterprise** | Everything above + deep authz model review. Is the model expressed as policy? Is there an audit log for every authorization decision? Does revocation propagate? | Anything at lower tiers stays critical. Adds: missing SAML/SSO support → critical for enterprise sales. Missing audit logging of authz decisions → critical for SOC2/HIPAA. Missing session-revocation mechanism → critical. |

**The tier × concern applicability matrix** (per the scope's `/spec`-time output):
- **Route inventory:** Internal+ (matters starting at Internal)
- **Admin-endpoint protection:** Internal+
- **Tenant isolation:** Customer-facing-SaaS+ (below this, single-tenant is fine)
- **IDOR scan:** Public-facing+ (internal tools can accept some IDOR risk; public can't)
- **Session management pattern classification:** Internal+
- **Role-hardcoding detection:** Public-facing+ (below this, scale of authz is too small for the refactor to be worth it)
- **Passkey/WebAuthn availability assessment:** Public-facing+ (informational), Customer-facing-SaaS+ (should have)
- **Policy-as-code adoption:** Customer-facing-SaaS+ (informational), Regulated+ (should have)

**Multi-tenant isolation is Customer-facing-SaaS-critical.** This is the single most important statement in this brief. The difference between "authenticated" and "authorized" is the difference between "safe" and "one user sees another user's billing data." Vibe Sec's most valuable output for a SaaS app is a confident answer to "does every tenant-scoped query filter by tenant?" — and an audit that fails when the answer is no.

---

## Cross-concern dependencies

This concern overlaps with others in the Vibe Sec swarm. The synthesis step needs to reconcile these.

- **OWASP A01 (Broken Access Control):** This brief is the A01 core. Overlap with general A01 findings (missing ACLs on functions, force-browsing) is full.
- **OWASP A07 (Identification and Authentication Failures):** This brief covers the authentication half (session management, library configuration). Overlap with credential-specific findings (password complexity, credential stuffing resistance) belongs partly here, partly in a rate-limiting brief.
- **OWASP A04 (Insecure Design):** Policy-as-code adoption, zero-trust architecture posture, authz model soundness — these are A04 overlaps. The role-hardcoding finding lands in both A01 (because it creates broken access control) and A04 (because the design is brittle).
- **Rate limiting (separate brief):** Login endpoint brute-force protection, password-reset abuse, token-refresh abuse — these are auth surfaces that rate-limiting owns. Vibe Sec should detect them in the auth audit but defer the remediation to the rate-limiting brief.
- **Config posture (separate brief):** Cookie flags (HttpOnly, Secure, SameSite) — auth cares about them because they protect sessions; config cares about them as hardening. Emit findings in this brief, defer the generic-cookie-policy check to config posture.
- **Crypto / PII (separate brief):** Password hashing algorithm choice (bcrypt cost factor, argon2id parameters, scrypt vs. bcrypt vs. argon2), JWT signing algorithm (HS256 vs RS256 vs EdDSA), token-at-rest encryption — these are crypto concerns that surface in auth. Detect + defer.
- **Secret detection (separate brief):** Hardcoded `NEXTAUTH_SECRET`, `JWT_SECRET`, OAuth client secrets, Firebase admin SDK keys — detect in the auth audit (because we'll see them when we walk the auth config), defer the general "hardcoded-secret" finding to the secret-detection brief. The overlap is: auth cares because a leaked auth secret is catastrophic; secret-detection cares because it's a secret.
- **Supply chain (separate brief):** CVEs in auth libraries (CVE-2025-29927 for Next.js middleware, any JWT library CVEs, password-hashing library CVEs) — defer to SCA, but elevate priority on any dep-CVE that lands in the auth chain.
- **Vibe Test composition:** Per the gap-analysis schemas, `findings.jsonl` entries from this concern should carry `test_recommendation` fields for Vibe Test to elevate. Examples: an unprotected admin route → "behavioral test: unauthorized user gets 401"; an IDOR → "behavioral test: user A cannot read user B's resource"; a missing RLS → "behavioral test: cross-tenant query returns zero rows."

---

## Open questions for synthesis

These are the hard decisions the synthesis agent (or Este at `/spec` time) needs to resolve.

1. **Depth vs. false-positive tradeoff for IDOR scanning.** Industry data shows IDOR-like static analysis findings carry >50% FP rates. Vibe Sec's 12% across-the-board commitment is looser than Vibe Test's <5%, but IDOR alone could blow past it. Options: (a) ship IDOR detection at lower confidence and route findings to the "worth reviewing" band, not the critical band, (b) only emit IDOR findings for multi-tenant SaaS tier and above, (c) require a pattern-match gate (e.g., only flag when `:id` param goes directly into `findById`/`findUnique` with no intervening function call). **Recommendation:** combination of (b) + (c) — IDOR detection gated to Public-facing+ tier, and only at high-confidence patterns.

2. **Should Vibe Sec attempt dynamic route tracing, or stay strictly lexical?** Dynamic tracing (following a route handler into a service function, following that into a repository method, checking whether the repo method applies ownership filtering) would dramatically reduce FP rate but explodes complexity and risks brittleness on real codebases. **Recommendation:** stay lexical in v0.2. Handler-level analysis only. Flag "needs deeper review" when the handler clearly delegates to a service layer.

3. **How much should Vibe Sec opine on auth library choice?** The scope doc's "curated + boundary-expanding" design suggests Vibe Sec should *recommend* libraries, not just detect them. But recommendations have opinion cost — being wrong about "you should use Clerk here" burns trust. **Recommendation:** recommendations only in the "tier-inappropriate but if you graduate" band, not as critical findings. Detection stays factual; recommendation stays advisory.

4. **Passkey/WebAuthn — critical finding, recommendation, or silent?** As of 2026, passkeys are mainstream but not yet default-expected. For Public-facing tier, is "no passkey option" a finding? **Recommendation:** not a finding at Public-facing; informational at Customer-facing-SaaS; "should have" at Regulated. Revisit in v0.3 when adoption crosses ~80% of the top 1000 sites.

5. **How should Vibe Sec handle Server Actions specifically?** They're a Next.js-specific attack surface that most auth middleware doesn't cover. Worth a dedicated sub-probe? **Recommendation:** yes. The Next.js App Router is dominant enough in vibe-coded apps that Server Actions deserve a first-class detection path, with its own finding type (`auth.server-action.missing-check`).

6. **JWT vs session findings — how opinionated?** JWTs-in-localStorage is a recognizable anti-pattern. But some teams deliberately chose it with mitigations (CSP, short expiry). Should Vibe Sec flag it as critical, or surface it with mitigations inquiry? **Recommendation:** flag as high at Customer-facing-SaaS+, medium at Public-facing. Let the "suppress with reason" mechanism carry the team's rationale.

7. **Authorization matrix rendering.** Vibe Sec's signature auth deliverable is the authz matrix. How does it render in the three output channels (markdown, terminal banner, JSON sidecar)? Table in markdown (rows = routes, columns = "auth", "role", "ownership", "rls/rules", cells are colored status marks). Abbreviated in the terminal. Full structured object in JSON. **Recommendation:** confirm at `/spec` time with a concrete example from the WSYATM dogfood.

8. **CVE-2025-29927 (Next.js middleware bypass) handling.** Should this specific CVE be a built-in finding in v0.2 (since so many vibe-coded apps are Next.js)? **Recommendation:** yes — seed it as a baked-in rule in the auth brief, not relying solely on `npm audit` passthrough. Belt and suspenders.

9. **Handshake enrichment for Vibe Test.** Per the gap-analysis contracts, Vibe Sec emits `findings.jsonl` that Vibe Test reads to elevate test priorities. For auth findings, what's the minimal set of fields Vibe Test needs to generate a useful behavioral test? Proposed: `{ id, severity, surface (route), finding_type, expected_behavior (e.g., "401 for unauthenticated"), priority_elevation }`. **Recommendation:** confirm alignment with Vibe Test's `/vibe-test:generate` schema at `/spec` time.

10. **Living-docs re-run cadence for this brief.** Auth landscape shifts fast (passkey adoption numbers change quarterly, major CVEs drop every few months). How often should `/vibe-sec:research --concern auth-model` be re-run? **Recommendation:** quarterly by default, with a "new major CVE or new OWASP cheat sheet version" trigger. Feeds Pattern #14 wins log.

---

*End of brief. Durable reference for `/vibe-sec:audit` auth detection logic, `/vibe-sec:fix` remediation routing, `/vibe-sec:threat-model` actor enumeration, and `/vibe-sec:gate` tier thresholds. Re-run via `/vibe-sec:research --concern auth-model` to refresh landscape intel.*

## Sources

- [State of Passkeys 2026](https://state-of-passkeys.io/)
- [FIDO Alliance Passkey Index 2025](https://fidoalliance.org/passkey-index-2025/)
- [Passkeys Hit Critical Mass — Security Boulevard (March 2026)](https://securityboulevard.com/2026/03/passkeys-hit-critical-mass-microsoft-auto-enables-for-millions-87-of-companies-deploy-as-passwords-near-end-of-life/)
- [Descope — 50+ Customer Auth Stats for 2026](https://www.descope.com/blog/post/auth-stats-2026)
- [Dashlane Passkey Power 20 (2025)](https://www.dashlane.com/blog/passkey-report-2025)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide — IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP Microservice Security Cheat Sheet — Authorization Patterns (June 2025)](https://www.innoq.com/en/blog/2025/06/owasp-microservice-security-cheat-sheet-update-authorization-patterns/)
- [OAuth 2.1 — IETF Draft 15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OAuth 2.1 vs 2.0 — Stytch](https://stytch.com/blog/oauth-2-1-vs-2-0/)
- [OAuth 2.1 vs 2.0 — Descope](https://www.descope.com/blog/post/oauth-2-0-vs-oauth-2-1)
- [CVE-2025-29927 Next.js Middleware Authorization Bypass — ProjectDiscovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass)
- [Auth.js — Protecting Routes](https://authjs.dev/getting-started/session-management/protecting)
- [Next.js Middleware Authentication 2025 — HashBuilds](https://www.hashbuilds.com/articles/next-js-middleware-authentication-protecting-routes-in-2025)
- [Supabase Row Level Security Docs](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase RLS Multi-Tenant Guide — AntStack](https://www.antstack.com/blog/multi-tenant-applications-with-rls-on-supabase-postgress/)
- [Firebase Firestore Multi-Tenancy — KTree](https://ktree.com/blog/implementing-multi-tenancy-with-firebase-a-step-by-step-guide.html)
- [Firestore Real-time Updates with Tenant Isolation — Hotovo](https://www.hotovo.com/blog/firestore-real-time-updates-with-tenant-isolation)
- [Structuring Firestore Security Rules — Firebase](https://firebase.google.com/docs/firestore/security/rules-structure)
- [Clerk vs Auth0 vs Supabase Auth — DesignRevision](https://designrevision.com/blog/auth-providers-compared)
- [The Authentication Showdown: Auth0 vs Clerk vs Supabase — Startup Starter Kit](https://www.thestartupstarterkit.com/newsletter/2025-12-14-authentication-showdown)
- [v0 vs Lovable vs Bolt — NxCode 2026](https://www.nxcode.io/resources/news/v0-vs-bolt-vs-lovable-ai-app-builder-comparison-2025)
- [Apache Casbin](https://casbin.apache.org/)
- [Cerbos](https://www.cerbos.dev/)
- [Casbin vs Alternatives — AuthZed](https://authzed.com/blog/casbin)
- [IDOR Vulnerability Explained — Aikido](https://www.aikido.dev/blog/idor-vulnerability-explained)
- [Finding and Fixing IDORs in Python — Snyk](https://snyk.io/blog/insecure-direct-object-references-python/)
- [NIST SP 800-207 Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf)
- [Adopting Zero Trust in 2025 — Seraphic](https://seraphicsecurity.com/learn/zero-trust/adopting-zero-trust-in-2025-a-practical-guide/)
- [JWTs vs Sessions — Stytch](https://stytch.com/blog/jwts-vs-sessions-which-is-right-for-you/)
- [Please Don't Use JWTs for Browser Sessions — Ian London](https://ianlondon.github.io/posts/dont-use-jwts-for-sessions/)
