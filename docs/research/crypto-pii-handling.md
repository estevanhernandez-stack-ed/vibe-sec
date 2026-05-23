# Crypto + PII Handling — Research Brief

**Concern:** OWASP A02 (Cryptographic Failures) + data-protection exposure in vibe-coded apps
**Author:** Domain-research agent (cryptography + data-protection persona)
**Written:** 2026-04-20
**Status:** Durable living doc — re-run via `/vibe-sec:research --concern crypto-pii-handling` as NIST guidance and enforcement trends evolve.
**Target release:** Vibe Sec v0.2

---

## Landscape

Crypto-and-PII is the second-most-expensive category in the OWASP Top 10 — only A01 Broken Access Control racks up more incidents, and A02 dominates the regulatory-fine tail. Vibe-coded apps are specifically vulnerable because the LLM's "shortest path to a working demo" silently selects the crypto primitive most cited in training data, and that bias skews old: MD5 still appears in sample code, bcrypt at cost factor 10 is the modal answer to "hash this password," and AES-CBC without a MAC is a surprisingly common emission for "encrypt this." The stack moved on; the LLM's muscle memory did not.

### Password hashing — 2025-2026 state of play

**Argon2id is the ceiling.** OWASP's Password Storage Cheat Sheet and NIST SP 800-63B-4 (final 2024, effective 2025) both name Argon2id as the preferred scheme. OWASP parameter sets: `m=47104 (46 MiB), t=1, p=1` or `m=19456 (19 MiB), t=2, p=1` — memory-hardness over iteration count, exploiting the fact that GPU/ASIC crackers struggle with memory-bound work.

**bcrypt remains acceptable for legacy** but the floor moved from cost 10 to cost 12 in the current cheat sheet. `bcrypt.hash(password, 10)` is writing to the 2018 bar. bcrypt also silently truncates inputs beyond 72 bytes — a detection-worthy gotcha when the builder thinks a long passphrase is protective.

**scrypt** is acceptable when Argon2id isn't available. **PBKDF2-HMAC-SHA256** is the FIPS-compliance fallback and the only family member implementable in Node.js `crypto` with no dependency — matters on Cloudflare Workers and edge runtimes.

**NIST SP 800-63B-4 also changed the password UX contract.** Composition rules ("one uppercase, one digit, one symbol") are explicitly prohibited. Periodic rotation is prohibited unless compromise is suspected. Minimum length for password-only auth is 15 characters. Passwords must be screened against known-breached lists. An audit that ignores these policy signals is auditing to the 2015 bar.

### Symmetric encryption — authenticated or bust

**AES-256-GCM and ChaCha20-Poly1305 are the two defensible choices.** Both are AEAD — encrypt and authenticate in one primitive, eliminating the Encrypt-then-MAC composition traps of hand-rolled CBC. OWASP is explicit: GCM/CCM first; CTR or CBC only with a separately-implemented Encrypt-then-MAC.

**ChaCha20-Poly1305** is preferred on mobile/embedded (no AES hardware) and as a hedge against GCM's nonce-reuse fragility — same nonce twice under the same key leaks the auth key. Node.js code generating nonces from `Math.random()` or fixed literals is an auditable pattern.

**AES-CBC without a MAC, ECB in any form, DES, 3DES, and RC4 are dead.** NIST SP 800-131A Rev. 3 (draft October 2024) retires ECB as a confidentiality mode. SHA-1 is deprecated through 2030-12-31 and disallowed thereafter. The 112-bit → 128-bit minimum-security-strength transition also lands 2030-12-31, so 112-bit-strength primitives deserve a "graduating-soon" flag today.

### TLS floors

**PCI-DSS and HIPAA still accept TLS 1.2 as the floor.** TLS 1.3 is "strongly recommended," not yet mandatory. TLS 1.0/1.1 are explicitly prohibited for CHD in transit (PCI-DSS 4.2); Microsoft ended full support 2025-08-31. Practical implication for vibe-coded apps: TLS is usually inherited from the hosting platform (Vercel, Netlify, Cloudflare, Firebase Hosting) and is already modern. Audit risk is *internal* HTTP — admin endpoints on localhost tunneled via ngrok, service-to-service over `http://`, unauthenticated webhook receivers, and `secure: false` cookie flags promoted to production by copy-paste.

### PII regulatory boundaries

**GDPR:** any data identifying or linkable to a natural person — name, email, phone, IP, cookie/device identifiers, location, behavioral profiles. 2024-2025 enforcement moved beyond Big Tech: Spanish DPA fined a bank €6.2M for inadequate security, Italian DPA €5M against a utility for outdated customer data, Irish DPC €310M on LinkedIn (Oct 2024) and €530M on TikTok (May 2025). Cumulative GDPR fines crossed €5.88B by Jan 2025, and decisions increasingly cite *governance* failures, not just technical gaps.

**CCPA/CPRA:** information that "identifies, relates to, describes, is capable of being associated with... a particular consumer or household." Includes SSN, demographics, financial accounts, biometrics, browsing history. Carves out HIPAA-governed PHI.

**HIPAA:** 18 enumerated PHI identifiers — name, address, dates granular beyond year, phone, fax, email, SSN, MRN, account number, license, vehicle ID, device ID, URL, IP, biometric, photo, any other unique identifier — when combined with health data.

### Recent incidents that sharpen the bar

- **RockYou2024 (July 2024):** 9.9B unique plaintext passwords. Credential-stuffing attackers operate with a corpus of essentially every previously-breached password.
- **16B-credential leak (June 2025):** infostealer-log aggregation, signaling endpoint compromise → keychain → mass credential exposure as a routine distribution channel.
- **GitGuardian 2024 report:** 23M hardcoded secrets committed to GitHub in 2024, +25% YoY. Private repos were 8× more likely to contain plaintext credentials — builders treat private as "safe," the exact vibe-coded trap.
- **Mobile app analysis 2024:** 815K leaked hardcoded secrets across 156K apps, most App Store apps leak at least one. Client-bundled API keys and Firebase configs with service-account material are endemic.

---

## Detection mechanics

Seven detectable families, all static — regex, AST walks, and dependency-graph introspection. No dynamic analysis in v0.2.

### 1. Deprecated-crypto imports and call sites

Patterns: `crypto.createHash('md5'|'sha1')`, `crypto.createCipheriv('des-*'|'3des-*'|'aes-*-ecb', ...)`, the no-IV `crypto.createCipher(...)`, third-party `require('md5')` / `import md5 from 'md5'`, `CryptoJS.MD5 / .SHA1 / .DES / .TripleDES`, `new NodeRSA(...)` with modulus < 2048. Python equivalents: `hashlib.md5/sha1`, `Crypto.Cipher.DES / ARC4`, `Crypto.Cipher.AES.MODE_ECB`.

**AST walk beats regex** — a legitimate `"md5"` string literal used as a cache-key identifier shouldn't trip. Match `CallExpression` nodes where the callee resolves to a known weak-primitive API.

**Key-length introspection:** `crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })` is a finding. `aes-128-*` at Customer-facing+ warrants a graduation note (128-bit AES is still 128-bit-strength, but NIST's 2030 transition makes 256-bit the forward default).

### 2. Password-handling patterns

The question is never "do they hash" — it's "with what, configured how, compared how."

Positive indicators (hashing *exists*): imports of `bcrypt`, `bcryptjs`, `argon2`, `@node-rs/argon2`, `@node-rs/bcrypt`, `scrypt`, `crypto.pbkdf2`, `crypto.scrypt`; schema fields named `password`, `hashedPassword`, `passwordHash`, `password_digest`; route handlers at `/login`, `/signin`, `/register`, `/auth/*`.

Algorithm + config extraction:

- `bcrypt.hash(password, N)` — cost < 12 finding at Public-facing+; < 10 Critical anywhere.
- `argon2.hash(..., { memoryCost, timeCost, parallelism })` — extract and compare to OWASP profile.
- `crypto.pbkdf2(password, salt, iterations, ...)` — < 600,000 iterations for SHA-256 is below the OWASP 2023+ floor.
- `crypto.scrypt(..., 64, { N, r, p })` — `N < 2^17` is a finding.

Critical anti-patterns:

- `crypto.createHash('sha256').update(password).digest(...)` — unsalted SHA-256 of password. Most common LLM emission for "secure password storage." Always Critical.
- `password === storedPassword` — plaintext compare. Always Critical.
- `btoa(password)` / `Buffer.from(password).toString('base64')` — "encryption" by encoding. Always Critical, amusingly common.
- `crypto.createCipheriv(...)` applied to passwords with a hardcoded key — reversible encryption instead of hashing. Always Critical.

**Timing-attack check:** `storedHash === incoming` is timing-leaky. Bar is `crypto.timingSafeEqual(a, b)` or `bcrypt.compare(plain, hash)`. Equality compares against variables matching `password|hash|token|secret` → High.

### 3. Hardcoded crypto keys and env-var usage

Detectable literal patterns:

- String literals ≥32 chars of hex/base64 assigned to variables matching `*_KEY|*_SECRET|*_TOKEN|JWT_SECRET|ENCRYPTION_KEY|AES_KEY`
- `new Uint8Array([...])` with 16/24/32 numeric-literal bytes passed to a cipher constructor
- PEM blocks (`-----BEGIN ... PRIVATE KEY-----`) embedded in `.js`/`.ts`/`.py` source
- Imports from a local `./keys.js` / `./constants/crypto.ts` exporting key material (indirection doesn't redeem it)

Positive — env-var read: `process.env.*`, `os.environ[...]`, `Deno.env.get(...)`, `import.meta.env.*` (Vite), config-library reads.

**Fallback trap:** `process.env.JWT_SECRET || 'dev-secret-change-me'` — the literal becomes the production key when the env var isn't set. Accounts for a large fraction of real-world JWT-forgery incidents; flag High anywhere, Critical at Public-facing+.

**Client-side leakage:** any key literal or env-var read inside `src/`, `app/`, `pages/`, `components/`, `client/` in Next.js / Remix / SvelteKit / Vite projects. `NEXT_PUBLIC_*` and `VITE_*` are *public by design* — crypto material under those prefixes is definitionally leaked to the browser.

### 4. PII field inference from ORM schemas

Four schema systems cover ~95% of TS/JS vibe-coded apps: Prisma, Drizzle, Zod, Yup (plus Joi in older Node).

Stage 1 — parse schema:

- **Prisma** (`schema.prisma`): `model User { email String ... }` — regex-extractable or via `@prisma/internals`.
- **Drizzle** (`schema.ts`): `pgTable('users', { email: varchar('email', ...) })` — AST walk on `CallExpression` to `pgTable`/`mysqlTable`/`sqliteTable`.
- **Zod**: `z.object({ email: z.string().email() })` — AST walk on `z.object` calls.
- **Yup / Joi**: same AST pattern on `yup.object(...)` / `Joi.object(...)`.

Stage 2 — match field names against the PII pattern library (CCPA ∪ HIPAA ∪ GDPR practical union):

| Category | Match patterns (case-insensitive, word-boundary) |
|---|---|
| Name | `name`, `first_name`, `last_name`, `firstName`, `lastName`, `full_name`, `legal_name` |
| Contact | `email`, `phone`, `telephone`, `mobile`, `fax` |
| Address | `address`, `street`, `city`, `state`, `zip`, `postal`, `country` (when paired with other PII) |
| Government ID | `ssn`, `social_security`, `tax_id`, `ein`, `passport`, `license_number`, `national_id` |
| Financial | `card_number`, `cc_number`, `cvv`, `cvc`, `iban`, `swift`, `bank_account`, `routing_number`, `account_number` |
| Health | `medical_record`, `mrn`, `diagnosis`, `patient`, `prescription`, `insurance_id` |
| Digital identity | `ip_address`, `ip`, `device_id`, `mac_address`, `session_id`, `cookie`, `user_agent`, `fingerprint` |
| Geolocation | `geolocation`, `lat`, `lng`, `latitude`, `longitude`, `coordinates`, `gps` |
| Biometric | `biometric`, `fingerprint_hash`, `face_encoding`, `voice_print`, `retina` |
| Dates of concern | `dob`, `date_of_birth`, `birthdate`, `birthday` |

Emit a **PII Inventory** artifact: each detected field with schema location, category, and whether it's encrypted/hashed/marked-sensitive. The inventory feeds the crypto audit — a PII field stored in a column with no at-rest encryption indicator is a tier-scaling finding.

### 5. PII-in-logs detection

Grep-level, scoped to log call sites to control false positives.

Call sites: `console.log|info|debug|warn|error`, logger libraries (`logger.*`, `log.*`, `pino`, `winston`, `bunyan`, `debug`), Python (`print`, `logger.*`, `logging.*`), error trackers (`Sentry.captureException`, `datadog.log`, `LogRocket.captureMessage`).

Match logic — within the log call's argument list:

- Object-literal shorthand referring to a PII-pattern variable: `logger.info({ email, password })`
- Template-literal interpolation: `` `Login for ${email}` ``
- Direct variable reference where the name flows from a PII-schema-typed source: `console.log(req.body)` on a route handler receiving PII
- Full-request logging: `console.log(req)`, `app.use(morgan('combined'))` without field redaction on auth routes

Severity model: PII in `console.log` is Medium default, High on auth routes, **Critical if the sink is a third-party error tracker** (Sentry, LogRocket, Datadog, New Relic). Cross-border PII flow to a US-based tracker from an EU-user context is a GDPR Article 44 concern — flag it at Public-facing+.

### 6. HTTP endpoints serving sensitive traffic

Config-file inspection: `next.config.js` (missing HSTS in `headers`), `vite.config.ts` (`server.https` state cross-referenced with detected hosting platform), `express`/`fastify` apps (bare `app.listen` without a TLS-terminating platform detected), cookie-flag AST walks on `res.cookie(...)` call sites (`httpOnly`/`secure`/`sameSite` presence checks, `sameSite: 'none'` without `secure: true`).

Literal `http://` URLs (excluding `localhost`, `127.0.0.1`, `.test`, `.local`) in fetch calls, axios config, webhook registrations, OAuth redirects. Webhook receivers without signature-verification middleware (Stripe, GitHub, Slack, Twilio each have canonical signing schemes).

### 7. At-rest encryption gaps

Hardest to detect statically. Three proxies:

- **DB connection strings:** `sslmode=require` / `verify-full` for Postgres, `ssl=true` for MySQL. Absence at Customer-facing-SaaS+ is a finding; `sslmode=disable` is Critical at any tier.
- **ORM-layer encryption signals:** presence of `@prisma/field-encryption`, `@47ng/cloak`, `@cloak-app/crypto`, `sodium-native`, `libsodium-wrappers` is a positive credit. `node-forge` is ambiguous (often misused).
- **Cloud-storage config:** `serverless.yml`, `firebase.json`, `supabase/config.toml`, `wrangler.toml` — bucket definitions without encryption flags; S3 `PutObjectCommand` without `ServerSideEncryption`; Firebase Storage rules absent or `allow read, write: if true`.

---

## False-positive risks

Vibe Sec's 12% FP commitment puts this concern at higher-than-average risk — legitimate code routinely *looks* vulnerable. Disciplined exclusions:

- **Test fixtures with weak crypto intentionally.** Paths including `/test/`, `/tests/`, `/spec/`, `/__tests__/`, `/fixtures/`, `/examples/`, or filenames matching `*.test.*`, `*.spec.*`, `*.fixture.*` are downgraded.
- **Legacy-hash migration code.** Dual-path password verification (`if (user.passwordVersion === 1) bcrypt.compare(...) else argon2.verify(...)`) is the correct rehash-on-login pattern. Heuristic: if a weak-crypto call is in the same function as a strong-crypto call plus a conditional, treat as legitimate migration, emit informational asking the builder to confirm the migration is completing.
- **MD5/SHA1 as non-security checksums.** ETags, cache keys, content-addressed storage (Git uses SHA-1 for content addressing). Heuristic: if the hash output flows into an `etag` header, a filename, a cache key, a `contentHash`-style variable, or is compared `===` against another hash of the same algo (not a stored credential), emit informational with "confirm non-security use."
- **Field names that look like PII but aren't.** `publicName`, `displayName`, `displayEmail` (contact forms), `authorName`, `companyName`, `productName`. Heuristic: names starting with `public`, `display`, `company`, `product`, `brand`, `team`, `org` are downgraded unless the record *also* contains other PII fields.
- **Geolocation in legitimate-use contexts.** `lat`/`lng` on a restaurant-locations table is not PII. Downgrade if the record name matches `place|location|venue|restaurant|store|business|poi|landmark`.
- **IP in non-user contexts.** Firewall rules, allowlists, server-health checks. Downgrade when the record type matches `rule|allowlist|blocklist|firewall|health|server|node`.
- **Base64-looking strings that aren't keys.** Image data URIs, base64 assets, JWT payloads in tests. Require: variable-name key-match, ≥32 bytes decoded, not in a comment block.
- **PEM blocks in docs / README / fixtures.** Path-exclude `*.md`, `README*`, `CHANGELOG*`, `docs/`, `examples/`.
- **Dev/test env fallbacks.** `process.env.JWT_SECRET || 'test-only'` inside a `NODE_ENV === 'test'` branch is legitimate. If the fallback sits inside a conditional on `NODE_ENV`, `CI`, or `import.meta.env.DEV`, downgrade to informational.

---

## Remediation patterns

Maps to `/vibe-sec:fix` confidence-tier routing (auto ≥0.90 / stage 0.70–0.89 / inline <0.70) with destructive-action overrides from scope.md.

| Finding | Fix type | Conf. | Routing |
|---|---|---|---|
| MD5/SHA1 for non-security checksum | Swap to SHA-256 | 0.75 | Stage — may break ETag or migration hash-match |
| MD5/SHA1 for password or signature | Hashing-migration path | 0.35 | **Inline** — destructive, requires rehash-on-login |
| Unsalted `sha256(password)` | Replace with bcrypt/argon2 + migration | 0.35 | **Inline** — destructive |
| bcrypt cost < 12 | Increase to 12 | 0.85 | Stage — safe forward, verify perf under load |
| Plaintext password `===` compare | `bcrypt.compare` / `timingSafeEqual` | 0.90 | Auto after builder confirms stored value is a hash |
| Hardcoded crypto key literal | Literal → `process.env.*` read + `.env.example` stub | 0.88 | Stage — builder must populate env and rotate leaked key |
| JWT secret `\|\|` fallback literal | Remove fallback, fail-fast at boot | 0.92 | Auto — removes silent-fallback hazard |
| Leaked secret in git history | Rotation checklist + `git-filter-repo` advisory | N/A | **Inline always** — rotation is irreversible ops work |
| AES-CBC without MAC | Swap to AES-GCM | 0.60 | Stage — ciphertext format changes; data migration |
| ECB mode | Swap to GCM | 0.55 | Stage — same |
| `secure: false` cookie | Set `true` in prod branch | 0.90 | Auto in a prod-branched config path |
| Missing `httpOnly`/`sameSite` | Add flags | 0.92 | Auto |
| PII in `console.log` | Remove or add structured redaction | 0.70 | Stage — builder confirms log-safe fields |
| PII field at Customer-facing-SaaS+ w/ no at-rest encryption | App-layer encryption library advisory | 0.50 | Inline — architectural |
| HTTP auth endpoint (not localhost) | Advisory + config diff | 0.60 | Stage — hosting-platform dependent |
| TLS 1.0/1.1 allowed server-side | Raise to 1.2+ | 0.85 | Stage |
| Missing webhook signature verification | Platform-specific signing middleware template | 0.75 | Stage |

**Hard destructive-action overrides:**
- **Password-rehash migration is always inline.** Even at 99% confidence the old hashes are MD5, the migration touches live user records. Advisory includes the dual-read / rehash-on-login skeleton; the builder executes.
- **Leaked-secret rotation is always inline.** Rotating a JWT secret invalidates live sessions; rotating a Stripe key requires dashboard work + coordinated deploy.
- **Key-material regeneration is always inline.** Same logic.

---

## Pattern #13 complements

Tools surfaced to the builder for post-audit "future runs":

- **Semgrep** — pattern-based SAST with mature crypto rule packs (`p/crypto`, `p/jwt`, `p/owasp-top-ten`). Catches idiomatic misuse regex won't. Free tier covers most vibe-coded repos.
- **Mozilla Observatory** — TLS-config grading (HSTS, CSP, cookie flags, cipher suites). Note: the underlying `tls-observatory` scanner was archived Dec 2025, but the web service at observatory.mozilla.org remains operational.
- **testssl.sh** — local TLS scanner CLI; captures cipher-suite offerings, protocol versions, vulnerable extensions. Complements Observatory when the target isn't internet-reachable.
- **gitleaks** — regex-based secret scanning, TOML-configurable, 150+ built-in types. Scans git history natively; Vibe Sec's own scanner is working-tree-first.
- **TruffleHog** — secret scanner with *live credential verification* (pings the issuing API to confirm the secret is active). Useful for triage — a verified-live Stripe key in history is an incident, not a finding.
- **GitGuardian** — hosted commit-time secret detection. Overkill for solo vibe-coded until the team grows.
- **Snyk Code** — SAST with crypto rule coverage. Free tier for open source.
- **Microsoft Presidio** — open-source PII-detection, NER + regex for free-text PII (complements Vibe Sec's schema-field-name approach).
- **OWASP Dependency-Check** — flags crypto libraries with known CVEs (old `node-forge` with prototype-pollution, etc.). Overlaps with the dep-audit concern but with crypto-library specificity.
- **Mozilla SSL Configuration Generator** (ssl-config.mozilla.org) — reference generator used as target-state config when producing TLS remediation diffs.

---

## Tier applicability

| Tier | Crypto audit | PII audit |
|---|---|---|
| **Prototype (30%)** | Hardcoded secrets only. No primitive audit. | Off. |
| **Internal (55%)** | + Deprecated-primitive detection. Is *any* hashing used? Env-var usage. | Off-to-light — flag egregious cases (passwords in logs); no full inventory. |
| **Public-facing (70%)** | + AES-mode, TLS config, cookie flags, JWT-fallback detection. | **On.** Full schema PII inventory. PII-in-logs audit. Third-party-log-sink data-transfer flag. |
| **Customer-facing SaaS (80%)** | + At-rest encryption (DB conn strings, bucket config, ORM-layer). Key-rotation. Webhook signatures. | + Cross-border data-flow (GDPR Art. 44). Retention-impl check. |
| **Regulated / enterprise (90%)** | + FIPS check (PBKDF2 vs Argon2id). NIST 800-131A Rev. 3 2030-floor readiness. Crypto-agility audit. | + HIPAA 18-identifier audit. GDPR Art. 30 processing record. DPIA trigger surface. |

**Crypto matters from Internal up. PII matters from Public-facing up. Full compliance-grade audit at Customer-facing-SaaS + Regulated.** Below Internal the floor is "don't leak the key"; above, the floor graduates quickly.

---

## Cross-concern dependencies

Heavy overlap with three Vibe Sec concerns — enumerated for the synthesis pass:

- **Secret detection (concern #2).** Crypto keys *are* secrets. **Split rule:** crypto-pii owns *semantics* (this literal is passed to `crypto.createCipheriv` — so it's a key, and we can reason about length/entropy); secret-detection owns *provenance* (this literal matches AWS-key regex — so it's AWS credentials). Both fire on the same line when applicable, with de-duplicated report entries.
- **Auth model static analysis (concern #8).** Password hashing, session-token signing, and JWT-secret handling are joint. **Split rule:** crypto-pii owns the primitive (algorithm, parameters, key source); auth-model owns the flow (validation on each request, logout invalidation, rotation). JWT-secret-fallback detection is joint.
- **OWASP A02 Cryptographic Failures (under concern #3).** This brief *is* the A02 rule set. The OWASP Top 10 pass treats it as source-of-truth and contributes category framing + cross-category scoring.

Lighter overlap: config-posture (concern #5) owns cookie/CORS/CSP but cookie flags touch crypto via TLS; rate-limiting (concern #7) affects severity calculus on password-hashing findings (strong rate-limiting partially mitigates weak hashes, but doesn't gate).

---

## Open questions for synthesis

1. **Severity inflection on legacy tolerance.** How tolerant of MD5/SHA1 in inherited 5-year-old code the builder just adopted? Vibe-coded-first positioning → low tolerance. Confirm.
2. **Self-hosted vs platform-delegated TLS.** Should the audit reach out (Mozilla Observatory API or testssl shell-out) or stay static? Recommend static for v0.2; surface Observatory/testssl as Pattern #13.
3. **PII field-name locale coverage.** Current library is English-biased. Spanish `nombre|apellido|correo|telefono` etc. won't match. Recommend English-only for v0.2, expand via `/vibe-sec:research` in v0.3.
4. **Third-party log-sink severity.** At Public-facing+, PII → Sentry/Datadog/LogRocket is a severe GDPR Art. 44 concern; at Internal it's informational. Recommend: scale strictly with tier, educational surface at Public-facing+.
5. **ORM-encryption-library positive-signal weight.** Does importing `@47ng/cloak` or `sodium-native` *credit* the audit? Recommend yes — credit against at-rest-encryption findings, but require per-PII-field wrapping for full clearance.
6. **PCI-DSS SAQ scope detection.** If card-number fields are detected, should Vibe Sec auto-escalate to PCI rules? Recommend: emit a *tier elevation* finding ("this codebase appears PCI-in-scope — consider Regulated tier"), defer full SAQ to concern #3 orchestration.
7. **Post-quantum readiness.** NIST finalized ML-KEM, ML-DSA, SLH-DSA in Aug 2024. PQC-migration advice for Regulated tier? Recommend: informational only for v0.2, full audit v0.3+. No vibe-coded app needs to front the 5-year PQC transition curve.
8. **Git-history secret scanning handoff.** Working-tree secret scan lives in concern #2. Does crypto-pii want specific history patterns (historic PEM-block commits)? Recommend: centralize all history work in concern #2; crypto-pii consumes via handshake.

---

*End of brief. Upstream sources: CCPA/CPRA, HIPAA 45 CFR §164.514, GDPR, NIST SP 800-63B-4 (2024 final), NIST SP 800-131A Rev. 3 (draft Oct 2024), OWASP Cryptographic Storage Cheat Sheet (live), OWASP Password Storage Cheat Sheet (live). Downstream consumers: detection-rule seed list for `src/scanner/crypto/`, PII-pattern library for `src/scanner/pii/`, remediation templates for `src/fixer/crypto-pii/`, severity-per-tier matrix for the synthesis pass.*
