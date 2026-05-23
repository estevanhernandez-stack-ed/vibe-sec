// Detector → findings.jsonl mappers (spec §6; checklist 2.5).
//
// The detectors emit concern-shaped result objects; the handoff spine is the
// single `Finding` schema. These mappers translate each concern's output into
// Finding records the state writer persists, so /vibe-sec:scan and /vibe-sec:deps
// (and later :audit) all write the same line shape. Severity is the detector's
// base severity here; tier × concern × amplifier calibration happens in scoring
// when an audit assembles the weighted score — the per-command writers persist
// severity_base = severity_tier_adjusted until a tier is bound.
//
// IDs are deterministic per concern + content so re-runs overwrite rather than
// duplicate (the weighted-score reader dedupes by id).

import { makeFinding, type Finding } from "../state/findings.js";
import type { Concern, Severity, Tier, FixClass } from "../types.js";
import type { SecretFinding } from "./secrets/scan-tree.js";
import type { MergedDepFinding } from "./deps/dedupe.js";
import type { TyposquatFinding } from "./supply-chain/typosquat.js";
import type { ActionsFinding } from "./supply-chain/actions-parse.js";
import type { PinningFinding } from "./supply-chain/index.js";
import type { CorsFinding } from "./config-posture/cors.js";
import type { FirebaseRulesFinding } from "./config-posture/firebase-rules.js";
import type { PrimitiveFinding } from "./crypto-pii/primitives.js";
import type { PasswordHashFinding } from "./crypto-pii/password-hashing.js";
import type { JwtFinding } from "./crypto-pii/jwt-audit.js";
import type { ClientKeyLeak } from "./crypto-pii/pii-inventory.js";
import type { PiiLogFinding } from "./crypto-pii/pii-in-logs.js";
import type { AdminFinding } from "./auth-model/admin-audit.js";
import type { TenantFinding } from "./auth-model/tenant-isolation.js";
import type { IdorFinding } from "./auth-model/idor.js";
import type { SessionFinding } from "./auth-model/session.js";
import type { RoleHardcodeFinding } from "./auth-model/role-hardcoding.js";
import type { Cve202529927Result } from "./config-posture/cve-2025-29927.js";
import type { TaggedSurveyFinding } from "./owasp-survey/index.js";
import type { SsrfFinding } from "./owasp-survey/ssrf-shallow.js";
import type { DynamicCodeFinding } from "./owasp-survey/dynamic-code-sinks.js";
import { dualTag } from "./owasp-survey/dual-tag.js";
import type { LlmEndpointFinding } from "./rate-limiting/llm-endpoint.js";
import type { MiddlewareFinding } from "./rate-limiting/middleware.js";
import type { AbuseMonitoringFinding } from "./rate-limiting/abuse-monitoring.js";

const PUBLIC_FACING_TIERS = new Set<Tier>([
  "public-facing",
  "customer-facing-saas",
  "regulated",
]);
const CUSTOMER_FACING_TIERS = new Set<Tier>(["customer-facing-saas", "regulated"]);
const IDOR_BAND1_CONFIDENCE = 0.9;

let seq = 0;
function nextId(concern: string): string {
  seq += 1;
  return `${concern}-${seq.toString().padStart(3, "0")}`;
}

/** Reset the per-run id sequence (call once at command start for stable ids). */
export function resetFindingIds(): void {
  seq = 0;
}

// ─── secrets → findings ──────────────────────────────────────────────────
export function secretToFinding(s: SecretFinding, tier: Tier): Finding {
  const fixClass: FixClass = "inline"; // secret rotation is always inline
  return makeFinding({
    id: nextId("secret"),
    primary_concern: "secret-detection",
    severity_base: s.severity,
    severity_tier_adjusted: s.severity,
    confidence: 0.9,
    finding_type: s.pattern,
    title: `Possible secret: ${s.pattern}`,
    description: s.remediation,
    file: s.file,
    line: s.line,
    tier,
    fix_class: fixClass,
    tool_of_record: "in-house",
    owasp_2021: "A07",
    owasp_2025: "A07",
    references: ["OWASP-A07-2021"],
  });
}

// ─── dependency CVE → findings ───────────────────────────────────────────
export function depToFinding(d: MergedDepFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("dep"),
    primary_concern: "dependency-cve",
    severity_base: d.severity,
    severity_tier_adjusted: d.severity,
    confidence: 0.95,
    finding_type: "vulnerable-dependency",
    title: `${d.package}@${d.version} — ${d.id}`,
    description: d.summary || `${d.id} affects ${d.package}.`,
    file: null,
    line: null,
    tier,
    fix_class: d.fixClass,
    tool_of_record: d.sources.includes("osv-scanner") ? "osv-scanner" : "npm-audit",
    epss_score: d.cvss ? null : null, // EPSS hook unwired (Decision 13)
    owasp_2021: "A06",
    owasp_2025: "A06",
    references: [d.id, ...d.aliases].filter(Boolean),
  });
}

// ─── supply-chain → findings ─────────────────────────────────────────────
export function pinningToFinding(p: PinningFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("supply"),
    primary_concern: "supply-chain",
    severity_base: "low",
    severity_tier_adjusted: "low",
    confidence: 1,
    finding_type: "floating-version-pin",
    title: `Floating pin: ${p.package}@${p.range}`,
    description: `${p.package} uses a floating pin (${p.range}) — the resolved version drifts between installs. Pin to an explicit version.`,
    file: "package.json",
    line: null,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: "A08",
    owasp_2025: "A08",
    references: ["OWASP-A08-2021"],
  });
}

export function typosquatToFinding(t: TyposquatFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("supply"),
    primary_concern: "supply-chain",
    severity_base: "high",
    severity_tier_adjusted: "high",
    confidence: 0.7,
    finding_type: "possible-typosquat",
    title: `${t.package} resembles ${t.resembles} (distance ${t.distance})`,
    description: `${t.package} is within edit distance ${t.distance} of the popular package ${t.resembles}. Confirm this is the package you meant — typosquats are the #1 net-new npm malware vector.`,
    file: "package.json",
    line: null,
    tier,
    fix_class: "inline",
    tool_of_record: "in-house",
    owasp_2021: "A08",
    owasp_2025: "A08",
    references: ["OWASP-A08-2021"],
  });
}

export function actionsToFinding(a: ActionsFinding, tier: Tier): Finding {
  const isThirdParty = a.finding_type === "unpinned-third-party-action";
  const severity: Severity = isThirdParty ? "medium" : "low";
  return makeFinding({
    id: nextId("supply"),
    primary_concern: "supply-chain",
    severity_base: severity,
    severity_tier_adjusted: severity,
    confidence: 1,
    finding_type: a.finding_type,
    title: a.action ? `${a.action} not SHA-pinned` : "Workflow missing permissions block",
    description: a.detail,
    file: a.workflow,
    line: a.line,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: "A08",
    owasp_2025: "A08",
    references: ["OWASP-A08-2021"],
  });
}

// ─── config-posture → findings ───────────────────────────────────────────
export function corsToFinding(c: CorsFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("config"),
    primary_concern: "config-posture",
    severity_base: c.severity,
    severity_tier_adjusted: c.severity,
    confidence: 0.85,
    finding_type: c.finding_type,
    title: "CORS misconfiguration",
    description: c.detail,
    file: c.file,
    line: c.line,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: "A05",
    owasp_2025: "A05",
    references: ["OWASP-A05-2021"],
  });
}

export function firebaseRulesToFinding(f: FirebaseRulesFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("config"),
    primary_concern: "config-posture",
    severity_base: f.severity,
    severity_tier_adjusted: f.severity,
    confidence: 0.95,
    finding_type: f.finding_type,
    title: "Open Firebase Security Rule",
    description: f.detail,
    file: f.file,
    line: f.line,
    tier,
    fix_class: "inline", // authorization logic — never auto
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    references: ["OWASP-A01-2021"],
  });
}

// ─── crypto / PII → findings (concern #4) ────────────────────────────────
// Crypto findings tag A02-2021 (Cryptographic Failures), reclassified A04-2025.

export function primitiveToFinding(p: PrimitiveFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("crypto"),
    primary_concern: "crypto-pii",
    severity_base: p.severity,
    severity_tier_adjusted: p.severity,
    confidence: p.finding_type === "weak-hash-primitive" ? 0.8 : 0.9,
    finding_type: p.finding_type,
    title: `Weak crypto primitive: ${p.primitive}`,
    description: p.detail,
    file: p.file,
    line: p.line,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: "A02",
    owasp_2025: "A04",
    references: ["OWASP-A02-2021", "OWASP-A04-2025"],
  });
}

export function passwordHashToFinding(p: PasswordHashFinding, tier: Tier): Finding {
  // bcrypt cost-12 migration changes stored hashes → never auto.
  const fixClass: FixClass =
    p.finding_type === "plaintext-password-compare" ? "inline" : "stage";
  return makeFinding({
    id: nextId("crypto"),
    primary_concern: "crypto-pii",
    severity_base: p.severity,
    severity_tier_adjusted: p.severity,
    confidence: 0.85,
    finding_type: p.finding_type,
    title: `Password hashing: ${p.finding_type}`,
    description: p.detail,
    file: p.file,
    line: p.line,
    tier,
    fix_class: fixClass,
    tool_of_record: "in-house",
    owasp_2021: "A02",
    owasp_2025: "A04",
    references: ["OWASP-A02-2021", "OWASP-A04-2025"],
  });
}

export function jwtToFinding(j: JwtFinding, tier: Tier): Finding {
  // Adding an algorithms: constraint is auto-safe; secret regen is never auto.
  const fixClass: FixClass =
    j.finding_type === "jwt-verify-missing-algorithms" ? "auto" : "inline";
  return makeFinding({
    id: nextId("crypto"),
    primary_concern: "crypto-pii",
    secondary_concerns: ["auth-model"],
    severity_base: j.severity,
    severity_tier_adjusted: j.severity,
    confidence: 0.9,
    finding_type: j.finding_type,
    title: `JWT: ${j.finding_type}`,
    description: j.detail,
    file: j.file,
    line: j.line,
    tier,
    fix_class: fixClass,
    tool_of_record: "in-house",
    owasp_2021: "A02",
    owasp_2025: "A04",
    references: ["OWASP-A02-2021", "CWE-347"],
  });
}

export function clientKeyLeakToFinding(c: ClientKeyLeak, tier: Tier): Finding {
  return makeFinding({
    id: nextId("crypto"),
    primary_concern: "crypto-pii",
    secondary_concerns: ["secret-detection"],
    severity_base: c.severity,
    severity_tier_adjusted: c.severity,
    confidence: 0.75,
    finding_type: c.finding_type,
    title: `Client-bundle key leak: ${c.variable}`,
    description: c.detail,
    file: c.file,
    line: c.line,
    tier,
    fix_class: "inline", // rename + rotate — never auto
    tool_of_record: "in-house",
    owasp_2021: "A02",
    owasp_2025: "A04",
    references: ["OWASP-A02-2021"],
  });
}

export function piiLogToFinding(p: PiiLogFinding, tier: Tier): Finding {
  // PII-in-logs is dual-tagged A09 (logging failures) by the survey concern.
  return makeFinding({
    id: nextId("crypto"),
    primary_concern: "crypto-pii",
    secondary_concerns: ["owasp-survey"],
    severity_base: p.severity,
    severity_tier_adjusted: p.severity,
    confidence: 0.7,
    finding_type: p.finding_type,
    title: `PII in logs (${p.piiHint}) → ${p.sink}`,
    description: p.detail,
    file: p.file,
    line: p.line,
    tier,
    fix_class: "inline",
    tool_of_record: "in-house",
    owasp_2021: "A09",
    owasp_2025: "A09",
    references: ["OWASP-A09-2021", "GDPR-Art-44"],
  });
}

// ─── auth-model → findings (concern #8 — the signature concern) ───────────
// A01 (Broken Access Control) / A07 (Auth Failures), no 2025 reclassification.

export function adminToFinding(a: AdminFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("auth"),
    primary_concern: "auth-model",
    secondary_concerns: ["owasp-survey"],
    severity_base: a.severity,
    severity_tier_adjusted: a.severity,
    confidence: 0.85,
    finding_type: a.finding_type,
    surface: a.route,
    title: a.finding_type === "admin-route-no-auth" ? "Unauthenticated admin route" : "Admin route without role gate",
    description: a.detail,
    file: a.file,
    line: a.line,
    tier,
    fix_class: "stage", // auth-middleware/role-gate adds stage minimum, never auto
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    cwe: "CWE-862",
    test_recommendation: "behavioral test: non-admin access returns 403",
    priority_elevation: a.severity,
    references: ["OWASP-A01-2021", "CWE-862"],
  });
}

export function tenantToFinding(t: TenantFinding, tier: Tier): Finding {
  // Supabase/Firestore tenant gaps are tenant isolation — Customer-facing-critical.
  const isRls =
    t.finding_type === "supabase-table-without-rls" ||
    t.finding_type === "supabase-rls-policy-true" ||
    t.finding_type === "firestore-permissive-rule";
  // Tier scaling: RLS gaps stay Critical at Customer-facing+; below that they're
  // still serious but the gate is binary at Customer-facing-SaaS (spec §2.4).
  const adjusted: Severity =
    isRls && !CUSTOMER_FACING_TIERS.has(tier) && t.severity === "critical"
      ? "high"
      : t.severity;
  return makeFinding({
    id: nextId("auth"),
    primary_concern: "auth-model",
    secondary_concerns: ["owasp-survey", "config-posture"],
    severity_base: t.severity,
    severity_tier_adjusted: adjusted,
    confidence: isRls ? 0.95 : 0.8,
    finding_type: t.finding_type,
    surface: t.subject,
    title: `Tenant isolation: ${t.finding_type}`,
    description: t.detail,
    file: t.file,
    line: t.line,
    tier,
    fix_class: isRls ? "stage" : "inline", // RLS as a migration; query fix inline
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    cwe: "CWE-639",
    references: ["OWASP-A01-2021", "CWE-639"],
  });
}

/**
 * IDOR mapper — Decision 18. Returns a Finding only when the IDOR qualifies as a
 * Band-1 finding: confidence ≥0.9 AND tier ≥ Public-facing. Otherwise returns
 * null (the orchestrator surfaces it as a Band-2 "worth reviewing" note instead).
 */
export function idorToFinding(i: IdorFinding, tier: Tier): Finding | null {
  if (i.confidence < IDOR_BAND1_CONFIDENCE) return null;
  if (!PUBLIC_FACING_TIERS.has(tier)) return null;
  return makeFinding({
    id: nextId("auth"),
    primary_concern: "auth-model",
    secondary_concerns: ["owasp-survey"],
    severity_base: "high",
    severity_tier_adjusted: "high",
    confidence: i.confidence,
    finding_type: i.finding_type,
    surface: i.subject,
    title: "Insecure direct object reference (IDOR)",
    description: i.detail,
    file: i.file,
    line: i.line,
    tier,
    fix_class: "inline", // ownership-check insertion — always inline
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    cwe: "CWE-639",
    references: ["OWASP-A01-2021", "CWE-639"],
  });
}

export function sessionToFinding(s: SessionFinding, tier: Tier): Finding {
  const fixClass: FixClass =
    s.finding_type === "jwt-in-web-storage" ? "inline" : "stage";
  return makeFinding({
    id: nextId("auth"),
    primary_concern: "auth-model",
    secondary_concerns: ["config-posture"],
    severity_base: s.severity,
    severity_tier_adjusted: s.severity,
    confidence: 0.8,
    finding_type: s.finding_type,
    title: `Session handling: ${s.finding_type}`,
    description: s.detail,
    file: s.file,
    line: s.line,
    tier,
    fix_class: fixClass,
    tool_of_record: "in-house",
    owasp_2021: "A07",
    owasp_2025: "A07",
    references: ["OWASP-A07-2021"],
  });
}

export function roleHardcodingToFinding(r: RoleHardcodeFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("auth"),
    primary_concern: "auth-model",
    secondary_concerns: ["owasp-survey"],
    severity_base: "medium",
    severity_tier_adjusted: "medium",
    confidence: 0.7,
    finding_type: r.finding_type,
    title: `Role checks scattered across ${r.fileCount} files`,
    description: r.detail,
    file: r.sites[0]?.file ?? null,
    line: r.sites[0]?.line ?? null,
    tier,
    fix_class: "inline", // policy-engine refactor — architectural
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    references: ["OWASP-A01-2021"],
  });
}

// ─── owasp-survey → findings (concern #3) ────────────────────────────────
// Every survey finding carries BOTH owasp_2021 and owasp_2025 (Decision 3).

export function surveyToFinding(s: TaggedSurveyFinding, tier: Tier): Finding {
  // Dynamic A03/A09 survey findings stage; the rest are advisory/stage by class.
  const fixClass: FixClass = s.category === "A09" ? "advisory" : "stage";
  const refs = [`OWASP-${s.tags.owasp_2021}-2021`];
  if (s.tags.reclassified) refs.push(`OWASP-${s.tags.owasp_2025}-2025`);
  return makeFinding({
    id: nextId("owasp"),
    primary_concern: s.primary_concern,
    secondary_concerns: s.secondary_concerns,
    severity_base: s.severity,
    severity_tier_adjusted: s.severity,
    confidence: s.confidence,
    finding_type: s.finding_type,
    title: `OWASP ${s.tags.owasp_2021}: ${s.finding_type}`,
    description: s.tags.shiftNote ? `${s.detail} (${s.tags.shiftNote})` : s.detail,
    file: s.file,
    line: s.line,
    tier,
    fix_class: fixClass,
    tool_of_record: "in-house",
    owasp_2021: s.tags.owasp_2021,
    owasp_2025: s.tags.owasp_2025,
    references: refs,
  });
}

export function ssrfToFinding(s: SsrfFinding, tier: Tier): Finding {
  // SSRF: A10-2021 → A01-2025 (the reclassification worth teaching).
  const tags = dualTag("A10");
  return makeFinding({
    id: nextId("owasp"),
    primary_concern: "owasp-survey",
    severity_base: s.severity,
    severity_tier_adjusted: s.severity,
    confidence: s.confidence,
    finding_type: s.finding_type,
    title: "Shallow SSRF — user-controlled outbound URL",
    description: `${s.detail} (${tags.shiftNote})`,
    file: s.file,
    line: s.line,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: tags.owasp_2021,
    owasp_2025: tags.owasp_2025,
    cwe: "CWE-918",
    references: ["OWASP-A10-2021", "OWASP-A01-2025", "CWE-918"],
  });
}

export function dynamicCodeToFinding(d: DynamicCodeFinding, tier: Tier): Finding {
  const tags = dualTag("A08");
  return makeFinding({
    id: nextId("owasp"),
    primary_concern: "owasp-survey",
    severity_base: d.severity,
    severity_tier_adjusted: d.severity,
    confidence: 0.6,
    finding_type: d.finding_type,
    title: `Dynamic code-execution sink (${d.sinkKind})`,
    description: d.detail,
    file: d.file,
    line: d.line,
    tier,
    fix_class: "inline", // review-required, never auto (synthesis §3.3)
    tool_of_record: "in-house",
    owasp_2021: tags.owasp_2021,
    owasp_2025: tags.owasp_2025,
    cwe: "CWE-95",
    references: ["OWASP-A08-2021", "CWE-95"],
  });
}

/**
 * CVE-2025-29927 joint finding (Decision 6). Fires ONCE: primary=auth-model,
 * secondaries=[dependency-cve, config-posture, owasp-survey]. Returns null when
 * the project isn't on a vulnerable next version.
 */
export function cve202529927ToFinding(c: Cve202529927Result, tier: Tier): Finding | null {
  if (!c.vulnerable) return null;
  return makeFinding({
    id: "auth-cve-2025-29927", // stable id — fires once, dedupes on re-run
    primary_concern: "auth-model",
    secondary_concerns: ["dependency-cve", "config-posture", "owasp-survey"],
    severity_base: "critical",
    severity_tier_adjusted: "critical",
    confidence: 0.98,
    finding_type: "cve-2025-29927-middleware-bypass",
    title: "CVE-2025-29927 — Next.js middleware authorization bypass",
    description: c.detail ?? "next is on a version vulnerable to the x-middleware-subrequest bypass.",
    file: "package.json",
    line: null,
    tier,
    fix_class: "stage", // dep bump + defense-in-depth note
    tool_of_record: "in-house",
    owasp_2021: "A01",
    owasp_2025: "A01",
    cwe: "CWE-285",
    references: ["CVE-2025-29927", "OWASP-A01-2021", "CWE-285"],
  });
}

// ─── rate-limiting → findings (concern #7) ───────────────────────────────
// Dual A04 (Insecure Design) + A09 (Logging Failures) tagging on rate-limit gaps.

/**
 * LLM-endpoint mapper — the one tier-override (Decision 5):
 *   - unauthenticated LLM endpoint → Critical at EVERY tier, including Prototype.
 *   - authenticated-but-unbounded  → tier-gated: Critical at Customer-facing+,
 *     High at Public-facing, Low (informational) below (Conflict 1 = A).
 */
export function llmEndpointToFinding(l: LlmEndpointFinding, tier: Tier): Finding {
  let severity: Severity;
  if (l.finding_type === "llm-endpoint-unauthenticated") {
    severity = "critical"; // the override — every tier
  } else {
    // authenticated but unbounded — tier-gated.
    severity = CUSTOMER_FACING_TIERS.has(tier)
      ? "critical"
      : tier === "public-facing"
        ? "high"
        : "low";
  }
  return makeFinding({
    id: nextId("rate"),
    primary_concern: "rate-limiting",
    secondary_concerns: ["owasp-survey"],
    severity_base: l.finding_type === "llm-endpoint-unauthenticated" ? "critical" : "high",
    severity_tier_adjusted: severity,
    confidence: 0.85,
    finding_type: l.finding_type,
    title:
      l.finding_type === "llm-endpoint-unauthenticated"
        ? `Unauthenticated LLM endpoint (${l.sdk})`
        : `Unbounded LLM endpoint — no per-user budget (${l.sdk})`,
    description: l.detail,
    file: l.file,
    line: l.line,
    tier,
    fix_class: "inline", // LLM token-budget middleware add — architectural
    tool_of_record: "in-house",
    owasp_2021: "A04",
    owasp_2025: "A04",
    references: ["OWASP-A04-2021", "OWASP-A09-2021"],
  });
}

export function middlewareToFinding(m: MiddlewareFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("rate"),
    primary_concern: "rate-limiting",
    secondary_concerns: ["owasp-survey"],
    severity_base: m.severity,
    severity_tier_adjusted: m.severity,
    confidence: 0.7,
    finding_type: m.finding_type,
    title: `Rate limiting: ${m.finding_type}`,
    description: m.detail,
    file: m.file,
    line: m.line,
    tier,
    fix_class: m.finding_type === "in-memory-rate-limit-store" ? "stage" : "advisory",
    tool_of_record: "in-house",
    owasp_2021: "A04",
    owasp_2025: "A04",
    references: ["OWASP-A04-2021", "OWASP-A09-2021"],
  });
}

/**
 * Library-absence finding (project level). Tier-gated: mandatory (auth routes) at
 * Public-facing → High; below that it's a Low signal. Returns null at Prototype
 * (rate limiting is dropped from scope there, except the LLM override).
 */
export function rateLimitAbsentToFinding(tier: Tier): Finding | null {
  if (tier === "prototype") return null;
  const severity: Severity = PUBLIC_FACING_TIERS.has(tier) ? "high" : "low";
  return makeFinding({
    id: "rate-no-limiter",
    primary_concern: "rate-limiting",
    secondary_concerns: ["owasp-survey"],
    severity_base: "medium",
    severity_tier_adjusted: severity,
    confidence: 0.75,
    finding_type: "no-rate-limit-library",
    title: "No rate-limit library detected",
    description:
      "The app exposes routes but no rate-limit library is present. Auth and abuse-prone endpoints (login, signup, password reset, anything expensive) can be hammered. Add a limiter — platform-native at Public-facing+, framework-generic below.",
    file: null,
    line: null,
    tier,
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: "A04",
    owasp_2025: "A04",
    references: ["OWASP-A04-2021", "OWASP-A09-2021"],
  });
}

export function abuseMonitoringToFinding(a: AbuseMonitoringFinding, tier: Tier): Finding {
  return makeFinding({
    id: nextId("rate"),
    primary_concern: "rate-limiting",
    secondary_concerns: ["owasp-survey"],
    severity_base: "low",
    severity_tier_adjusted: "low",
    confidence: 0.6,
    finding_type: a.finding_type,
    title: "Rate limiting without monitoring",
    description: a.detail,
    file: a.file,
    line: a.line,
    tier,
    fix_class: "advisory",
    tool_of_record: "in-house",
    owasp_2021: "A09",
    owasp_2025: "A09",
    references: ["OWASP-A04-2021", "OWASP-A09-2021"],
  });
}
