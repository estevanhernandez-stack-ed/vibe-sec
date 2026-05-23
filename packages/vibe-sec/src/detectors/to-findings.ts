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
