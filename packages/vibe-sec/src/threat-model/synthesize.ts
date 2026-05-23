// Threat-model synthesis sink (concern #9; spec §4.9, synthesis §3.9; checklist 4.1).
//
// The sink node. Pure synthesis — runs LAST, never parallelized. It detects
// nothing: it consumes the tier classification + all nine other concerns'
// findings + Vibe Test covered-surfaces, reconstructs a lightweight DFD, places
// the three canonical trust boundaries, and walks STRIDE-per-element. DREAD
// prioritizes; LINDDUN overlays at Customer-facing+; attack trees cover the
// top-3 at Public-facing+ (top-5 at Regulated).
//
// Two output channels, consistent with Vibe Sec's three-channel pattern:
//   - Primary: Mermaid-in-markdown → docs/vibe-sec/threat-model.md
//   - Sidecar: Threat-Dragon-v2.5.0-compatible JSON → .vibe-sec/state/threat-model.json
//
// Locked Mermaid convention (synthesis §3.9, spec §4.9):
//   stadiums  = external entities
//   rectangles= processes
//   cylinders = data stores
//   hexagons  = third-parties
//   subgraphs = trust boundaries
//
// Tier applicability (Conflict 2 = C): stub at Prototype → lightweight at
// Internal (OPT-IN only, NOT auto-included in :audit) → full STRIDE+DREAD+
// attack-trees-top-3 at Public-facing → +LINDDUN at Customer-facing →
// +attack-trees-top-5 + pytm stub at Regulated.
//
// FP target is "threat relevance" not accuracy — every enumerated threat is a
// real class in principle; the question is whether it applies to THIS app at
// THIS tier. Tier-appropriate filtering is the final pass.

import { type Tier, type Concern } from "../types.js";
import type { Finding } from "../state/findings.js";
import type { Route } from "../detectors/auth-model/route-inventory.js";
import type { PiiField } from "../detectors/crypto-pii/pii-inventory.js";

// ─── STRIDE / DREAD / LINDDUN vocabulary ─────────────────────────────────────

export type StrideCategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information Disclosure"
  | "Denial of Service"
  | "Elevation of Privilege";

export const STRIDE_CATEGORIES: readonly StrideCategory[] = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
] as const;

/** LINDDUN privacy categories (Customer-facing+ overlay). */
export type LinddunCategory =
  | "Linking"
  | "Identifying"
  | "Non-repudiation"
  | "Detecting"
  | "Data Disclosure"
  | "Unawareness"
  | "Non-compliance";

/** DREAD dimensions, scored ordinal High/Med/Low → numeric for ordering. */
export type DreadLevel = "high" | "medium" | "low";

export interface DreadScore {
  damage: DreadLevel;
  reproducibility: DreadLevel;
  exploitability: DreadLevel;
  affectedUsers: DreadLevel;
  discoverability: DreadLevel;
  /** Sum of dimension weights (high=3, med=2, low=1), range 5..15. */
  total: number;
}

// ─── DFD element model (the lightweight internal representation) ──────────────

export type DfdShape =
  | "external-entity" // stadium
  | "process" // rectangle
  | "data-store" // cylinder
  | "third-party"; // hexagon

export interface DfdNode {
  id: string;
  label: string;
  shape: DfdShape;
  /** The trust boundary this node sits inside, if any. */
  boundary: string | null;
}

export interface DfdFlow {
  from: string;
  to: string;
  label: string;
}

export interface TrustBoundary {
  id: string;
  label: string;
}

export interface Dfd {
  boundaries: TrustBoundary[];
  nodes: DfdNode[];
  flows: DfdFlow[];
}

// ─── Threat records ──────────────────────────────────────────────────────────

export interface Threat {
  id: string;
  category: StrideCategory;
  /** The DFD element / boundary this threat applies to. */
  element: string;
  title: string;
  description: string;
  mitigation: string;
  /** Which concern owns the remediation (advisory when none). */
  remediationOwner: Concern | "advisory";
  /** Cross-reference to a real finding id when the threat is realized. */
  realizedByFinding: string | null;
  dread: DreadScore;
}

export interface PrivacyThreat {
  id: string;
  category: LinddunCategory;
  element: string;
  title: string;
  mitigation: string;
}

export interface AttackTree {
  /** Root attacker goal. */
  goal: string;
  /** Sub-goals → leaf exploits, kept shallow (2 levels) for readability. */
  branches: { subGoal: string; leaves: string[] }[];
}

// ─── Inventory inputs (what the synthesizer consumes) ────────────────────────

/** The inventory the sink node reads — assembled by :audit / :threat-model. */
export interface ThreatModelInput {
  tier: Tier;
  /** App / project display name for the document header. */
  appName: string;
  /** Route inventory from auth-model (#8) — the deepest input. */
  routes: readonly Route[];
  /** PII fields from crypto-pii (#4) — drives stores + the LINDDUN overlay. */
  piiFields: readonly PiiField[];
  /** Third-party integrations (from Vibe Test detected_stack or deps). */
  integrations: readonly string[];
  /** All findings from the other nine concerns, deduped by id. */
  findings: readonly Finding[];
  /**
   * Total routes the framework scanners detected, for the completeness check.
   * When omitted, completeness uses routes.length (assumes full coverage).
   */
  totalRoutesDetected?: number;
  /** Endpoints Vibe Test covered — informs Repudiation/Info-Disclosure realism. */
  coveredEndpoints?: readonly string[];
  /** Multi-tenant signal (from modifiers / tenant findings) → tenant boundary. */
  multiTenant?: boolean;
}

/** The completeness check result — fires the <90% banner. */
export interface CompletenessCheck {
  routeCoveragePct: number;
  /** True when coverage ≥ 90% — synthesis proceeds without the warning banner. */
  complete: boolean;
  /** The banner string when incomplete, else null. */
  banner: string | null;
}

export interface ThreatModelResult {
  tier: Tier;
  /** True at Prototype — the model is a stub, no synthesis ran. */
  isStub: boolean;
  completeness: CompletenessCheck;
  dfd: Dfd;
  boundaries: TrustBoundary[];
  threats: Threat[];
  /** DREAD-ordered top threats (top-10 at Public-facing+, top-3 lightweight). */
  prioritized: Threat[];
  /** LINDDUN privacy threats — Customer-facing+ only, else empty. */
  privacyThreats: PrivacyThreat[];
  /** Attack trees for the top-3 (Public-facing+) / top-5 (Regulated), else empty. */
  attackTrees: AttackTree[];
  /** Whether a pytm Python stub should be emitted (Regulated only). */
  pytmStub: boolean;
}

const COMPLETENESS_THRESHOLD = 0.9;

const DREAD_WEIGHT: Record<DreadLevel, number> = { high: 3, medium: 2, low: 1 };

const TIER_RANK: Record<Tier, number> = {
  prototype: 0,
  internal: 1,
  "public-facing": 2,
  "customer-facing-saas": 3,
  regulated: 4,
};

function atLeast(tier: Tier, floor: Tier): boolean {
  return TIER_RANK[tier] >= TIER_RANK[floor];
}

/**
 * Whether the threat model is AUTO-included in `/vibe-sec:audit` at a tier
 * (Conflict 2 = C — the locked rule):
 *   - Prototype: no (stub only, never auto-run)
 *   - Internal:  NO — OPT-IN ONLY via `/vibe-sec:threat-model`, not in :audit
 *   - Public-facing and up: yes — runs as part of the audit
 *
 * The audit orchestrator MUST consult this before running the sink node. Opt-in
 * (direct `/vibe-sec:threat-model`) bypasses it — the user explicitly asked.
 */
export function threatModelInAudit(tier: Tier): boolean {
  return atLeast(tier, "public-facing");
}

function dread(
  damage: DreadLevel,
  reproducibility: DreadLevel,
  exploitability: DreadLevel,
  affectedUsers: DreadLevel,
  discoverability: DreadLevel,
): DreadScore {
  return {
    damage,
    reproducibility,
    exploitability,
    affectedUsers,
    discoverability,
    total:
      DREAD_WEIGHT[damage] +
      DREAD_WEIGHT[reproducibility] +
      DREAD_WEIGHT[exploitability] +
      DREAD_WEIGHT[affectedUsers] +
      DREAD_WEIGHT[discoverability],
  };
}

// ─── completeness check (synthesis §FP-risks: undergeneration is the worst) ──

/**
 * Inventory-completeness check. Route coverage = inventoried / detected. Below
 * 90% fires a banner so silent undergeneration never happens — the harder
 * failure mode where the model looks complete but isn't.
 */
export function checkCompleteness(input: ThreatModelInput): CompletenessCheck {
  const detected = input.totalRoutesDetected ?? input.routes.length;
  const inventoried = input.routes.length;
  // No routes at all → trivially complete (static site / no surface).
  if (detected === 0) {
    return { routeCoveragePct: 100, complete: true, banner: null };
  }
  const pct = Math.min(100, Math.round((inventoried / detected) * 100));
  const complete = inventoried / detected >= COMPLETENESS_THRESHOLD;
  const banner = complete
    ? null
    : `Inventory completeness: ${pct}% — threat model may be missing surfaces. ` +
      `${detected - inventoried} of ${detected} detected routes were not inventoried.`;
  return { routeCoveragePct: pct, complete, banner };
}

// ─── DFD reconstruction (routes → processes, data → stores, etc.) ────────────

function slug(s: string): string {
  return s.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "n";
}

/**
 * Reconstruct a lightweight DFD from the inventory. Not a pytm-grade process
 * decomposition — just enough to drive STRIDE-per-element and render a Mermaid.
 */
export function buildDfd(input: ThreatModelInput): Dfd {
  const boundaries: TrustBoundary[] = [
    { id: "external", label: "External user boundary" },
  ];

  const nodes: DfdNode[] = [];
  const flows: DfdFlow[] = [];

  // External entities — always the user; admin when the role matrix has >1 role.
  nodes.push({ id: "user", label: "User", shape: "external-entity", boundary: "external" });
  const hasAdmin = input.routes.some((r) => r.isAdmin);
  if (hasAdmin) {
    // Distinct boundary id from the node id so Mermaid subgraph ids never
    // collide with node ids (a subgraph + node sharing an id breaks rendering).
    boundaries.push({ id: "admin_boundary", label: "Admin / elevated-role boundary" });
    nodes.push({ id: "admin", label: "Admin", shape: "external-entity", boundary: "admin_boundary" });
  }

  // Tenant boundary at multi-tenant signal.
  if (input.multiTenant) {
    boundaries.push({ id: "tenant", label: "Tenant isolation boundary" });
  }

  // The backend process — the single application process for the lightweight model.
  nodes.push({ id: "backend", label: "Backend / API", shape: "process", boundary: null });
  nodes.push({ id: "frontend", label: "Frontend", shape: "process", boundary: null });
  flows.push({ from: "user", to: "frontend", label: "uses" });
  flows.push({ from: "frontend", to: "backend", label: "API calls" });
  if (hasAdmin) flows.push({ from: "admin", to: "backend", label: "admin actions" });

  // Data stores — a primary DB when there's any persisted model / PII.
  const hasData = input.piiFields.length > 0;
  if (hasData) {
    nodes.push({ id: "db", label: "Primary datastore", shape: "data-store", boundary: null });
    flows.push({ from: "backend", to: "db", label: "reads/writes" });
  }

  // Third parties — integrations as hexagons, with a service-to-service boundary.
  if (input.integrations.length > 0) {
    boundaries.push({ id: "service", label: "Service-to-service boundary" });
    for (const integ of input.integrations) {
      const id = `tp_${slug(integ)}`;
      nodes.push({ id, label: integ, shape: "third-party", boundary: "service" });
      flows.push({ from: "backend", to: id, label: "integrates" });
    }
  }

  return { boundaries, nodes, flows };
}

// ─── STRIDE-per-element enumeration ──────────────────────────────────────────

/** Map a STRIDE category to its typical remediation owner (synthesis §3.9). */
function ownerFor(category: StrideCategory): Concern | "advisory" {
  switch (category) {
    case "Spoofing":
      return "auth-model";
    case "Tampering":
      return "owasp-survey";
    case "Repudiation":
      return "advisory";
    case "Information Disclosure":
      return "crypto-pii";
    case "Denial of Service":
      return "rate-limiting";
    case "Elevation of Privilege":
      return "auth-model";
  }
}

/** Index findings by concern so realized threats can reference them. */
function findingByConcern(
  findings: readonly Finding[],
  concern: Concern,
): Finding | null {
  for (const f of findings) {
    if (f.primary_concern === concern) return f;
    if (f.secondary_concerns.includes(concern)) return f;
  }
  return null;
}

let threatSeq = 0;
function nextThreatId(): string {
  threatSeq += 1;
  return `threat-${threatSeq.toString().padStart(3, "0")}`;
}

/** Reset the per-run threat id sequence (call once before synthesize). */
export function resetThreatIds(): void {
  threatSeq = 0;
}

/**
 * Walk STRIDE per element for the external-user boundary. Each route is an
 * element; the walk produces tier-appropriate threats. Realized threats (where a
 * real finding exists) reference it by id and score higher on DREAD.
 */
function enumerateStride(input: ThreatModelInput): Threat[] {
  const threats: Threat[] = [];
  const { findings } = input;

  const secretF = findingByConcern(findings, "secret-detection");
  const cveF = findingByConcern(findings, "dependency-cve");
  const authF = findingByConcern(findings, "auth-model");
  const rateF = findingByConcern(findings, "rate-limiting");
  const configF = findingByConcern(findings, "config-posture");
  const cryptoF = findingByConcern(findings, "crypto-pii");

  // Spoofing — external-user boundary.
  threats.push({
    id: nextThreatId(),
    category: "Spoofing",
    element: "External user boundary",
    title: "Credential or session spoofing at the auth boundary",
    description:
      "An attacker presents forged or stolen credentials to impersonate a user. " +
      (authF
        ? "Realized risk: the auth model has a static-analysis gap."
        : "Severity depends on session strength and auth enforcement."),
    mitigation: "Enforce auth on every state-changing route; harden session tokens (→ auth-model, config CSRF).",
    remediationOwner: authF ? "auth-model" : "config-posture",
    realizedByFinding: authF?.id ?? null,
    dread: authF
      ? dread("high", "high", "medium", "high", "medium")
      : dread("medium", "medium", "low", "medium", "low"),
  });

  // Tampering — backend process.
  threats.push({
    id: nextThreatId(),
    category: "Tampering",
    element: "Backend / API process",
    title: "Request-payload tampering / injection",
    description:
      "Crafted input mutates queries, templates, or downstream calls. " +
      "Survey-level injection sinks and supply-chain integrity drive this class.",
    mitigation: "Validate + parameterize input; pin and verify dependencies (→ owasp-survey, supply-chain).",
    remediationOwner: "owasp-survey",
    realizedByFinding: findingByConcern(findings, "owasp-survey")?.id ?? null,
    dread: dread("high", "medium", "medium", "medium", "medium"),
  });

  // Repudiation — always advisory (audit logging rarely covered elsewhere).
  threats.push({
    id: nextThreatId(),
    category: "Repudiation",
    element: "Backend / API process",
    title: "No audit trail on state-changing actions",
    description:
      "Without an audit log, a user can deny having performed an action and the " +
      "system cannot prove otherwise.",
    mitigation: "Add an append-only audit log on auth-state changes and privileged actions (advisory).",
    remediationOwner: "advisory",
    realizedByFinding: null,
    dread: dread("low", "medium", "low", "low", "low"),
  });

  // Information Disclosure — data store / secrets.
  threats.push({
    id: nextThreatId(),
    category: "Information Disclosure",
    element: "Primary datastore",
    title: secretF
      ? "Committed credential grants direct data access"
      : "Sensitive data exposure via weak access or crypto",
    description: secretF
      ? "Realized: a credential is present in the repo — already-disclosed, the worst kind."
      : "PII and secrets can leak via missing access controls, weak crypto, or verbose errors.",
    mitigation: secretF
      ? "Rotate the credential (step zero), then add .gitignore + scan history (→ secret-detection)."
      : "Enforce least-privilege data access; encrypt sensitive fields at rest (→ crypto-pii, secret-detection).",
    remediationOwner: secretF ? "secret-detection" : "crypto-pii",
    realizedByFinding: secretF?.id ?? cryptoF?.id ?? cveF?.id ?? null,
    dread: secretF
      ? dread("high", "high", "high", "high", "high")
      : dread("high", "medium", "medium", "high", "medium"),
  });

  // Denial of Service — rate limiting.
  threats.push({
    id: nextThreatId(),
    category: "Denial of Service",
    element: "External user boundary",
    title: rateF
      ? "Unbounded endpoint enables resource exhaustion"
      : "No rate limiting on public endpoints",
    description:
      "An attacker exhausts compute, DB, or quota by flooding an endpoint. " +
      (rateF ? "Realized: a rate-limiting gap was detected." : "Risk scales with endpoint cost (LLM, email, DB)."),
    mitigation: "Add per-IP / per-user rate limits; platform-native WAF at Public-facing+ (→ rate-limiting).",
    remediationOwner: "rate-limiting",
    realizedByFinding: rateF?.id ?? null,
    dread: rateF
      ? dread("medium", "high", "high", "high", "medium")
      : dread("medium", "medium", "medium", "medium", "low"),
  });

  // Elevation of Privilege — admin boundary, only when an admin surface exists.
  const hasAdmin = input.routes.some((r) => r.isAdmin);
  if (hasAdmin || authF) {
    threats.push({
      id: nextThreatId(),
      category: "Elevation of Privilege",
      element: "Admin / elevated-role boundary",
      title: "Privilege escalation across the role boundary",
      description:
        "A regular user reaches privileged functionality — missing role gates, " +
        "IDOR, or unprotected admin routes.",
      mitigation: "Gate every admin route on role; enforce ownership checks; verify tenant isolation (→ auth-model).",
      remediationOwner: "auth-model",
      realizedByFinding: authF?.id ?? null,
      dread: dread("high", "medium", "medium", "medium", "medium"),
    });
  }

  // Config-misconfiguration surfaces as a Tampering/Spoofing cross-cut when present.
  if (configF) {
    threats.push({
      id: nextThreatId(),
      category: "Spoofing",
      element: "External user boundary",
      title: "Misconfiguration weakens the request-origin trust boundary",
      description:
        "Permissive CORS, missing CSRF protection, or open data-store rules let an " +
        "attacker forge cross-origin requests.",
      mitigation: "Tighten CORS to an allowlist; add CSRF tokens; lock data-store rules (→ config-posture).",
      remediationOwner: "config-posture",
      realizedByFinding: configF.id,
      dread: dread("medium", "high", "medium", "high", "high"),
    });
  }

  return threats;
}

// ─── tier-appropriate filtering (the FP control: relevance, not accuracy) ────

/**
 * Drop threats whose attacker-capability premise is implausible at the tier.
 * At Prototype the whole model is a stub (handled earlier). At Internal we keep
 * the external + admin boundary classes; speculative Elevation without an admin
 * surface is dropped. From Public-facing up, keep everything.
 */
function filterForTier(threats: Threat[], tier: Tier, hasAdmin: boolean): Threat[] {
  if (atLeast(tier, "public-facing")) return threats;
  // Internal: drop Elevation when there's no admin surface (no role separation
  // to escalate across); keep realized threats regardless.
  return threats.filter((t) => {
    if (t.category === "Elevation of Privilege" && !hasAdmin && !t.realizedByFinding) {
      return false;
    }
    return true;
  });
}

// ─── LINDDUN privacy overlay (Customer-facing+ only) ─────────────────────────

function enumerateLinddun(input: ThreatModelInput): PrivacyThreat[] {
  if (!atLeast(input.tier, "customer-facing-saas")) return [];
  if (input.piiFields.length === 0) return [];

  const out: PrivacyThreat[] = [];
  let n = 0;
  const id = (): string => `privacy-${(++n).toString().padStart(3, "0")}`;

  // One Linking + one Identifying threat per the PII store, plus the universal
  // Unawareness / Non-compliance pair that GDPR/CCPA reviews probe for.
  out.push({
    id: id(),
    category: "Linking",
    element: "Primary datastore",
    title: "User-attributable records can be linked across actions",
    mitigation: "Minimize identifiers in logs and analytics; pseudonymize where possible.",
  });
  out.push({
    id: id(),
    category: "Identifying",
    element: "Primary datastore",
    title: "Direct identifiers stored alongside behavioral data",
    mitigation: "Separate identity from behavioral stores; encrypt direct identifiers at rest.",
  });
  out.push({
    id: id(),
    category: "Data Disclosure",
    element: "Service-to-service boundary",
    title: "PII forwarded to third-party processors",
    mitigation: "Confirm DPAs with every processor; enforce GDPR Art. 44 transfer controls.",
  });
  out.push({
    id: id(),
    category: "Unawareness",
    element: "External user boundary",
    title: "Users may be unaware of data collection scope",
    mitigation: "Surface a clear privacy notice; honor consent and data-subject requests.",
  });
  out.push({
    id: id(),
    category: "Non-compliance",
    element: "Primary datastore",
    title: "Retention and deletion obligations may be unmet",
    mitigation: "Define retention windows; implement right-to-erasure (advisory).",
  });
  return out;
}

// ─── attack trees (Public-facing+ top-3; Regulated top-5) ────────────────────

function buildAttackTrees(prioritized: Threat[], tier: Tier): AttackTree[] {
  if (!atLeast(tier, "public-facing")) return [];
  const count = tier === "regulated" ? 5 : 3;
  return prioritized.slice(0, count).map((t) => attackTreeFor(t));
}

function attackTreeFor(t: Threat): AttackTree {
  // A shallow, two-level tree rooted at the attacker goal implied by the threat.
  const goal = `${t.category}: ${t.title}`;
  switch (t.category) {
    case "Information Disclosure":
      return {
        goal,
        branches: [
          { subGoal: "Obtain a valid credential", leaves: ["Find committed secret in repo/history", "Phish a user", "Reuse leaked password"] },
          { subGoal: "Bypass access control", leaves: ["IDOR on object id", "Missing auth on a data route"] },
        ],
      };
    case "Elevation of Privilege":
      return {
        goal,
        branches: [
          { subGoal: "Reach an admin route", leaves: ["Admin route lacks role gate", "Forge a role claim in the session"] },
          { subGoal: "Cross the tenant boundary", leaves: ["Missing RLS / tenant filter", "Predictable tenant id"] },
        ],
      };
    case "Denial of Service":
      return {
        goal,
        branches: [
          { subGoal: "Exhaust a costly resource", leaves: ["Flood an unbounded endpoint", "Trigger expensive LLM/email calls"] },
          { subGoal: "Amplify the request", leaves: ["No per-user budget", "No platform WAF"] },
        ],
      };
    case "Spoofing":
      return {
        goal,
        branches: [
          { subGoal: "Forge the request origin", leaves: ["Permissive CORS with credentials", "Missing CSRF token"] },
          { subGoal: "Replay a valid request", leaves: ["No nonce / idempotency guard"] },
        ],
      };
    default:
      return {
        goal,
        branches: [
          { subGoal: "Exploit the weakness", leaves: ["See the mapped concern's remediation"] },
        ],
      };
  }
}

// ─── the synthesis entry point ───────────────────────────────────────────────

/**
 * Synthesize the threat model from the inventory. Pure: returns the structured
 * result; the caller renders markdown + writes the JSON sidecar. At Prototype
 * the result is a stub (no synthesis ran).
 */
export function synthesizeThreatModel(input: ThreatModelInput): ThreatModelResult {
  resetThreatIds();
  const completeness = checkCompleteness(input);
  const dfd = buildDfd(input);

  // Prototype: no threat model. Return a stub.
  if (input.tier === "prototype") {
    return {
      tier: input.tier,
      isStub: true,
      completeness,
      dfd,
      boundaries: dfd.boundaries,
      threats: [],
      prioritized: [],
      privacyThreats: [],
      attackTrees: [],
      pytmStub: false,
    };
  }

  const hasAdmin = input.routes.some((r) => r.isAdmin);
  const allThreats = enumerateStride(input);
  const threats = filterForTier(allThreats, input.tier, hasAdmin);

  // DREAD-ordered prioritization. Lightweight (Internal) keeps the top-3; from
  // Public-facing up we surface the top-10.
  const sorted = [...threats].sort((a, b) => b.dread.total - a.dread.total);
  const topN = atLeast(input.tier, "public-facing") ? 10 : 3;
  const prioritized = sorted.slice(0, topN);

  const privacyThreats = enumerateLinddun(input);
  const attackTrees = buildAttackTrees(prioritized, input.tier);
  const pytmStub = input.tier === "regulated";

  return {
    tier: input.tier,
    isStub: false,
    completeness,
    dfd,
    boundaries: dfd.boundaries,
    threats,
    prioritized,
    privacyThreats,
    attackTrees,
    pytmStub,
  };
}

export { COMPLETENESS_THRESHOLD, DREAD_WEIGHT, atLeast as tierAtLeast };
