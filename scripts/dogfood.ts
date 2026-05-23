// vibe-sec dogfood harness — runs the full ten-concern audit backbone against a
// real app's source tree, the way the /vibe-sec:audit SKILL orchestrates the
// deterministic TypeScript layer.
//
// Usage:
//   node --experimental-strip-types scripts/dogfood.ts <target-path> [tier-override]
//
// It imports the BUILT backbone from the package's dist (tier classifier, all ten
// concern detectors, the weighted-score / severity engine, the four-band report
// renderer, the gate), runs them over <target-path>, and prints a JSON summary +
// the rendered markdown report to stdout. It writes NOTHING into the target tree:
// findings are assembled in memory and the markdown is returned to the caller,
// which writes it into the vibe-sec repo. (The audit-pipeline normally persists a
// .vibe-sec/ state dir; we deliberately skip the persist + read-back and feed the
// in-memory findings straight to the report/gate to keep the target read-only.)
//
// Multi-package handling: the structural detectors (secrets, crypto-pii,
// auth-model, owasp-survey) walk the whole tree from root and cover every
// sub-package in one pass. The manifest-rooted detectors (deps, supply-chain,
// config-posture, rate-limiting, platform-fingerprint) read fixed paths relative
// to the root handed to them, so we run them against the repo root AND each
// discovered sub-package root (a dir with its own package.json), then dedupe.

import fs from "node:fs";
import path from "node:path";

import {
  // tier classifier
  classifyTier,
  type RepoSignal,
  type Tier,
  // detectors
  scanSecrets,
  scanDependencies,
  scanSupplyChain,
  scanConfigPosture,
  scanCryptoPii,
  scanAuthModel,
  scanOwaspSurvey,
  scanRateLimiting,
  fingerprintPlatform,
  // mappers
  resetFindingIds,
  secretToFinding,
  depToFinding,
  depNotCheckedToFinding,
  depCoverageAdvisory,
  pinningToFinding,
  typosquatToFinding,
  actionsToFinding,
  corsToFinding,
  firebaseRulesToFinding,
  primitiveToFinding,
  passwordHashToFinding,
  jwtToFinding,
  clientKeyLeakToFinding,
  piiLogToFinding,
  adminToFinding,
  tenantToFinding,
  idorToFinding,
  sessionToFinding,
  roleHardcodingToFinding,
  cve202529927ToFinding,
  surveyToFinding,
  ssrfToFinding,
  dynamicCodeToFinding,
  llmEndpointToFinding,
  middlewareToFinding,
  rateLimitAbsentToFinding,
  abuseMonitoringToFinding,
  // report + scoring + gate
  buildBandedReport,
  renderMarkdownReport,
  renderBanner,
  weightedScore,
  evaluateGate,
  foldConcernResults,
  dedupeByLocation,
  type Finding,
  type Concern,
} from "../packages/vibe-sec/dist/index.js";

const target = process.argv[2];
if (!target) {
  console.error("usage: dogfood.ts <target-path> [tier-override]");
  process.exit(2);
}
const root = path.resolve(target);
const tierOverride = process.argv[3] as Tier | undefined;

// ─── Discover sub-package roots (dirs with their own package.json) ──────────
function findPackageRoots(dir: string, acc: string[], depth = 0): string[] {
  if (depth > 3) return acc;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git" || e.name === "dist") continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) findPackageRoots(full, acc, depth + 1);
  }
  if (fs.existsSync(path.join(dir, "package.json"))) acc.push(dir);
  return acc;
}
const pkgRoots = Array.from(new Set([root, ...findPackageRoots(root, [])]));

// ─── Tier signal gathering (the self-scan path the SKILL runs) ──────────────
// We have no Vibe Test handshake here, so we self-scan repo signals → classify.
function gatherSignals(roots: readonly string[]): RepoSignal[] {
  const signals: RepoSignal[] = [];
  const seen = new Set<string>();
  const add = (s: RepoSignal) => {
    if (seen.has(s.name)) return;
    seen.add(s.name);
    signals.push(s);
  };
  const exists = (rel: string) => roots.some((r) => fs.existsSync(path.join(r, rel)));
  const anyPkgHasDep = (re: RegExp): boolean =>
    roots.some((r) => {
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(r, "package.json"), "utf8"));
        const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
        return Object.keys(all).some((d) => re.test(d));
      } catch {
        return false;
      }
    });

  // Deploy / hosting config → it ships somewhere → public-facing minimum.
  if (exists("firebase.json") || exists("vercel.json") || exists("netlify.toml"))
    add({ name: "deploy config present", weight: "strong", promotes: "public-facing" });
  // Auth + multi-user (Firebase auth, role checks) → customer-facing SaaS signal.
  if (anyPkgHasDep(/firebase|@clerk\/|next-auth|@supabase\//))
    add({ name: "auth/identity dependency", weight: "medium", promotes: "public-facing" });
  // A real backend with user accounts + roles → customer-facing.
  if (exists("firestore.rules") || exists("storage.rules"))
    add({ name: "Firestore/Storage security rules", weight: "medium", promotes: "public-facing" });
  // Server / Cloud Functions backend.
  if (exists("functions") || exists("Backend") || anyPkgHasDep(/express|fastify|firebase-functions/))
    add({ name: "server-side backend", weight: "medium", promotes: "public-facing" });
  // Stores user PII / accounts (Firestore users collection is in CLAUDE.md). Treat
  // identity + persisted user data as a customer-facing-SaaS push.
  if (anyPkgHasDep(/firebase-admin/))
    add({ name: "firebase-admin (server-side user data)", weight: "medium", promotes: "customer-facing-saas" });
  return signals;
}

const signals = gatherSignals(pkgRoots);
const platform = fingerprintPlatform(root);
const classification = classifyTier({
  inheritedTier: null,
  signals,
  override: tierOverride ?? null,
});
const tier = classification.tier;

// ─── Run detectors. No external tools assumed (in-house baseline). ──────────
const noTools = (toolName: string) => ({ name: toolName, present: false, version: null });

resetFindingIds();
const findings: Finding[] = [];
const perConcernCount: Record<string, number> = {};
const errors: { concern: string; root: string; error: string }[] = [];
const bump = (c: string, n: number) => {
  perConcernCount[c] = (perConcernCount[c] ?? 0) + n;
};
function guard(concern: string, scanRoot: string, fn: () => void) {
  try {
    fn();
  } catch (ex) {
    errors.push({ concern, root: path.relative(root, scanRoot) || ".", error: String((ex as Error)?.stack ?? ex) });
  }
}

// — Whole-tree detectors: run once from the repo root (walkSource recurses). —
guard("secret-detection", root, () => {
  const r = scanSecrets(root, { probe: noTools, forceInhouse: true });
  const mapped = r.findings.map((s) => secretToFinding(s, tier));
  findings.push(...mapped);
  bump("secret-detection", mapped.length);
});

guard("crypto-pii", root, () => {
  const r = scanCryptoPii(root, { probe: noTools });
  let n = 0;
  for (const p of r.primitives) { findings.push(primitiveToFinding(p, tier)); n++; }
  for (const p of r.passwordHashing) { findings.push(passwordHashToFinding(p, tier)); n++; }
  for (const j of r.jwt) { findings.push(jwtToFinding(j, tier)); n++; }
  for (const c of r.clientKeyLeaks) { findings.push(clientKeyLeakToFinding(c, tier)); n++; }
  for (const p of r.piiInLogs) { findings.push(piiLogToFinding(p, tier)); n++; }
  bump("crypto-pii", n);
  // piiInventory is the signature artifact, not a finding — record count separately.
  (globalThis as Record<string, unknown>).__piiInventory = r.piiInventory.length;
});

let authzMatrix: unknown = null;
guard("auth-model", root, () => {
  const r = scanAuthModel(root, { probe: noTools });
  let n = 0;
  for (const a of r.admin) { findings.push(adminToFinding(a, tier)); n++; }
  for (const t of r.tenant) { findings.push(tenantToFinding(t, tier)); n++; }
  for (const i of r.idor) {
    const f = idorToFinding(i, tier);
    if (f) { findings.push(f); n++; }
  }
  for (const s of r.session) { findings.push(sessionToFinding(s, tier)); n++; }
  if (r.roleHardcoding) { findings.push(roleHardcodingToFinding(r.roleHardcoding, tier)); n++; }
  const cve = cve202529927ToFinding(r.cve202529927, tier);
  if (cve) { findings.push(cve); n++; }
  bump("auth-model", n);
  authzMatrix = r.matrix;
  (globalThis as Record<string, unknown>).__routeCount = r.routes.length;
  (globalThis as Record<string, unknown>).__idorRaw = r.idor.length;
});

let injectionSurfaced = false;
let llmDetected = false;
guard("owasp-survey", root, () => {
  const r = scanOwaspSurvey(root, { probe: noTools });
  let n = 0;
  for (const s of r.survey) { findings.push(surveyToFinding(s, tier)); n++; }
  for (const s of r.ssrf) { findings.push(ssrfToFinding(s, tier)); n++; }
  for (const d of r.dynamicCode) { findings.push(dynamicCodeToFinding(d, tier)); n++; }
  bump("owasp-survey", n);
  injectionSurfaced = r.survey.some((s) => s.tags.owasp_2021 === "A03") || r.dynamicCode.length > 0;
});

// — Manifest-rooted detectors: run per package root, dedupe by finding id. —
const idsSeen = new Set(findings.map((f) => f.id));
const pushUnique = (f: Finding | null) => {
  if (!f) return false;
  if (idsSeen.has(f.id)) return false;
  idsSeen.add(f.id);
  findings.push(f);
  return true;
};

for (const r of pkgRoots) {
  const label = path.relative(root, r) || "(root)";

  guard(`dependency-cve@${label}`, r, () => {
    const res = scanDependencies(r, { probe: noTools });
    let n = 0;
    for (const d of res.findings) if (pushUnique(depToFinding(d, tier))) n++;
    // No data source reached (no osv-scanner, no fetcher, no npm audit) and no
    // findings → surface a coverage advisory so a clean 1.0 isn't false comfort.
    if (res.notChecked && res.findings.length === 0) {
      if (pushUnique(depNotCheckedToFinding(depCoverageAdvisory(), tier))) n++;
    }
    bump("dependency-cve", n);
  });

  guard(`supply-chain@${label}`, r, () => {
    const res = scanSupplyChain(r);
    let n = 0;
    for (const p of res.integrity.floatingPins) if (pushUnique(pinningToFinding(p, tier))) n++;
    for (const t of res.typosquats) if (pushUnique(typosquatToFinding(t, tier))) n++;
    for (const a of res.actions) if (pushUnique(actionsToFinding(a, tier))) n++;
    bump("supply-chain", n);
  });

  guard(`config-posture@${label}`, r, () => {
    const res = scanConfigPosture(r);
    let n = 0;
    for (const c of res.cors) if (pushUnique(corsToFinding(c, tier))) n++;
    for (const f of res.firebaseRules) if (pushUnique(firebaseRulesToFinding(f, tier))) n++;
    const cve = cve202529927ToFinding(res.cve202529927, tier);
    if (cve && pushUnique(cve)) n++;
    bump("config-posture", n);
  });

  guard(`rate-limiting@${label}`, r, () => {
    const res = scanRateLimiting(r, { tier });
    let n = 0;
    for (const l of res.llmEndpoints) if (pushUnique(llmEndpointToFinding(l, tier))) n++;
    for (const m of res.middleware) if (pushUnique(middlewareToFinding(m, tier))) n++;
    for (const a of res.abuseMonitoring) if (pushUnique(abuseMonitoringToFinding(a, tier))) n++;
    if (res.libraryAbsent) {
      const f = rateLimitAbsentToFinding(tier);
      if (f && pushUnique(f)) n++;
    }
    if (res.llmRoutesDetected) llmDetected = true;
    bump("rate-limiting", n);
  });
}

// ─── Path-normalize + de-dupe (multi-root collapse) ─────────────────────────
// In a multi-package repo with no root package.json, manifest-rooted detectors
// run once per sub-root, so the same physical file surfaces under different
// relative prefixes (functions/src/games/quiz.js vs src/games/quiz.js) with
// different finding ids — id-dedup misses them. dedupeByLocation collapses by
// canonical location + concern + finding_type so a file scanned via multiple
// roots yields one finding (WSYATM dogfood §5 fix). Run BEFORE scoring/banding.
const dedupedFindings = dedupeByLocation(findings);
findings.length = 0;
findings.push(...dedupedFindings);

// ─── Score, gate, four-band report ──────────────────────────────────────────
// Fold findings into per-concern results the same way run-gate does over cached
// state (we feed the in-memory findings instead of reading findings.jsonl).
const concernResults = foldConcernResults(findings, tier);
const scoreResult = weightedScore(tier, concernResults);
const gate = evaluateGate(tier, concernResults);

const hasDeps = pkgRoots.some((r) => fs.existsSync(path.join(r, "package.json")));
const report = buildBandedReport(findings, tier, {
  hasDependencies: hasDeps,
  llmDetected,
  injectionSurfaced,
  toolsUsed: [],
});

const markdown = renderMarkdownReport(report, {
  command: "audit",
  score: scoreResult.score,
  gatePass: gate.pass,
  authzMatrix: authzMatrix as never,
  generatedAt: new Date().toISOString(),
});
const banner = renderBanner(report, {
  root,
  score: scoreResult.score,
  threshold: gate.threshold,
  gatePass: gate.pass,
  authzMatrix: authzMatrix as never,
  noColor: true,
});

// ─── Emit a structured summary the caller parses + the rendered report. ──────
const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
for (const f of findings) severityCounts[f.severity_tier_adjusted]++;

const summary = {
  target: root,
  packageRoots: pkgRoots.map((r) => path.relative(root, r) || "(root)"),
  platform: { platform: platform.platform, confidence: platform.confidence, signals: platform.signals },
  classification: {
    tier,
    confidence: classification.confidence,
    source: classification.source,
    rationale: classification.rationale,
    signals: signals.map((s) => `${s.name} (${s.weight} → ${s.promotes})`),
  },
  score: scoreResult.score,
  perConcernScore: scoreResult.perConcern,
  inScopeConcerns: scoreResult.inScopeConcerns,
  gate: { pass: gate.pass, exit: gate.exit, threshold: gate.threshold, blockingConcerns: gate.blockingConcerns, reasons: gate.reasons },
  findingsTotal: findings.length,
  severityCounts,
  perConcernFindingCount: perConcernCount,
  bandSizes: { band1: report.band1.length, band2: report.band2.length, band3: report.band3.length, band4: report.band4.length },
  artifacts: {
    piiInventoryFields: (globalThis as Record<string, unknown>).__piiInventory ?? 0,
    routeCount: (globalThis as Record<string, unknown>).__routeCount ?? 0,
    idorRawSignals: (globalThis as Record<string, unknown>).__idorRaw ?? 0,
  },
  errors,
};

console.log("===VIBE-SEC-DOGFOOD-SUMMARY-JSON===");
console.log(JSON.stringify(summary, null, 2));
console.log("===VIBE-SEC-DOGFOOD-BANNER===");
console.log(banner);
console.log("===VIBE-SEC-DOGFOOD-MARKDOWN===");
console.log(markdown);
console.log("===VIBE-SEC-DOGFOOD-BAND1-DETAIL===");
console.log(JSON.stringify(
  report.band1.map((f) => ({ concern: f.primary_concern, sev: f.severity_tier_adjusted, type: f.finding_type, title: f.title, file: f.file, line: f.line, confidence: f.confidence })),
  null, 2,
));
console.log("===VIBE-SEC-DOGFOOD-BAND2-DETAIL===");
console.log(JSON.stringify(
  report.band2.map((f) => ({ concern: f.primary_concern, sev: f.severity_tier_adjusted, type: f.finding_type, title: f.title, file: f.file, line: f.line, confidence: f.confidence })),
  null, 2,
));
console.log("===VIBE-SEC-DOGFOOD-ALL-FINDINGS-COMPACT===");
console.log(JSON.stringify(
  findings.map((f) => ({ id: f.id, concern: f.primary_concern, sev: f.severity_tier_adjusted, type: f.finding_type, file: f.file, line: f.line, conf: f.confidence })),
  null, 2,
));
