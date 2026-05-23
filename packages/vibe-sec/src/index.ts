// @esthernandez/vibe-sec — public surface (v0.2 Phase 1).
//
// The tier-aware audit + orchestration layer. Phase 1 ships the math substrate,
// the findings.jsonl handoff spine, the Vibe Test composition handshake, and
// the promoted secret scanner with the gitleaks/trufflehog deferral contract.
// Detectors for the other nine concerns land in Phases 2-4.

// Shared vocabulary.
export * from "./types.js";

// Scoring / math substrate (concern #10).
export * from "./scoring/severity-amplifier.js";
export * from "./scoring/weighted-score.js";

// Tier classifier.
export * from "./scanner/classify-tier.js";

// State / handoff spine.
export * from "./state/paths.js";
export * from "./state/findings.js";
export * from "./state/audit-state.js";

// Composition.
export * from "./composition/vibe-test.js";

// Orchestration deferral contract.
export * from "./orchestration/tool-registry.js";
export * from "./orchestration/defer.js";

// Secret detection (Layers A/B/C + history + verify + orchestration).
export * from "./detectors/secrets/index.js";
export {
  scanText,
  scanTree,
  scanTreeWith,
  downgradeForContext,
  maskMatch,
  type ScanLayer,
} from "./detectors/secrets/scan-tree.js";
export type { SecretFinding, ScanResult } from "./detectors/secrets/scan-tree.js";
export {
  SECRET_PATTERNS,
  type SecretPattern,
} from "./detectors/secrets/patterns.js";
export {
  shannonEntropy,
  isHighEntropyToken,
  scanEntropy,
  BASE64_ENTROPY_THRESHOLD,
  HEX_ENTROPY_THRESHOLD,
  MIN_TOKEN_LENGTH,
} from "./detectors/secrets/entropy.js";
export { scanAst, isParseable } from "./detectors/secrets/ast-walk.js";
export {
  scanHistory,
  type HistorySecretFinding,
  type GitRunner,
  type HistoryScanResult,
} from "./detectors/secrets/history-scan.js";
export { verifySecrets, type VerifyResult } from "./detectors/secrets/verify.js";
export {
  readHistoryScanCache,
  writeHistoryScanCache,
  decideScanMode,
  historyScanCachePath,
  type HistoryScanCache,
} from "./state/history-scan.js";

// Shared lockfile parser (consumed by deps #1 + supply-chain #6).
export {
  readLockfile,
  readDeclaredDeps,
  detectLockfile,
  classifyPin,
  type LockfileInfo,
  type LockEntry,
  type DeclaredDep,
  type PinStyle,
  type PackageManager,
} from "./detectors/supply-chain/lockfile.js";

// Dependency-CVE (#1) — OSV + npm audit + dedupe + app/lib classifier.
export {
  scanDependencies,
  shouldRollbackChurn,
  countDiffLines,
  LOCKFILE_CHURN_LIMIT,
  type DepScanResult,
  type DepScanOptions,
} from "./detectors/deps/index.js";
export {
  scanOsv,
  parseOsvScannerJson,
  cvssToSeverity,
  type DepVulnerability,
} from "./detectors/deps/osv-client.js";
export {
  parseNpmAudit,
  runNpmAudit,
  routeFixFromAudit,
} from "./detectors/deps/npm-audit.js";
export { mergeDepFindings, type MergedDepFinding } from "./detectors/deps/dedupe.js";
export { classifyProject, type ProjectKind } from "./detectors/deps/app-lib-classifier.js";

// Supply-chain hardening (#6) — integrity, pinning, actions, typosquat, SBOM.
export {
  scanSupplyChain,
  checkLockfileIntegrity,
  type SupplyChainScanResult,
  type SupplyChainScanOptions,
  type LockfileIntegrityResult,
  type PinningFinding,
} from "./detectors/supply-chain/index.js";
export {
  parseWorkflowText,
  parseWorkflows,
  findActionsIssues,
  classifyRef,
  type ActionUse,
  type WorkflowParse,
  type ActionsFinding,
  type RefStyle,
} from "./detectors/supply-chain/actions-parse.js";
export {
  levenshtein,
  findTyposquats,
  findDepConfusion,
  POPULAR_PACKAGES,
  type TyposquatFinding,
  type DepConfusionFinding,
} from "./detectors/supply-chain/typosquat.js";
export {
  scanPostinstall,
  type PostinstallFinding,
  type PostinstallScanResult,
} from "./detectors/supply-chain/postinstall.js";
export {
  detectSbom,
  type SbomDetectResult,
  type SbomFormat,
} from "./detectors/supply-chain/sbom-detect.js";

// Config posture (#5) — headers, CORS, cookies, Firebase rules, CVE-2025-29927.
export {
  scanConfigPosture,
  type ConfigPostureResult,
} from "./detectors/config-posture/index.js";
export {
  analyzeHeaders,
  headerFindings,
  type HeaderPosture,
  type HeaderFinding,
  type SecurityHeader,
} from "./detectors/config-posture/headers.js";
export { scanCors, type CorsFinding } from "./detectors/config-posture/cors.js";
export { scanCookies, type CookieFinding } from "./detectors/config-posture/cookies.js";
export {
  scanFirebaseRules,
  isFirebaseRulesFile,
  type FirebaseRulesFinding,
} from "./detectors/config-posture/firebase-rules.js";
export {
  detectCve202529927,
  checkNextVersion,
  parseSemVer,
  type Cve202529927Result,
} from "./detectors/config-posture/cve-2025-29927.js";

// Detector → findings.jsonl mappers (consumed by :scan / :deps / :audit).
export {
  resetFindingIds,
  secretToFinding,
  depToFinding,
  pinningToFinding,
  typosquatToFinding,
  actionsToFinding,
  corsToFinding,
  firebaseRulesToFinding,
} from "./detectors/to-findings.js";

// CLI core (re-export for headless CI).
export { runCli, VERSION } from "./cli.js";
