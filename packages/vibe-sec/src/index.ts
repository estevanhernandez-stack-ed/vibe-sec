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

// Secret detection (Layer A + orchestration).
export * from "./detectors/secrets/index.js";
export { scanText, downgradeForContext, maskMatch } from "./detectors/secrets/scan-tree.js";
export type { SecretFinding, ScanResult } from "./detectors/secrets/scan-tree.js";
export {
  SECRET_PATTERNS,
  type SecretPattern,
} from "./detectors/secrets/patterns.js";

// CLI core (re-export for headless CI).
export { runCli, VERSION } from "./cli.js";
