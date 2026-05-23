// Secret verification — opt-in (spec §4.2, Conflict 5 = A).
//
// v0.2 default is "no network." Verification (does this key actually
// authenticate against the live provider?) is opt-in via --verify, and when
// asked, we defer to trufflehog's verifier rather than rolling our own provider
// API-ping matrix. A trufflehog-verified secret is a confirmed live credential
// → Critical, no tier discount.
//
// This module is the policy + adapter: gate on the flag, check trufflehog is
// present, shell out in verify mode, map verified=true onto severity. When
// trufflehog is absent the caller surfaces a Band-4 complement instead of
// silently downgrading the request.

import {
  detectToolOfRecord,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";
import {
  parseTrufflehogJsonl,
  type CommandRunner,
  defaultCommandRunner,
} from "../../orchestration/defer.js";
import type { SecretFinding } from "./scan-tree.js";

export interface VerifyOptions {
  probe?: ToolProbe;
  runner?: CommandRunner;
}

export interface VerifyResult {
  /** Verified-live secrets, severity already lifted to critical. */
  findings: SecretFinding[];
  /** True when verification actually ran (trufflehog present + opt-in). */
  verified: boolean;
  /** Reason verification was skipped, when it was. */
  skippedReason: string | null;
}

/**
 * Run trufflehog in verify mode over the working tree. Only the verified
 * findings are returned — unverified secrets are the in-house layers' job, this
 * is the "is it live?" confirmation pass. Caller gates on the --verify flag.
 */
export function verifySecrets(
  projectRoot: string,
  opts: VerifyOptions = {},
): VerifyResult {
  const probe = opts.probe ?? defaultToolProbe;
  const runner = opts.runner ?? defaultCommandRunner;

  const tool = detectToolOfRecord(["trufflehog"], probe);
  if (!tool?.present) {
    return {
      findings: [],
      verified: false,
      skippedReason:
        "--verify needs trufflehog on PATH. Install it (github.com/trufflesecurity/trufflehog) to confirm which keys are live.",
    };
  }

  let out: string;
  try {
    // --only-verified keeps the output to confirmed-live credentials.
    out = runner(
      "trufflehog",
      ["filesystem", projectRoot, "--json", "--only-verified"],
      projectRoot,
    );
  } catch {
    return {
      findings: [],
      verified: false,
      skippedReason: "trufflehog verification failed to run; left findings unverified.",
    };
  }

  // parseTrufflehogJsonl already maps Verified=true → critical.
  const findings = parseTrufflehogJsonl(out).filter((f) => f.severity === "critical");
  return { findings, verified: true, skippedReason: null };
}
