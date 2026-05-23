// OWASP Top 10 survey orchestrator (concern #3; spec §4.3, synthesis §3.3;
// checklist 3.3).
//
// The breadth layer + the dual-tag glue. Runs the survey rules, shallow SSRF,
// and dynamic-code-sink passes; tags every finding with both 2021 + 2025 OWASP
// categories; and computes the primary-concern assignment for cross-concern
// findings (the ownership matrix in spec §6) by consuming the crypto-pii (3.1)
// and auth-model (3.2) outputs.
//
// Deferral: Semgrep CE is the tool of record for deep A03 injection + crypto
// (synthesis Decision 4). The survey baseline always runs (breadth is the
// point); when Semgrep is present it's credited and surfaced as the Band-4
// complement for deep injection. A03 stays survey-level here regardless.

import { walkSource } from "../source-walk.js";
import { scanSurveyRules, type SurveyFinding } from "./survey-rules.js";
import { scanSsrf, type SsrfFinding } from "./ssrf-shallow.js";
import { scanDynamicCodeSinks, type DynamicCodeFinding } from "./dynamic-code-sinks.js";
import { dualTag, type OwaspTags, type Owasp2021 } from "./dual-tag.js";
import {
  detectToolOfRecord,
  SEMGREP_TOOL_CANDIDATES,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";
import type { Concern } from "../../types.js";

/** A survey finding with its dual tags resolved + primary/secondary ownership. */
export interface TaggedSurveyFinding extends SurveyFinding {
  tags: OwaspTags;
  primary_concern: Concern;
  secondary_concerns: Concern[];
}

export interface OwaspSurveyScanResult {
  survey: TaggedSurveyFinding[];
  ssrf: SsrfFinding[];
  dynamicCode: DynamicCodeFinding[];
  semgrepAvailable: boolean;
}

export interface OwaspSurveyScanOptions {
  probe?: ToolProbe;
}

// Primary-concern ownership by survey category (spec §6 ownership matrix):
// the deepest-domain owner is primary; survey is the secondary cross-reference.
const CATEGORY_OWNER: Record<Owasp2021, { primary: Concern; secondaries: Concern[] }> = {
  A01: { primary: "auth-model", secondaries: ["owasp-survey"] },
  A02: { primary: "crypto-pii", secondaries: ["owasp-survey"] },
  A03: { primary: "owasp-survey", secondaries: [] }, // injection stays survey-owned in v0.2
  A04: { primary: "owasp-survey", secondaries: [] },
  A05: { primary: "config-posture", secondaries: ["owasp-survey"] },
  A06: { primary: "dependency-cve", secondaries: ["owasp-survey"] },
  A07: { primary: "auth-model", secondaries: ["owasp-survey"] },
  A08: { primary: "supply-chain", secondaries: ["owasp-survey"] },
  A09: { primary: "owasp-survey", secondaries: [] },
  A10: { primary: "owasp-survey", secondaries: [] }, // SSRF survey-owned in v0.2
};

/** Resolve dual tags + primary/secondary ownership for a survey finding. */
export function tagFinding(f: SurveyFinding): TaggedSurveyFinding {
  const owner = CATEGORY_OWNER[f.category];
  return {
    ...f,
    tags: dualTag(f.category),
    primary_concern: owner.primary,
    secondary_concerns: owner.secondaries,
  };
}

/** Run the full OWASP survey pass over a project. */
export function scanOwaspSurvey(
  projectRoot: string,
  opts: OwaspSurveyScanOptions = {},
): OwaspSurveyScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const semgrep = detectToolOfRecord(SEMGREP_TOOL_CANDIDATES, probe);

  const survey = walkSource(projectRoot, [scanSurveyRules]).map(tagFinding);
  const ssrf = walkSource(projectRoot, [scanSsrf]);
  const dynamicCode = walkSource(projectRoot, [scanDynamicCodeSinks]);

  return {
    survey,
    ssrf,
    dynamicCode,
    semgrepAvailable: Boolean(semgrep?.present),
  };
}

export { scanSurveyRules, scanSsrf, scanDynamicCodeSinks, dualTag };
export type { SurveyFinding, SsrfFinding, DynamicCodeFinding, OwaspTags, Owasp2021 };
