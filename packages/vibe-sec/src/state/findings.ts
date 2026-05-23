// findings.jsonl schema + append-only writer/reader (spec §6, synthesis §4.1).
//
// The handoff spine. One JSON object per line, append-only. The weighted-score
// calculator de-duplicates by `id` (synthesis §4.3) — so the reader exposes a
// dedup-by-id read that keeps the last write per id.

import fs from "node:fs";
import path from "node:path";
import {
  type Concern,
  type FixClass,
  type Severity,
  type ToolOfRecord,
  type Tier,
} from "../types.js";
import { findingsPath } from "./paths.js";

/** The locked findings.jsonl record (spec §6). */
export interface Finding {
  schema_version: 1;
  id: string;
  created_at: string;
  primary_concern: Concern;
  secondary_concerns: Concern[];
  owasp_2021: string | null;
  owasp_2025: string | null;
  cwe: string | null;
  severity_base: Severity;
  severity_tier_adjusted: Severity;
  confidence: number;
  surface: string | null;
  finding_type: string;
  title: string;
  description: string;
  file: string | null;
  line: number | null;
  tier: Tier;
  tier_scaling_at_current_tier: number;
  fix_class: FixClass;
  fix_ref: string | null;
  test_recommendation: string | null;
  priority_elevation: string | null;
  expected_behavior: string | null;
  epss_score: number | null;
  kev_listed: boolean;
  suppressed: boolean;
  suppressed_reason: string | null;
  /** Added for the orchestration pivot — which detector produced the raw finding. */
  tool_of_record: ToolOfRecord;
  references: string[];
}

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low"]);
const FIX_CLASSES = new Set<FixClass>([
  "auto",
  "stage",
  "inline",
  "advisory",
  "inform-only",
]);

/**
 * Validate a finding's required-field contract. Returns the list of problems;
 * empty array means valid. Cheap structural check — not a full JSON schema.
 */
export function validateFinding(f: unknown): string[] {
  const problems: string[] = [];
  if (typeof f !== "object" || f === null) return ["finding is not an object"];
  const o = f as Record<string, unknown>;

  if (o.schema_version !== 1) problems.push("schema_version must be 1");
  if (typeof o.id !== "string" || o.id.length === 0) problems.push("id is required");
  if (typeof o.primary_concern !== "string") problems.push("primary_concern is required");
  if (!Array.isArray(o.secondary_concerns)) problems.push("secondary_concerns must be an array");
  if (!SEVERITIES.has(o.severity_base as Severity)) problems.push("severity_base invalid");
  if (!SEVERITIES.has(o.severity_tier_adjusted as Severity))
    problems.push("severity_tier_adjusted invalid");
  if (typeof o.confidence !== "number" || o.confidence < 0 || o.confidence > 1)
    problems.push("confidence must be in [0,1]");
  if (typeof o.finding_type !== "string") problems.push("finding_type is required");
  if (typeof o.title !== "string") problems.push("title is required");
  if (typeof o.tier !== "string") problems.push("tier is required");
  if (!FIX_CLASSES.has(o.fix_class as FixClass)) problems.push("fix_class invalid");
  if (typeof o.tool_of_record !== "string") problems.push("tool_of_record is required");
  if (typeof o.kev_listed !== "boolean") problems.push("kev_listed must be boolean");
  if (typeof o.suppressed !== "boolean") problems.push("suppressed must be boolean");
  if (!Array.isArray(o.references)) problems.push("references must be an array");

  return problems;
}

/** Fill the optional fields of a finding from a partial input. */
export function makeFinding(
  partial: Pick<
    Finding,
    | "id"
    | "primary_concern"
    | "severity_base"
    | "severity_tier_adjusted"
    | "confidence"
    | "finding_type"
    | "title"
    | "tier"
    | "fix_class"
    | "tool_of_record"
  > &
    Partial<Finding>,
): Finding {
  return {
    schema_version: 1,
    secondary_concerns: [],
    owasp_2021: null,
    owasp_2025: null,
    cwe: null,
    surface: null,
    description: "",
    file: null,
    line: null,
    tier_scaling_at_current_tier: 1.0,
    fix_ref: null,
    test_recommendation: null,
    priority_elevation: null,
    expected_behavior: null,
    epss_score: null,
    kev_listed: false,
    suppressed: false,
    suppressed_reason: null,
    references: [],
    created_at: new Date().toISOString(),
    ...partial,
  };
}

/** Append one finding to findings.jsonl, creating the dir + file as needed. */
export function appendFinding(
  projectRoot: string,
  finding: Finding,
  app?: string,
): void {
  appendFindings(projectRoot, [finding], app);
}

/** Append many findings atomically (single write). */
export function appendFindings(
  projectRoot: string,
  findings: readonly Finding[],
  app?: string,
): void {
  if (findings.length === 0) return;
  const file = findingsPath(projectRoot, app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lines = findings.map((f) => JSON.stringify(f)).join("\n") + "\n";
  fs.appendFileSync(file, lines, "utf8");
}

/**
 * Read all findings from findings.jsonl, in file order. Skips blank/corrupt
 * lines rather than throwing — a single bad line should not blind the audit.
 */
export function readFindings(projectRoot: string, app?: string): Finding[] {
  const file = findingsPath(projectRoot, app);
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf8");
  const out: Finding[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as Finding);
    } catch {
      // skip corrupt line
    }
  }
  return out;
}

/**
 * Read findings deduped by `id` — last write wins (re-detected findings
 * overwrite earlier copies). This is the read the weighted-score calculator
 * consumes so the same id counts once.
 */
export function readFindingsDeduped(projectRoot: string, app?: string): Finding[] {
  const all = readFindings(projectRoot, app);
  const byId = new Map<string, Finding>();
  for (const f of all) {
    byId.set(f.id, f);
  }
  return [...byId.values()];
}
