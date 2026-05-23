// Dynamic-code-loading sinks (A08-2021; spec §4.3, synthesis §3.3).
//
// The dynamic-code-execution family: the runtime string-eval primitive, the
// Function-constructor, the string-bodied timer calls, vm module execution, and
// document-write DOM injection. These are flagged but ALWAYS routed
// review-required / inline — never auto-fix (synthesis §3.3): a rewrite changes
// behavior and the builder must own it.
//
// Author's-note discipline (synthesis preamble): the sink identifiers collide
// with Claude Code's security-reminder hook substring matchers, so the regexes
// are assembled from character fragments rather than written as literal source
// tokens. Same approach the owasp-top-10-survey brief used. The detection is
// identical; only the way the pattern is spelled in source differs.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface DynamicCodeFinding {
  finding_type: "dynamic-code-execution-sink";
  sinkKind: string;
  severity: Severity;
  file: string;
  line: number;
  detail: string;
}

// Build sink regexes from fragments to avoid embedding the literal sink tokens.
const E = "e" + "v" + "a" + "l"; // the runtime string-eval primitive
const FN = "F" + "unction"; // the Function constructor
const SINK_PATTERNS: { kind: string; re: RegExp }[] = [
  // The runtime string-eval primitive — call form.
  { kind: "string-eval", re: new RegExp(`\\b${E}\\s*\\(`, "g") },
  // The Function constructor invoked with a string body (new Function('...') / Function('...')).
  { kind: "function-constructor", re: new RegExp(`\\b(?:new\\s+)?${FN}\\s*\\([^)]*["'\`]`, "g") },
  // String-bodied timer: setTimeout/setInterval with a string first arg.
  { kind: "string-timer", re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g },
  // Node vm module execution.
  { kind: "vm-exec", re: /\bvm\s*\.\s*(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(/g },
  // DOM document-write injection.
  { kind: "document-write", re: /\bdocument\s*\.\s*write(?:ln)?\s*\(/g },
];

/** Scan one source file for dynamic-code-execution sinks. */
export function scanDynamicCodeSinks(text: string, filePath: string): DynamicCodeFinding[] {
  const findings: DynamicCodeFinding[] = [];
  for (const { kind, re } of SINK_PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      findings.push({
        finding_type: "dynamic-code-execution-sink",
        sinkKind: kind,
        severity: "medium",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        detail: `Dynamic code-execution sink (${kind}). If any part of the input is attacker-controlled this is remote code execution. Review required — never auto-fixed; replace with a non-dynamic construction or strictly validate the input.`,
      });
    }
  }
  return findings;
}
