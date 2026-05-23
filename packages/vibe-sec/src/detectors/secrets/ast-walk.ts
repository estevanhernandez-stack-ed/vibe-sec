// Secret-detection Layer C — AST (spec §4.2, synthesis §3.2, Conflict 4 = A).
//
// Regex sees text; the AST sees structure. Two leak shapes regex reliably
// misses, both real in vibe-coded React/Next apps:
//
//   1. JSX prop leaks — `<Stripe apiKey="sk_live_..." />`. The value is a
//      string literal in a JSXAttribute; a regex tuned for `key = "..."`
//      assignment context skips it because there's no `=` operator, just JSX.
//   2. `process.env.X = "literal"` overwrites — assigning a hardcoded secret
//      back onto process.env defeats the whole "use env vars" pattern, and the
//      LHS member-expression doesn't look like a secret-shaped variable name.
//
// We parse with @babel/parser (TS + JSX, error-recovery on) and walk the AST
// by hand — no @babel/traverse dependency, keeps the bundle lean. A parse
// failure is non-fatal: Layer C silently yields nothing and Layers A/B still
// run. AST is the precision layer that makes the 12% FP target reachable for
// generic-secret-assign patterns.

import { parse } from "@babel/parser";
import type { SecretFinding } from "./scan-tree.js";
import { maskMatch } from "./scan-tree.js";
import type { Severity } from "../../types.js";

// A minimal structural node shape — we only read the fields we walk, so we
// avoid pulling @babel/types into the runtime surface.
interface Node {
  type: string;
  loc?: { start: { line: number; column: number } } | null;
  [key: string]: unknown;
}

const SECRET_NAME_RE =
  /(key|secret|token|password|passwd|pwd|auth|credential|apikey|access)/i;

// A value that looks secret-ish enough to flag when it lands in a leak shape:
// long, no whitespace, not an obvious placeholder/URL/path.
const PLACEHOLDER_RE =
  /^(?:your[_-]?|my[_-]?|example|sample|placeholder|dummy|fake|test[_-]?key|xxx+|<.*>|\$\{.*\}|process\.env)/i;

function looksSecret(value: string): boolean {
  if (value.length < 16) return false;
  if (/\s/.test(value)) return false;
  if (PLACEHOLDER_RE.test(value)) return false;
  // URLs and file paths are usually not the secret itself.
  if (/^https?:\/\//.test(value) && !/:\/\/[^:@/]+:[^@/]+@/.test(value)) return false;
  return true;
}

const AST_SEVERITY: Severity = "high";

function isStringLiteral(n: unknown): n is Node & { value: string } {
  return (
    typeof n === "object" &&
    n !== null &&
    (n as Node).type === "StringLiteral" &&
    typeof (n as Node).value === "string"
  );
}

/** Is this member expression `process.env.SOMETHING`? */
function isProcessEnvMember(n: Node): boolean {
  if (n.type !== "MemberExpression") return false;
  const obj = n.object as Node | undefined;
  if (!obj) return false;
  // process.env.X  → object is MemberExpression(process.env)
  if (obj.type === "MemberExpression") {
    const inner = obj.object as Node | undefined;
    const innerProp = obj.property as Node | undefined;
    return (
      inner?.type === "Identifier" &&
      (inner as { name?: string }).name === "process" &&
      innerProp?.type === "Identifier" &&
      (innerProp as { name?: string }).name === "env"
    );
  }
  return false;
}

function jsxAttrName(n: Node): string | null {
  const name = n.name as Node | undefined;
  if (name?.type === "JSXIdentifier") return (name as { name?: string }).name ?? null;
  return null;
}

/**
 * Walk an AST collecting findings. Recursive descent over plain objects/arrays;
 * checks each node against the two leak shapes before recursing into children.
 */
function walk(node: unknown, filePath: string, out: SecretFinding[], seen: WeakSet<object>): void {
  if (node === null || typeof node !== "object") return;
  if (seen.has(node)) return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, filePath, out, seen);
    return;
  }
  seen.add(node);
  const n = node as Node;

  // Shape 1: JSX prop with a string-literal secret — <X apiKey="..." />.
  if (n.type === "JSXAttribute") {
    const attr = jsxAttrName(n);
    const value = n.value;
    if (attr && SECRET_NAME_RE.test(attr) && isStringLiteral(value) && looksSecret(value.value)) {
      const loc = (value as Node).loc?.start ?? n.loc?.start;
      out.push({
        pattern: "AST_JSX_PROP_SECRET",
        severity: AST_SEVERITY,
        file: filePath,
        line: loc?.line ?? 0,
        column: (loc?.column ?? 0) + 1,
        match: maskMatch(value.value),
        preview: `<… ${attr}="${maskMatch(value.value)}" />`,
        remediation:
          "Hardcoded secret in a JSX prop ships to the client bundle. Move it server-side or to an env var, and rotate it.",
      });
    }
  }

  // Shape 2: process.env.X = "literal" overwrite.
  if (n.type === "AssignmentExpression" && n.operator === "=") {
    const left = n.left as Node | undefined;
    const right = n.right;
    if (left && isProcessEnvMember(left) && isStringLiteral(right) && looksSecret(right.value)) {
      const loc = (right as Node).loc?.start ?? n.loc?.start;
      const prop = (left.property as { name?: string } | undefined)?.name ?? "X";
      out.push({
        pattern: "AST_PROCESS_ENV_OVERWRITE",
        severity: AST_SEVERITY,
        file: filePath,
        line: loc?.line ?? 0,
        column: (loc?.column ?? 0) + 1,
        match: maskMatch(right.value),
        preview: `process.env.${prop} = "${maskMatch(right.value)}"`,
        remediation:
          "Assigning a hardcoded secret onto process.env defeats env-var hygiene. Set it in your environment, not in source, and rotate it.",
      });
    }
  }

  // Recurse into child nodes (skip loc/comments/tokens metadata).
  for (const key of Object.keys(n)) {
    if (key === "loc" || key === "start" || key === "end" || key === "range") continue;
    walk(n[key], filePath, out, seen);
  }
}

const PARSEABLE_EXT = /\.(?:[mc]?[jt]sx?)$/i;

/** True when the file extension is one @babel/parser can handle here. */
export function isParseable(filePath: string): boolean {
  return PARSEABLE_EXT.test(filePath);
}

/**
 * Layer C scan over a single source file. Parse failures yield [] — never
 * throw, so a syntax-error file doesn't blind the whole scan.
 */
export function scanAst(text: string, filePath: string): SecretFinding[] {
  if (!isParseable(filePath)) return [];
  let ast: unknown;
  try {
    ast = parse(text, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: [
        "jsx",
        "typescript",
        "decorators-legacy",
        "classProperties",
        "topLevelAwait",
        "importAttributes",
      ],
    });
  } catch {
    return [];
  }
  const out: SecretFinding[] = [];
  walk((ast as { program?: unknown }).program ?? ast, filePath, out, new WeakSet());
  return out;
}
