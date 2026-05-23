// Secret-detection Layer A scan-tree (spec §4.2, checklist 1.6).
//
// The in-house fallback: walk a working tree, run the regex catalog, apply the
// example/sample path-downgrade and placeholder filters, and mask matches so a
// raw secret is never persisted. Mirrors the CLI's scanText/scanRepo logic but
// emits structured SecretFinding records the orchestration layer can map into
// the findings.jsonl schema.

import fs from "node:fs";
import path from "node:path";
import {
  SECRET_PATTERNS,
  PATH_SKIP_REGEX,
  FILENAME_HINT_REGEX,
  BINARY_EXT,
  KNOWN_PLACEHOLDERS,
} from "./patterns.js";
import type { Severity } from "../../types.js";

export interface SecretFinding {
  pattern: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  /** Masked — never the raw secret. */
  match: string;
  preview: string;
  remediation: string;
}

export interface ScanResult {
  findings: SecretFinding[];
  filesScanned: number;
}

const MAX_FILE_BYTES = 1024 * 1024; // skip files > 1 MB, as the CLI did.

function isBinary(filename: string): boolean {
  return BINARY_EXT.has(path.extname(filename).toLowerCase());
}

function shouldSkipPath(rel: string): boolean {
  return PATH_SKIP_REGEX.test(rel);
}

function* walk(dir: string, root: string): Generator<{ full: string; rel: string }> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full).replace(/\\/g, "/");
    if (shouldSkipPath(rel)) continue;
    if (entry.isDirectory()) {
      yield* walk(full, root);
    } else if (entry.isFile()) {
      if (isBinary(entry.name)) continue;
      yield { full, rel };
    }
  }
}

/**
 * Example/sample/mock path downgrade — a critical match in a fixture file is
 * not a live-credential leak. Critical → medium, High → low (preserved from CLI).
 */
export function downgradeForContext(severity: Severity, filename: string): Severity {
  if (FILENAME_HINT_REGEX.test(filename)) {
    if (severity === "critical") return "medium";
    if (severity === "high") return "low";
  }
  return severity;
}

function lineColumn(text: string, index: number): { line: number; col: number } {
  let line = 1;
  let col = 1;
  for (let i = 0; i < index; i++) {
    if (text[i] === "\n") {
      line++;
      col = 1;
    } else {
      col++;
    }
  }
  return { line, col };
}

export function maskMatch(s: string): string {
  if (s.length <= 8) return s[0] + "…" + s[s.length - 1];
  return s.slice(0, 6) + "…" + s.slice(-4);
}

function previewAt(text: string, index: number, matchLen: number): string {
  const before = Math.max(0, text.lastIndexOf("\n", index - 1) + 1);
  const after = text.indexOf("\n", index + matchLen);
  const end = after === -1 ? text.length : after;
  const line = text.slice(before, end);
  const full = text.slice(index, index + matchLen);
  const masked = line.split(full).join(maskMatch(full));
  return masked.trim().slice(0, 160);
}

/** Run the Layer A catalog over a single text blob. */
export function scanText(text: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const p of SECRET_PATTERNS) {
    // Reset lastIndex — the global regexes are reused across files.
    p.regex.lastIndex = 0;
    for (const m of text.matchAll(p.regex)) {
      const matched = m[0];
      if (KNOWN_PLACEHOLDERS.has(matched)) continue;
      const idx = m.index ?? 0;
      const { line, col } = lineColumn(text, idx);
      findings.push({
        pattern: p.name,
        severity: downgradeForContext(p.severity, filePath),
        file: filePath,
        line,
        column: col,
        match: maskMatch(matched),
        preview: previewAt(text, idx, matched.length),
        remediation: p.remediation,
      });
    }
  }
  return findings;
}

/** Walk a directory tree and scan every text file. */
export function scanTree(root: string): ScanResult {
  return scanTreeWith(root, [scanText]);
}

/** A per-file layer: text + path → findings. Layers A/B/C all conform. */
export type ScanLayer = (text: string, filePath: string) => SecretFinding[];

/**
 * Dedup key for a finding — a byte range can be matched by more than one layer
 * (e.g. Layer A regex + Layer B entropy on the same token). Keep the first,
 * which is the higher-precision layer when layers are ordered A→B→C.
 */
function findingKey(f: SecretFinding): string {
  return `${f.file}:${f.line}:${f.column}`;
}

/**
 * Walk a tree running an ordered list of layers per file, deduping overlapping
 * matches by file:line:column (first layer wins). This is how the in-house
 * fallback composes Layer A (regex) + B (entropy) + C (AST).
 */
export function scanTreeWith(root: string, layers: readonly ScanLayer[]): ScanResult {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();
  let filesScanned = 0;
  const resolved = path.resolve(root);
  for (const { full, rel } of walk(resolved, resolved)) {
    let text: string;
    try {
      const stat = fs.statSync(full);
      if (stat.size > MAX_FILE_BYTES) continue;
      text = fs.readFileSync(full, "utf8");
    } catch {
      continue;
    }
    filesScanned++;
    for (const layer of layers) {
      for (const f of layer(text, rel)) {
        const key = findingKey(f);
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(f);
      }
    }
  }
  return { findings, filesScanned };
}
