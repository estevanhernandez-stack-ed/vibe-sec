// Secret-detection Layer B — entropy (spec §4.2, synthesis §3.2).
//
// Layer A (regex) catches known provider prefixes. Layer B catches the
// generic high-entropy blob that has no telltale prefix — a 40-char random
// token assigned to a config field. The math: Shannon entropy over a candidate
// token, with separate thresholds for the two alphabets a secret usually lives
// in (base64-ish ≥4.5, hex ≥3.0), and a 20-char floor so short words don't
// trip it.
//
// This is deliberately conservative — entropy is the noisiest layer, so it
// only fires inside assignment context (the token is the RHS of a key/secret/
// token-shaped name) to keep the 12% FP budget intact. Whole-file entropy
// sweeps are a v0.3 concern.

import type { Severity } from "../../types.js";
import { maskMatch } from "./scan-tree.js";
import type { SecretFinding } from "./scan-tree.js";

/** Shannon entropy in bits-per-character for a string. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const BASE64_ENTROPY_THRESHOLD = 4.5;
export const HEX_ENTROPY_THRESHOLD = 3.0;
export const MIN_TOKEN_LENGTH = 20;

const HEX_RE = /^[0-9a-fA-F]+$/;
const BASE64ISH_RE = /^[A-Za-z0-9+/=_-]+$/;

/**
 * Does this token clear the entropy bar for its alphabet? Hex strings get the
 * lower 3.0 bar (only 16 symbols → max entropy 4.0); base64-ish gets 4.5.
 */
export function isHighEntropyToken(token: string): boolean {
  if (token.length < MIN_TOKEN_LENGTH) return false;
  const entropy = shannonEntropy(token);
  if (HEX_RE.test(token)) return entropy >= HEX_ENTROPY_THRESHOLD;
  if (BASE64ISH_RE.test(token)) return entropy >= BASE64_ENTROPY_THRESHOLD;
  return false;
}

// Assignment context: a secret-shaped name on the LHS, the token quoted on the
// RHS. We capture the value group so we measure entropy on the secret, not the
// surrounding syntax.
const ASSIGN_CONTEXT_RE =
  /\b([A-Za-z_][A-Za-z0-9_]*(?:key|secret|token|password|passwd|pwd|auth|credential|apikey|access)[A-Za-z0-9_]*)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,})["']/gi;

function lineOf(text: string, index: number): { line: number; col: number } {
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

/**
 * Entropy severity is intentionally Medium — a high-entropy blob with no
 * provider prefix is "worth reviewing," not a confirmed live credential.
 * Tier calibration + the amplifier upgrade it where context warrants.
 */
const ENTROPY_SEVERITY: Severity = "medium";

/**
 * Scan a text blob for high-entropy secrets in assignment context. Skips
 * tokens that any Layer A pattern would already catch (the caller dedupes by
 * file:line:column so the two layers don't double-count the same byte range).
 */
export function scanEntropy(text: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  ASSIGN_CONTEXT_RE.lastIndex = 0;
  for (const m of text.matchAll(ASSIGN_CONTEXT_RE)) {
    const token = m[2] ?? "";
    if (!isHighEntropyToken(token)) continue;
    const valueStart = (m.index ?? 0) + m[0].indexOf(token);
    const { line, col } = lineOf(text, valueStart);
    findings.push({
      pattern: "HIGH_ENTROPY_ASSIGN",
      severity: ENTROPY_SEVERITY,
      file: filePath,
      line,
      column: col,
      match: maskMatch(token),
      preview: `${m[1]} = "${maskMatch(token)}"`,
      remediation:
        "High-entropy value assigned to a secret-shaped name. If this is a real credential, move it to an env var and rotate it. If it's a hash or random ID, ignore.",
    });
  }
  return findings;
}
