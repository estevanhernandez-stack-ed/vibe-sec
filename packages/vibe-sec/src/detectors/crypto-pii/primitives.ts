// Crypto primitives — deprecated-primitive call sites (spec §4.4, synthesis §3.4).
//
// AEAD or bust. The two defensible symmetric choices are AES-256-GCM and
// ChaCha20-Poly1305. Everything else listed here is dead for confidentiality:
//   - MD5 / SHA1 used as a security primitive (password hash, HMAC, signature)
//   - DES / 3DES / RC4 ciphers
//   - AES in ECB mode, or CBC without an authenticating MAC
//   - createCipher (the legacy, IV-less node API) — always wrong
//
// The hard part is precision: MD5/SHA1 are legitimate for non-security checksums
// (ETags, cache keys, content-addressing). We flag the call site but downgrade
// the severity when the surrounding context reads "checksum/etag/cache" — same
// discipline the secret detector uses for example/sample paths. createCipher and
// the dead ciphers have no defensible use, so they stay High.

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface PrimitiveFinding {
  finding_type:
    | "weak-hash-primitive"
    | "dead-cipher"
    | "ecb-mode"
    | "cbc-without-mac"
    | "legacy-createcipher";
  severity: Severity;
  primitive: string;
  file: string;
  line: number;
  detail: string;
}

// `createHash('md5')` / `createHash("sha1")` and crypto.createHmac('md5', …).
const WEAK_HASH_RE = /\bcreate(?:Hash|Hmac)\s*\(\s*["'`](md5|sha1)["'`]/gi;
// Dead ciphers by name in createCipheriv / algorithm strings.
const DEAD_CIPHER_RE = /["'`](des|des-ede3|des-ede3-cbc|rc4|rc4-40|3des)["'`]/gi;
// AES-ECB mode — no IV, leaks structure.
const ECB_RE = /["'`]aes-(?:128|192|256)-ecb["'`]/gi;
// AES-CBC — defensible only with a separate MAC; we flag and ask the builder.
const CBC_RE = /["'`]aes-(?:128|192|256)-cbc["'`]/gi;
// The legacy IV-less createCipher / createDecipher (NOT createCipheriv).
const LEGACY_CIPHER_RE = /\bcreate(?:Cipher|Decipher)\s*\(/g;

// Context that downgrades a weak-hash finding to informational: a non-security
// use of md5/sha1 (content addressing, cache keys, ETags).
const CHECKSUM_CONTEXT_RE = /\b(?:checksum|etag|cache[_-]?key|content[_-]?hash|integrity[_-]?hash|fingerprint)\b/i;
// Context that confirms a weak-hash finding is a security use → keep severity up.
const SECURITY_CONTEXT_RE = /\b(?:password|passwd|secret|token|signature|sign|verify|hmac|salt|hash[_-]?password)\b/i;

function contextAround(text: string, index: number): string {
  const start = Math.max(0, index - 120);
  const end = Math.min(text.length, index + 120);
  return text.slice(start, end);
}

/** Scan a single source file for deprecated/weak crypto primitive call sites. */
export function scanPrimitives(text: string, filePath: string): PrimitiveFinding[] {
  const findings: PrimitiveFinding[] = [];

  WEAK_HASH_RE.lastIndex = 0;
  for (const m of text.matchAll(WEAK_HASH_RE)) {
    const idx = m.index ?? 0;
    const algo = (m[1] ?? "").toLowerCase();
    const ctx = contextAround(text, idx);
    // A security context (password/HMAC/signature) keeps it High; a checksum
    // context downgrades to Low (informational-grade, not a finding to block on).
    let severity: Severity = "medium";
    if (SECURITY_CONTEXT_RE.test(ctx)) severity = "high";
    else if (CHECKSUM_CONTEXT_RE.test(ctx)) severity = "low";
    findings.push({
      finding_type: "weak-hash-primitive",
      severity,
      primitive: algo,
      file: filePath,
      line: lineOf(text, idx),
      detail:
        severity === "low"
          ? `${algo.toUpperCase()} used in what looks like a non-security checksum context. Fine for content addressing; never use it for passwords, HMACs, or signatures.`
          : `${algo.toUpperCase()} is cryptographically broken for security use. Use SHA-256+ for integrity, and a password hash (Argon2id/bcrypt) for credentials.`,
    });
  }

  ECB_RE.lastIndex = 0;
  for (const m of text.matchAll(ECB_RE)) {
    const idx = m.index ?? 0;
    findings.push({
      finding_type: "ecb-mode",
      severity: "high",
      primitive: "aes-ecb",
      file: filePath,
      line: lineOf(text, idx),
      detail:
        "AES-ECB mode encrypts identical plaintext blocks to identical ciphertext — it leaks structure. Use an AEAD mode (AES-256-GCM or ChaCha20-Poly1305).",
    });
  }

  CBC_RE.lastIndex = 0;
  for (const m of text.matchAll(CBC_RE)) {
    const idx = m.index ?? 0;
    findings.push({
      finding_type: "cbc-without-mac",
      severity: "medium",
      primitive: "aes-cbc",
      file: filePath,
      line: lineOf(text, idx),
      detail:
        "AES-CBC is only safe paired with a separate MAC (encrypt-then-MAC). Prefer an AEAD mode (AES-256-GCM or ChaCha20-Poly1305), which authenticates as part of the construction.",
    });
  }

  DEAD_CIPHER_RE.lastIndex = 0;
  for (const m of text.matchAll(DEAD_CIPHER_RE)) {
    const idx = m.index ?? 0;
    const algo = (m[1] ?? "").toLowerCase();
    findings.push({
      finding_type: "dead-cipher",
      severity: "high",
      primitive: algo,
      file: filePath,
      line: lineOf(text, idx),
      detail: `${algo.toUpperCase()} is a dead cipher. Use AES-256-GCM or ChaCha20-Poly1305.`,
    });
  }

  LEGACY_CIPHER_RE.lastIndex = 0;
  for (const m of text.matchAll(LEGACY_CIPHER_RE)) {
    const idx = m.index ?? 0;
    findings.push({
      finding_type: "legacy-createcipher",
      severity: "high",
      primitive: "createCipher",
      file: filePath,
      line: lineOf(text, idx),
      detail:
        "createCipher/createDecipher derive a key from a password with no IV and are deprecated. Use createCipheriv with a random IV and an AEAD mode.",
    });
  }

  return findings;
}
