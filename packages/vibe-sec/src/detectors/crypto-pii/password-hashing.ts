// Password hashing — cost-factor + algorithm audit (spec §4.4, synthesis §3.4).
//
// Argon2id is the 2026 ceiling; bcrypt cost-12 is the floor. The findings:
//   - bcrypt.hash(pw, N) / genSaltSync(N) with N < 12  → cost below the floor.
//     bcrypt(pw, 10) is the 2018 bar — flag High at Public-facing+ (tier scaling
//     happens in the mapper; the detector reports the base severity).
//   - Argon2 with memoryCost / timeCost below the OWASP minimums (m=19456 KiB,
//     t=2) → weak params.
//   - Plaintext / reversible password storage signals: comparing a password with
//     === to a stored value, or storing it without any hash call nearby.
//   - Unsalted SHA used directly on a password (createHash('sha256')(password)).
//
// Legacy-hash migration (dual-path `if (passwordVersion === 1) …`) is NOT a
// finding — it's the correct pattern. We detect it and emit informational only,
// surfaced via `migration: true` so the mapper can skip it (spec §4.4, Decision:
// "legacy-hash-migration = informational-not-finding").

import { lineOf } from "../source-walk.js";
import type { Severity } from "../../types.js";

export interface PasswordHashFinding {
  finding_type:
    | "bcrypt-cost-below-floor"
    | "argon2-weak-params"
    | "unsalted-password-hash"
    | "plaintext-password-compare";
  severity: Severity;
  file: string;
  line: number;
  detail: string;
  /** Cost factor / param value, when the finding is numeric. */
  observed: number | null;
}

export interface MigrationSignal {
  file: string;
  line: number;
  detail: string;
  /** Always true — this is informational-not-finding (Decision). */
  migration: true;
}

export interface PasswordHashScan {
  findings: PasswordHashFinding[];
  /** Dual-path legacy-hash migrations — informational, never findings. */
  migrations: MigrationSignal[];
}

const BCRYPT_FLOOR = 12;
const ARGON2_MIN_MEMORY = 19456; // KiB, OWASP minimum
const ARGON2_MIN_TIME = 2;

// bcrypt.hash(pw, 10) / bcrypt.hashSync(pw, 8) — second arg is the cost.
const BCRYPT_HASH_RE = /\bbcrypt(?:\.\w+)?\.hash(?:Sync)?\s*\([^,]+,\s*(\d{1,2})\s*[),]/g;
// bcrypt.genSalt(10) / genSaltSync(8).
const BCRYPT_SALT_RE = /\bgenSalt(?:Sync)?\s*\(\s*(\d{1,2})\s*\)/g;
// argon2 memoryCost / timeCost options.
const ARGON2_MEMORY_RE = /\bmemoryCost\s*:\s*(\d+)/g;
const ARGON2_TIME_RE = /\btimeCost\s*:\s*(\d+)/g;
// createHash('sha256').update(password) — unsalted SHA on a password.
const UNSALTED_SHA_RE =
  /createHash\s*\(\s*["'`]sha(?:1|256|512)["'`]\s*\)\s*\.update\s*\([^)]*\bpass(?:word|wd)?\b/gi;
// `password === storedPassword` / `pw == user.password` — plaintext compare.
const PLAINTEXT_COMPARE_RE =
  /\b(?:password|passwd|pwd)\b\s*={2,3}\s*\b\w*(?:password|passwd|pwd|hash)?\b/gi;
// Dual-path legacy migration: a version branch around a re-hash.
const MIGRATION_RE =
  /\bpassword(?:Version|Hash(?:Version)?|Algo(?:rithm)?)\b\s*={2,3}\s*(?:["'`]?\w+["'`]?)/gi;

/** Scan one source file for password-hashing weaknesses + migration signals. */
export function scanPasswordHashing(text: string, filePath: string): PasswordHashScan {
  const findings: PasswordHashFinding[] = [];
  const migrations: MigrationSignal[] = [];

  for (const re of [BCRYPT_HASH_RE, BCRYPT_SALT_RE]) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const cost = Number(m[1]);
      if (Number.isFinite(cost) && cost < BCRYPT_FLOOR) {
        findings.push({
          finding_type: "bcrypt-cost-below-floor",
          severity: "high",
          file: filePath,
          line: lineOf(text, m.index ?? 0),
          observed: cost,
          detail: `bcrypt cost factor ${cost} is below the recommended floor of ${BCRYPT_FLOOR}. Raise it to ${BCRYPT_FLOOR}+ — cost ${cost} is roughly the 2018 bar and is too cheap to brute-force against in 2026.`,
        });
      }
    }
  }

  ARGON2_MEMORY_RE.lastIndex = 0;
  for (const m of text.matchAll(ARGON2_MEMORY_RE)) {
    const mem = Number(m[1]);
    if (Number.isFinite(mem) && mem < ARGON2_MIN_MEMORY) {
      findings.push({
        finding_type: "argon2-weak-params",
        severity: "high",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        observed: mem,
        detail: `Argon2 memoryCost ${mem} KiB is below the OWASP minimum of ${ARGON2_MIN_MEMORY} KiB. Raise it — low memory cost defeats Argon2's memory-hardness.`,
      });
    }
  }

  ARGON2_TIME_RE.lastIndex = 0;
  for (const m of text.matchAll(ARGON2_TIME_RE)) {
    const t = Number(m[1]);
    if (Number.isFinite(t) && t < ARGON2_MIN_TIME) {
      findings.push({
        finding_type: "argon2-weak-params",
        severity: "medium",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        observed: t,
        detail: `Argon2 timeCost ${t} is below the OWASP minimum of ${ARGON2_MIN_TIME}.`,
      });
    }
  }

  UNSALTED_SHA_RE.lastIndex = 0;
  for (const m of text.matchAll(UNSALTED_SHA_RE)) {
    findings.push({
      finding_type: "unsalted-password-hash",
      severity: "high",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      observed: null,
      detail:
        "A bare SHA hash on a password is unsalted and fast — both fatal for credential storage. Use Argon2id or bcrypt cost-12+, which are salted and deliberately slow.",
    });
  }

  PLAINTEXT_COMPARE_RE.lastIndex = 0;
  for (const m of text.matchAll(PLAINTEXT_COMPARE_RE)) {
    // Skip when the compared value clearly references a hash (the safe shape is
    // bcrypt.compare, not ===; an === against a *hash* is still a smell but
    // weaker, so we keep it medium).
    const matched = m[0];
    const comparesHash = /hash/i.test(matched);
    findings.push({
      finding_type: "plaintext-password-compare",
      severity: comparesHash ? "medium" : "high",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      observed: null,
      detail: comparesHash
        ? "Comparing a password (or its hash) with === is not constant-time and can be a logic smell. Use the library's compare (e.g. bcrypt.compare), which is constant-time."
        : "Comparing a password with === suggests plaintext storage or a timing-vulnerable check. Hash with Argon2id/bcrypt and compare with the library's constant-time verify.",
    });
  }

  MIGRATION_RE.lastIndex = 0;
  for (const m of text.matchAll(MIGRATION_RE)) {
    migrations.push({
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      detail:
        "Dual-path password-hash migration detected (version/algorithm branch). This is the correct pattern — re-hash on next login. Informational only, not a finding.",
      migration: true,
    });
  }

  return { findings, migrations };
}
