// Crypto / PII orchestrator (concern #4; spec §4.4, synthesis §3.4; checklist 3.1).
//
// Follows the established orchestration pattern (Phase 1.6 / Phase 2): probe for
// the tool of record (Semgrep CE for crypto rules, Presidio for free-text PII),
// defer when present, run the in-house TypeScript baseline when absent and
// surface the tool as a Band-4 complement. Severity re-classification + findings
// writing happen in the mappers; this returns the concern-shaped result.
//
// In-house baseline passes:
//   - primitives  — deprecated/weak crypto call sites (MD5/SHA1 security use,
//     dead ciphers, ECB, CBC-without-MAC, legacy createCipher)
//   - password-hashing — bcrypt cost / Argon2 params / unsalted SHA / plaintext
//     compare; legacy-migration is informational-not-finding
//   - jwt-audit  — `none` algo, missing algorithms: constraint, short secret
//   - pii-inventory — schema parse (Prisma/Drizzle/Zod/Yup) + client-side key leak
//   - pii-in-logs — PII flowing into console / third-party trackers

import { walkSource } from "../source-walk.js";
import { scanPrimitives, type PrimitiveFinding } from "./primitives.js";
import {
  scanPasswordHashing,
  type PasswordHashFinding,
  type MigrationSignal,
} from "./password-hashing.js";
import { scanJwt, type JwtFinding } from "./jwt-audit.js";
import {
  scanPiiInventory,
  scanClientKeyLeak,
  type PiiField,
  type PiiCategory,
  type ClientKeyLeak,
} from "./pii-inventory.js";
import { scanPiiInLogs, type PiiLogFinding } from "./pii-in-logs.js";
import {
  detectToolOfRecord,
  SEMGREP_TOOL_CANDIDATES,
  type ToolProbe,
  defaultToolProbe,
} from "../../orchestration/tool-registry.js";

export interface CryptoPiiScanResult {
  primitives: PrimitiveFinding[];
  passwordHashing: PasswordHashFinding[];
  /** Legacy-migration signals — informational-not-finding (kept for the report). */
  migrations: MigrationSignal[];
  jwt: JwtFinding[];
  /** The signature artifact: per-field PII inventory. */
  piiInventory: PiiField[];
  clientKeyLeaks: ClientKeyLeak[];
  piiInLogs: PiiLogFinding[];
  /**
   * When Semgrep is present we'd defer the crypto-rule pass; in v0.2 the in-house
   * baseline always runs. This flag records whether Semgrep is available so the
   * report can credit it / surface it as a Band-4 complement.
   */
  semgrepAvailable: boolean;
}

export interface CryptoPiiScanOptions {
  probe?: ToolProbe;
}

/** Run the full crypto/PII pass over a project. */
export function scanCryptoPii(
  projectRoot: string,
  opts: CryptoPiiScanOptions = {},
): CryptoPiiScanResult {
  const probe = opts.probe ?? defaultToolProbe;
  const semgrep = detectToolOfRecord(SEMGREP_TOOL_CANDIDATES, probe);

  // In-house baseline. Walk the source tree once, fan each scanner across it.
  const primitives = walkSource(projectRoot, [scanPrimitives]);
  const jwt = walkSource(projectRoot, [scanJwt]);
  const clientKeyLeaks = walkSource(projectRoot, [scanClientKeyLeak]);
  const piiInLogs = walkSource(projectRoot, [scanPiiInLogs]);

  // password-hashing returns findings + migrations per file — fold them.
  const passwordHashing: PasswordHashFinding[] = [];
  const migrations: MigrationSignal[] = [];
  for (const r of walkSource(projectRoot, [
    (text, rel) => [scanPasswordHashing(text, rel)],
  ])) {
    passwordHashing.push(...r.findings);
    migrations.push(...r.migrations);
  }

  // PII inventory: include .prisma schema files too (walkSource is source-only,
  // so Prisma schemas are scanned via the inventory's own file read below).
  const piiInventory = [
    ...walkSource(projectRoot, [scanPiiInventory]),
    ...scanPrismaSchemas(projectRoot),
  ];

  return {
    primitives,
    passwordHashing,
    migrations,
    jwt,
    piiInventory,
    clientKeyLeaks,
    piiInLogs,
    semgrepAvailable: Boolean(semgrep?.present),
  };
}

// .prisma files aren't a source extension walkSource covers; read them directly.
import fs from "node:fs";
import path from "node:path";

function scanPrismaSchemas(projectRoot: string): PiiField[] {
  const candidates = [
    "schema.prisma",
    "prisma/schema.prisma",
    "src/prisma/schema.prisma",
    "db/schema.prisma",
  ];
  const out: PiiField[] = [];
  for (const rel of candidates) {
    try {
      const text = fs.readFileSync(path.join(projectRoot, rel), "utf8");
      out.push(...scanPiiInventory(text, rel));
    } catch {
      // not present — skip
    }
  }
  return out;
}

export {
  scanPrimitives,
  scanPasswordHashing,
  scanJwt,
  scanPiiInventory,
  scanClientKeyLeak,
  scanPiiInLogs,
};
export type {
  PrimitiveFinding,
  PasswordHashFinding,
  MigrationSignal,
  JwtFinding,
  PiiField,
  PiiCategory,
  ClientKeyLeak,
  PiiLogFinding,
};
