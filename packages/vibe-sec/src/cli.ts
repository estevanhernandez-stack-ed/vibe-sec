#!/usr/bin/env node
// vibe-sec CLI — thin re-export over the promoted secret scanner (checklist 1.6).
//
// Preserves the legacy CLI's exit-code contract exactly:
//   0 — clean, or only findings below --min-severity
//   1 — findings at or above --min-severity
//   2 — scanner error (unreadable tree, invalid args, etc.)
//
// The detection logic now lives in src/detectors/secrets — this file is the
// headless-CI entry point. It defers to gitleaks/trufflehog when present and
// falls back to in-house Layer A when absent, same as /vibe-sec:scan.

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import {
  scanSecrets,
  type SecretScanResult,
  type SecretScanOptions,
} from "./detectors/secrets/index.js";
import type { SecretFinding } from "./detectors/secrets/scan-tree.js";
import type { Severity } from "./types.js";

export const VERSION = "0.2.0";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[41;97m",
  high: "\x1b[31;1m",
  medium: "\x1b[33m",
  low: "\x1b[90m",
};
const RESET = "\x1b[0m";

function countBySeverity(findings: readonly SecretFinding[]): Record<Severity, number> {
  const acc: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) acc[f.severity] += 1;
  return acc;
}

function usage(): string {
  return `vibe-sec scan · v${VERSION}

Usage:
  vibe-sec scan [options]
  vibe-sec [options]                   (same as 'scan')

Options:
  -r, --root <dir>         Root directory to scan                (default: cwd)
  -o, --output <file>      JSON report path                      (default: .vibe-sec/state/audit.json)
      --min-severity <lv>  Exit 1 at or above this level         (default: high)
                           Values: critical | high | medium | low
      --json               Print only JSON, no banner
      --no-color           Disable ANSI colors in the banner
  -h, --help               Show this message
  -v, --version            Show version number

Exit codes:
  0  clean, or findings below --min-severity
  1  findings at or above --min-severity
  2  scanner error

Defers to gitleaks/trufflehog when on PATH; in-house Layer A regex otherwise.
`;
}

function renderBanner(
  root: string,
  result: SecretScanResult,
  noColor: boolean,
  isTty: boolean,
): string {
  const { findings, filesScanned, toolOfRecord } = result;
  const counts = countBySeverity(findings);
  const useColor = isTty && !noColor;
  const color = useColor ? (c: string, s: string) => c + s + RESET : (_c: string, s: string) => s;
  const lines: string[] = [];
  const fileNote = filesScanned >= 0 ? `${filesScanned} files scanned` : `via ${toolOfRecord}`;
  lines.push("");
  lines.push(`  vibe-sec scan · v${VERSION} · ${toolOfRecord}`);
  lines.push(`  ${fileNote} · ${root}`);
  lines.push("");
  if (!findings.length) {
    lines.push(`  ${color("\x1b[32;1m", "✓")} No secrets detected.`);
    lines.push("");
    return lines.join("\n");
  }
  lines.push(`  Findings:`);
  for (const sev of ["critical", "high", "medium", "low"] as Severity[]) {
    if (counts[sev]) {
      lines.push(`    ${color(SEVERITY_COLORS[sev], sev.toUpperCase().padEnd(9))} ${counts[sev]}`);
    }
  }
  lines.push("");
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );
  for (const f of sorted.slice(0, 10)) {
    lines.push(
      `    ${color(SEVERITY_COLORS[f.severity], f.severity.padEnd(8))} ${f.pattern.padEnd(28)} ${f.file}:${f.line}:${f.column}`,
    );
  }
  if (sorted.length > 10) {
    lines.push(`    … and ${sorted.length - 10} more (see JSON report)`);
  }
  lines.push("");
  return lines.join("\n");
}

export interface CliIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  isTty: boolean;
}

const defaultIo: CliIo = {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  isTty: Boolean(process.stdout.isTTY),
};

/**
 * Run the CLI and RETURN the exit code (does not call process.exit). This is
 * the testable core — the exported wrapper at the bottom calls process.exit.
 * Exit-code parity with the legacy CLI is asserted in cli.test.ts.
 */
export function runCli(
  argv: string[],
  io: CliIo = defaultIo,
  scanOpts: SecretScanOptions = {},
): 0 | 1 | 2 {
  // Strip a leading 'scan' or legacy 'audit' positional (default subcommand).
  const args = argv
    .slice(2)
    .filter((a, i) => !(i === 0 && (a === "scan" || a === "audit")));

  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        root: { type: "string", short: "r" },
        output: { type: "string", short: "o" },
        "min-severity": { type: "string" },
        json: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (ex) {
    io.stderr(`error: ${(ex as Error).message}\n\n${usage()}`);
    return 2;
  }

  if (parsed.values.help) {
    io.stdout(usage());
    return 0;
  }
  if (parsed.values.version) {
    io.stdout(VERSION + "\n");
    return 0;
  }

  const root = path.resolve(parsed.values.root ?? process.cwd());
  const outRel = parsed.values.output ?? ".vibe-sec/state/audit.json";
  const minSeverity = (parsed.values["min-severity"] ?? "high") as Severity;
  if (!SEVERITY_ORDER[minSeverity]) {
    io.stderr("error: --min-severity must be one of critical|high|medium|low\n");
    return 2;
  }

  let result: SecretScanResult;
  try {
    result = scanSecrets(root, scanOpts);
  } catch (ex) {
    io.stderr(`scan failed: ${(ex as Error).message}\n`);
    return 2;
  }

  const { findings, filesScanned, toolOfRecord } = result;
  const report = {
    version: 1,
    scanner: "vibe-sec",
    scannerVersion: VERSION,
    toolOfRecord,
    scannedAt: new Date().toISOString(),
    rootDir: root,
    filesScanned,
    counts: countBySeverity(findings),
    findings,
  };

  const outPath = path.resolve(root, outRel);
  try {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  } catch (ex) {
    io.stderr(`warning: couldn't write report: ${(ex as Error).message}\n`);
  }

  if (parsed.values.json) {
    io.stdout(JSON.stringify(report, null, 2) + "\n");
  } else {
    io.stdout(renderBanner(root, result, Boolean(parsed.values["no-color"]), io.isTty));
    if (findings.length) {
      io.stdout(`  → JSON report: ${path.relative(root, outPath) || outPath}\n\n`);
    }
  }

  const breach = findings.some(
    (f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[minSeverity],
  );
  return breach ? 1 : 0;
}

// Entry point when invoked as the `vibe-sec` binary. Guarded so importing this
// module (e.g. from index.ts or tests) does not trigger a scan / process.exit.
//
// Detection is format-agnostic on purpose: comparing the invoked script's
// basename avoids `import.meta` (empty in CJS) and `require.main` (absent in
// ESM), so the same source builds cleanly to both formats. The published bin
// resolves to dist/cli.js.
function isMainBinary(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  const base = path.basename(entry).toLowerCase();
  return base === "cli.js" || base === "cli.cjs" || base === "vibe-sec";
}

if (isMainBinary()) {
  process.exit(runCli(process.argv));
}
