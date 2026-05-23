import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runCli, type CliIo } from "./cli.js";
import type { ToolProbe } from "./orchestration/tool-registry.js";

// Force the in-house Layer A path so exit codes are deterministic and
// comparable to the legacy CLI (which is pure-regex, no external tools).
// The default probe shells out to gitleaks if installed — not what these
// parity tests are asserting.
const noTools: ToolProbe = (tool) => ({ name: tool, present: false, version: null });
const inHouse = { probe: noTools };

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-cli-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const AWS = "AKIA" + "ABCDEFGHIJ234567";
const STRIPE_TEST = "sk_test_" + "0123456789abcdefABCDEF99";

function silentIo(): CliIo {
  return { stdout: () => {}, stderr: () => {}, isTty: false };
}

// Resolve the legacy CLI path so we can compare exit codes against it.
const here = path.dirname(fileURLToPath(import.meta.url));
const legacyCli = path.resolve(here, "..", "..", "vibe-sec-cli", "src", "index.js");

function legacyExit(args: string[]): number {
  try {
    execFileSync("node", [legacyCli, ...args], { stdio: "ignore" });
    return 0;
  } catch (ex) {
    return (ex as { status?: number }).status ?? -1;
  }
}

describe("CLI exit-code contract", () => {
  it("clean tree → exit 0", () => {
    fs.writeFileSync(path.join(tmp, "hello.ts"), "export const x = 1;\n");
    expect(runCli(["node", "cli", "--root", tmp], silentIo(), inHouse)).toBe(0);
  });

  it("AWS leak at default min-severity (high) → exit 1", () => {
    fs.writeFileSync(path.join(tmp, "config.js"), `const k = "${AWS}";`);
    expect(runCli(["node", "cli", "--root", tmp], silentIo(), inHouse)).toBe(1);
  });

  it("medium-only finding at default min-severity (high) → exit 0", () => {
    // Stripe TEST key is medium; with --min-severity high it should not breach.
    fs.writeFileSync(path.join(tmp, "billing.ts"), `const k = "${STRIPE_TEST}";`);
    expect(runCli(["node", "cli", "--root", tmp], silentIo(), inHouse)).toBe(0);
  });

  it("medium finding with --min-severity medium → exit 1", () => {
    fs.writeFileSync(path.join(tmp, "billing.ts"), `const k = "${STRIPE_TEST}";`);
    expect(
      runCli(["node", "cli", "--root", tmp, "--min-severity", "medium"], silentIo(), inHouse),
    ).toBe(1);
  });

  it("invalid --min-severity → exit 2", () => {
    expect(
      runCli(["node", "cli", "--root", tmp, "--min-severity", "bananas"], silentIo(), inHouse),
    ).toBe(2);
  });

  it("--help → exit 0", () => {
    expect(runCli(["node", "cli", "--help"], silentIo())).toBe(0);
  });

  it("--version → exit 0", () => {
    expect(runCli(["node", "cli", "--version"], silentIo())).toBe(0);
  });
});

describe("exit-code parity with the legacy CLI", () => {
  it("clean tree: legacy 0 === re-export 0", () => {
    fs.writeFileSync(path.join(tmp, "hello.ts"), "export const x = 1;\n");
    const legacy = legacyExit(["--root", tmp, "--output", path.join(tmp, "legacy.json")]);
    const reexport = runCli(
      ["node", "cli", "--root", tmp, "--output", path.join(tmp, "re.json")],
      silentIo(),
      inHouse,
    );
    expect(legacy).toBe(0);
    expect(reexport).toBe(legacy);
  });

  it("AWS leak: legacy 1 === re-export 1", () => {
    fs.writeFileSync(path.join(tmp, "config.js"), `const k = "${AWS}";`);
    const legacy = legacyExit(["--root", tmp, "--output", path.join(tmp, "legacy.json")]);
    const reexport = runCli(
      ["node", "cli", "--root", tmp, "--output", path.join(tmp, "re.json")],
      silentIo(),
      inHouse,
    );
    expect(legacy).toBe(1);
    expect(reexport).toBe(legacy);
  });

  it("invalid arg: legacy 2 === re-export 2", () => {
    const legacy = legacyExit(["--min-severity", "bananas", "--root", tmp]);
    const reexport = runCli(
      ["node", "cli", "--root", tmp, "--min-severity", "bananas"],
      silentIo(),
      inHouse,
    );
    expect(legacy).toBe(2);
    expect(reexport).toBe(legacy);
  });
});
