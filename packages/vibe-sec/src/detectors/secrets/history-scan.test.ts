import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanHistory } from "./history-scan.js";
import { readHistoryScanCache } from "../../state/history-scan.js";

let tmp: string;

// A secret committed then deleted — the canonical "it's gone from HEAD but
// still in history" case. Built via concatenation to dodge push-protection.
const AWS = "AKIA" + "ABCDEFGHIJ234567";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

function initRepo(dir: string): void {
  git(["init", "-q"], dir);
  git(["config", "user.email", "test@example.com"], dir);
  git(["config", "user.name", "Test"], dir);
  git(["config", "commit.gpgsign", "false"], dir);
}

function commit(dir: string, msg: string): void {
  git(["add", "-A"], dir);
  git(["commit", "-q", "-m", msg], dir);
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-history-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("git-history secret scan", () => {
  it("finds a secret committed in a PRIOR commit and later deleted", () => {
    initRepo(tmp);
    // Commit 1: README (clean).
    fs.writeFileSync(path.join(tmp, "README.md"), "# Project\n");
    commit(tmp, "init");
    // Commit 2: a leaked AWS key in config.js.
    fs.writeFileSync(path.join(tmp, "config.js"), `const k = "${AWS}";\n`);
    commit(tmp, "add config");
    // Commit 3: remove the secret — gone from HEAD, still in history.
    fs.rmSync(path.join(tmp, "config.js"));
    commit(tmp, "remove config");

    const result = scanHistory(tmp);
    expect(result.mode).toBe("full");
    const aws = result.findings.find((f) => f.pattern === "AWS_ACCESS_KEY_ID");
    expect(aws).toBeDefined();
    expect(aws?.historical_path).toBe("config.js");
    expect(aws?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(aws?.match).not.toBe(AWS); // masked
  });

  it("writes the cache and goes incremental on the second run", () => {
    initRepo(tmp);
    fs.writeFileSync(path.join(tmp, "a.txt"), "hello\n");
    commit(tmp, "init");

    const first = scanHistory(tmp);
    expect(first.mode).toBe("full");
    const cache = readHistoryScanCache(tmp);
    expect(cache.full_scan_done).toBe(true);
    expect(cache.last_scanned_commit).toMatch(/^[0-9a-f]{40}$/);

    // No new commits → incremental, zero commits scanned.
    const second = scanHistory(tmp);
    expect(second.mode).toBe("incremental");
    expect(second.commitsScanned).toBe(0);
  });

  it("returns empty (no throw) on a non-git directory", () => {
    const result = scanHistory(tmp); // tmp is not a git repo
    expect(result.findings).toEqual([]);
    expect(result.commitsScanned).toBe(0);
  });

  it("scans only new commits incrementally after the first run", () => {
    initRepo(tmp);
    fs.writeFileSync(path.join(tmp, "a.txt"), "first\n");
    commit(tmp, "c1");
    scanHistory(tmp); // full, caches HEAD

    // New commit introduces a secret.
    fs.writeFileSync(path.join(tmp, "leak.js"), `const k = "${AWS}";\n`);
    commit(tmp, "c2 leak");

    const inc = scanHistory(tmp);
    expect(inc.mode).toBe("incremental");
    expect(inc.commitsScanned).toBe(1); // only the new commit
    expect(inc.findings.some((f) => f.pattern === "AWS_ACCESS_KEY_ID")).toBe(true);
  });
});
