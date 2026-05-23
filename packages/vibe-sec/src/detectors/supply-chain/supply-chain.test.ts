import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  parseWorkflowText,
  findActionsIssues,
  classifyRef,
} from "./actions-parse.js";
import { levenshtein, findTyposquats, findDepConfusion } from "./typosquat.js";
import { scanPostinstall } from "./postinstall.js";
import { detectSbom } from "./sbom-detect.js";
import { checkLockfileIntegrity, scanSupplyChain } from "./index.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-supply-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

describe("lockfile integrity + pinning — floating pins flagged", () => {
  it("flags `latest` and `*` floating pins", () => {
    write(
      "package.json",
      JSON.stringify({ dependencies: { chalk: "latest", debug: "*", express: "^4.18.0" } }),
    );
    write("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {} }));
    const r = checkLockfileIntegrity(tmp);
    expect(r.present).toBe(true);
    const names = r.floatingPins.map((p) => p.package);
    expect(names).toContain("chalk");
    expect(names).toContain("debug");
    expect(names).not.toContain("express"); // caret is fine
  });
});

describe("GitHub Actions ref-style + permissions", () => {
  it("classifies sha / tag / floating refs", () => {
    expect(classifyRef("a".repeat(40))).toBe("sha");
    expect(classifyRef("v4.1.0")).toBe("tag");
    expect(classifyRef("v4")).toBe("floating");
    expect(classifyRef("main")).toBe("branch");
  });

  it("flags an unpinned third-party Action and a missing permissions block", () => {
    const wf = `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-vendor/risky-action@v1
      - uses: pinned/action@${"b".repeat(40)}
`;
    const parsed = parseWorkflowText(wf, ".github/workflows/ci.yml");
    const issues = findActionsIssues([parsed]);
    const thirdParty = issues.find(
      (i) => i.finding_type === "unpinned-third-party-action" && i.action === "some-vendor/risky-action",
    );
    expect(thirdParty).toBeDefined();
    // SHA-pinned action is NOT flagged.
    expect(issues.find((i) => i.action === "pinned/action")).toBeUndefined();
    // No top-level permissions block → flagged.
    expect(issues.some((i) => i.finding_type === "missing-permissions-block")).toBe(true);
  });
});

describe("typosquat detection (Levenshtein ≤2)", () => {
  it("computes edit distance", () => {
    expect(levenshtein("expres", "express")).toBe(1);
    expect(levenshtein("express", "express")).toBe(0);
    expect(levenshtein("reakt", "react")).toBe(1);
  });

  it("flags `expres` as a typosquat of `express`", () => {
    write("package.json", JSON.stringify({ dependencies: { expres: "1.0.0" } }));
    const squats = findTyposquats(tmp);
    const expres = squats.find((s) => s.package === "expres");
    expect(expres).toBeDefined();
    expect(expres?.resembles).toBe("express");
    expect(expres?.distance).toBe(1);
  });

  it("does NOT flag the real package", () => {
    write("package.json", JSON.stringify({ dependencies: { express: "^4.18.0" } }));
    expect(findTyposquats(tmp)).toHaveLength(0);
  });
});

describe("dependency-confusion", () => {
  it("flags an org-scoped dep with no private registry configured", () => {
    write("package.json", JSON.stringify({ dependencies: { "@myco/internal": "1.0.0" } }));
    const findings = findDepConfusion(tmp, false);
    expect(findings.some((f) => f.package === "@myco/internal")).toBe(true);
  });

  it("does not flag known public scopes", () => {
    write("package.json", JSON.stringify({ dependencies: { "@babel/core": "^7.0.0" } }));
    expect(findDepConfusion(tmp, false)).toHaveLength(0);
  });
});

describe("postinstall inspection", () => {
  it("flags the project's own install hook", () => {
    write("package.json", JSON.stringify({ scripts: { postinstall: "node setup.js" } }));
    const r = scanPostinstall(tmp, { depth: 0 });
    expect(r.findings.some((f) => f.hook === "postinstall" && f.own)).toBe(true);
  });

  it("reads ignore-scripts mitigation from .npmrc", () => {
    write("package.json", "{}");
    write(".npmrc", "ignore-scripts=true\n");
    expect(scanPostinstall(tmp, { depth: 0 }).ignoreScriptsEnabled).toBe(true);
  });
});

describe("SBOM detection-only", () => {
  it("detects a CycloneDX bom.json when present", () => {
    write("bom.json", JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5" }));
    const r = detectSbom(tmp);
    expect(r.present).toBe(true);
    expect(r.format).toBe("cyclonedx");
  });

  it("reports absent when no SBOM file exists", () => {
    write("package.json", "{}");
    expect(detectSbom(tmp).present).toBe(false);
  });
});

describe("scanSupplyChain — fast subset skips typosquat round-trips", () => {
  it("fast mode skips typosquat + dep-confusion + postinstall", () => {
    write("package.json", JSON.stringify({ dependencies: { expres: "1.0.0" } }));
    const full = scanSupplyChain(tmp);
    const fast = scanSupplyChain(tmp, { fast: true });
    expect(full.typosquats.length).toBeGreaterThan(0);
    expect(fast.typosquats).toHaveLength(0);
    // Integrity check still runs in fast mode (it's in the :deps subset).
    expect(fast.integrity.present).toBeDefined();
  });
});
