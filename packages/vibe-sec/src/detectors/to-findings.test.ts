import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanSecrets } from "./secrets/index.js";
import { scanDependencies, depCoverageAdvisory } from "./deps/index.js";
import { scanSupplyChain } from "./supply-chain/index.js";
import {
  resetFindingIds,
  secretToFinding,
  depToFinding,
  depNotCheckedToFinding,
  pinningToFinding,
  typosquatToFinding,
} from "./to-findings.js";
import type { SecretFinding } from "./secrets/scan-tree.js";
import { appendFindings, readFindings, validateFinding } from "../state/findings.js";
import type { CommandRunner } from "../orchestration/defer.js";
import type { ToolProbe } from "../orchestration/tool-registry.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-tofind-"));
  resetFindingIds();
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

const noTools: ToolProbe = (tool) => ({ name: tool, present: false, version: null });
const AWS = "AKIA" + "ABCDEFGHIJ234567";

const NPM_AUDIT_JSON = JSON.stringify({
  vulnerabilities: {
    lodash: {
      name: "lodash",
      severity: "high",
      range: "<4.17.12",
      via: [{ source: 1, name: "lodash", title: "Prototype Pollution", url: "https://github.com/advisories/GHSA-jf85-cpcp-j695", cvss: { score: 7.4 } }],
      fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
    },
  },
});

describe("2.5 — /vibe-sec:scan writes findings.jsonl over the full secret stack", () => {
  it("maps secret findings to the schema and persists them", () => {
    write("config.js", `const k = "${AWS}";`);
    const scan = scanSecrets(tmp, { probe: noTools, forceInhouse: true });
    const findings = scan.findings.map((f) => secretToFinding(f, "public-facing"));
    appendFindings(tmp, findings);

    const readBack = readFindings(tmp);
    expect(readBack.length).toBe(findings.length);
    expect(readBack.length).toBeGreaterThan(0);
    // Every persisted finding validates against the schema.
    for (const f of readBack) {
      expect(validateFinding(f)).toEqual([]);
      expect(f.primary_concern).toBe("secret-detection");
      // Raw secret never persisted — title/description carry no raw value.
      expect(JSON.stringify(f)).not.toContain(AWS);
    }
  });
});

describe("2.5 — /vibe-sec:deps writes findings.jsonl (CVE + integrity + pinning)", () => {
  it("runs the CVE + supply-chain subset and persists deduped findings", () => {
    write(
      "package.json",
      JSON.stringify({ name: "app", private: true, dependencies: { chalk: "latest", expres: "1.0.0" } }),
    );
    write("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {} }));

    const runner: CommandRunner = (cmd, args) => {
      if (cmd === "npm" && args.includes("audit")) return NPM_AUDIT_JSON;
      return "";
    };

    // CVE pass.
    const deps = scanDependencies(tmp, { probe: noTools, runner });
    // Supply-chain SUBSET (fast): integrity + pinning only, NO typosquat.
    const supply = scanSupplyChain(tmp, { fast: true });

    const findings = [
      ...deps.findings.map((d) => depToFinding(d, "public-facing")),
      ...supply.integrity.floatingPins.map((p) => pinningToFinding(p, "public-facing")),
    ];
    appendFindings(tmp, findings);

    const readBack = readFindings(tmp);
    // One CVE finding + the `chalk` floating pin.
    expect(readBack.some((f) => f.primary_concern === "dependency-cve")).toBe(true);
    expect(readBack.some((f) => f.finding_type === "floating-version-pin")).toBe(true);
    // The fast :deps subset did NOT run typosquat — `expres` must not appear.
    expect(supply.typosquats).toHaveLength(0);
    expect(readBack.every((f) => f.finding_type !== "possible-typosquat")).toBe(true);
    for (const f of readBack) expect(validateFinding(f)).toEqual([]);
  });

  it(":deps fast mode skips SBOM + typosquat that :audit would run", () => {
    write("package.json", JSON.stringify({ dependencies: { expres: "1.0.0" } }));
    write("bom.json", JSON.stringify({ bomFormat: "CycloneDX" }));
    const fast = scanSupplyChain(tmp, { fast: true });
    const full = scanSupplyChain(tmp);
    // SBOM detection still records presence (cheap), but typosquat is skipped.
    expect(fast.typosquats).toHaveLength(0);
    expect(full.typosquats.length).toBeGreaterThan(0);
  });
});

// ─── Regression: Firebase-web-key informational mapping (Fix 2) ─────────────
describe("secretToFinding — informational Firebase web key (regression)", () => {
  it("maps an informational secret to inform-only + companion routing, not a blocker", () => {
    resetFindingIds();
    const webKey: SecretFinding = {
      pattern: "FIREBASE_WEB_API_KEY",
      severity: "low",
      file: "src/firebase.ts",
      line: 3,
      column: 10,
      match: "AIzaS…AAAA",
      preview: 'apiKey: "AIzaS…AAAA"',
      remediation: "Firebase web API keys are public by design.",
      informational: true,
      companion: "config-posture",
    };
    const f = secretToFinding(webKey, "public-facing");
    expect(f.severity_tier_adjusted).toBe("low");
    expect(f.fix_class).toBe("inform-only");
    expect(f.secondary_concerns).toContain("config-posture");
    expect(f.title).toContain("Public-by-design");
    expect(validateFinding(f)).toEqual([]);
  });
});

// ─── Regression: dependency-cve no-op coverage advisory (Fix 3) ─────────────
describe("dependency-cve coverage advisory (regression)", () => {
  it("scanDependencies flags notChecked when no osv-scanner + no npm audit", () => {
    write("package.json", JSON.stringify({ dependencies: { left: "1.0.0" } }));
    // Runner that mimics npm being unavailable (throws with no stdout).
    const runner: CommandRunner = () => {
      throw new Error("npm not found");
    };
    const res = scanDependencies(tmp, { probe: noTools, runner });
    expect(res.osvSource).toBe("none");
    expect(res.npmAuditRan).toBe(false);
    expect(res.notChecked).toBe(true);
    expect(res.findings.length).toBe(0);
  });

  it("maps the coverage advisory to an inform-only low finding (not a clean pass)", () => {
    resetFindingIds();
    const f = depNotCheckedToFinding(depCoverageAdvisory(), "public-facing");
    expect(f.primary_concern).toBe("dependency-cve");
    expect(f.severity_tier_adjusted).toBe("low");
    expect(f.fix_class).toBe("inform-only");
    expect(f.finding_type).toBe("dependency-scan-not-performed");
    expect(f.description).toMatch(/not a clean pass/i);
    expect(validateFinding(f)).toEqual([]);
  });

  it("does NOT flag notChecked when npm audit ran (even with zero vulns)", () => {
    write("package.json", JSON.stringify({ dependencies: { left: "1.0.0" } }));
    const runner: CommandRunner = (cmd, args) => {
      if (cmd === "npm" && args.includes("audit")) return JSON.stringify({ vulnerabilities: {} });
      return "";
    };
    const res = scanDependencies(tmp, { probe: noTools, runner });
    expect(res.npmAuditRan).toBe(true);
    expect(res.notChecked).toBe(false);
  });
});

describe("2.5 — id sequencing keeps findings deduped on re-run", () => {
  it("resetFindingIds yields stable ids so the score reader dedupes", () => {
    resetFindingIds();
    const f1 = typosquatToFinding({ package: "expres", resembles: "express", distance: 1, dev: false }, "public-facing");
    resetFindingIds();
    const f2 = typosquatToFinding({ package: "expres", resembles: "express", distance: 1, dev: false }, "public-facing");
    expect(f1.id).toBe(f2.id); // same id across runs → dedup by id works
  });
});
