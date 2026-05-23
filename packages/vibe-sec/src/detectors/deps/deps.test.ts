import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseOsvScannerJson, cvssToSeverity } from "./osv-client.js";
import { parseNpmAudit, routeFixFromAudit } from "./npm-audit.js";
import { mergeDepFindings } from "./dedupe.js";
import { classifyProject } from "./app-lib-classifier.js";
import {
  scanDependencies,
  shouldRollbackChurn,
  countDiffLines,
  LOCKFILE_CHURN_LIMIT,
} from "./index.js";
import type { CommandRunner } from "../../orchestration/defer.js";
import type { ToolProbe } from "../../orchestration/tool-registry.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-deps-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function writePkg(pkg: object): void {
  fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify(pkg), "utf8");
}

const osvPresent: ToolProbe = (tool) => ({
  name: tool,
  present: tool === "osv-scanner",
  version: tool === "osv-scanner" ? "1.8.0" : null,
});
const noTools: ToolProbe = (tool) => ({ name: tool, present: false, version: null });

// A vuln reported by BOTH OSV (as CVE) and npm audit (as GHSA alias).
const OSV_JSON = JSON.stringify({
  results: [
    {
      packages: [
        {
          package: { name: "lodash", version: "4.17.11", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "CVE-2019-10744",
              aliases: ["GHSA-jf85-cpcp-j695"],
              summary: "Prototype pollution in lodash",
              database_specific: { severity: "HIGH" },
              affected: [{ ranges: [{ events: [{ fixed: "4.17.12" }] }] }],
            },
          ],
        },
      ],
    },
  ],
});

const NPM_AUDIT_JSON = JSON.stringify({
  vulnerabilities: {
    lodash: {
      name: "lodash",
      severity: "high",
      range: "<4.17.12",
      via: [
        {
          source: 1065,
          name: "lodash",
          title: "Prototype Pollution",
          url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
          severity: "high",
          cvss: { score: 7.4 },
        },
      ],
      fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
    },
  },
});

describe("cvssToSeverity", () => {
  it("maps CVSS bands to Vibe-Sec-native severity", () => {
    expect(cvssToSeverity(9.8)).toBe("critical");
    expect(cvssToSeverity(7.4)).toBe("high");
    expect(cvssToSeverity(5.0)).toBe("medium");
    expect(cvssToSeverity(2.0)).toBe("low");
    expect(cvssToSeverity(null)).toBe("medium");
  });
});

describe("OSV + npm audit dedup", () => {
  it("collapses the same CVE reported by both scanners into ONE finding", () => {
    const osv = parseOsvScannerJson(OSV_JSON);
    const audit = parseNpmAudit(NPM_AUDIT_JSON);
    expect(osv).toHaveLength(1);
    expect(audit).toHaveLength(1);

    const merged = mergeDepFindings(osv, audit);
    // CVE-2019-10744 (OSV) and GHSA-jf85-cpcp-j695 (npm alias) are the same vuln.
    expect(merged).toHaveLength(1);
    expect(merged[0]!.sources).toContain("osv-scanner");
    expect(merged[0]!.sources).toContain("npm-audit");
    // npm audit won the fix-availability question.
    expect(merged[0]!.fixedVersion).toBe("4.17.21");
  });
});

describe("isSemVerMajor fix routing", () => {
  it("routes a major bump to Inline, a minor to Stage, a simple fix to Auto", () => {
    expect(routeFixFromAudit({ version: "5.0.0", isSemVerMajor: true }).fixClass).toBe("inline");
    expect(routeFixFromAudit({ version: "4.18.0", isSemVerMajor: false }).fixClass).toBe("stage");
    expect(routeFixFromAudit(true).fixClass).toBe("auto");
    expect(routeFixFromAudit(false).fixClass).toBe("inform-only");
  });
});

describe("app-vs-lib classifier (--omit=dev on applications)", () => {
  it("classifies a private app and applies --omit=dev", () => {
    writePkg({ name: "my-app", private: true, scripts: { dev: "next dev" }, dependencies: { next: "14.0.0" } });
    const r = classifyProject(tmp);
    expect(r.kind).toBe("application");
    expect(r.omitDev).toBe(true);
  });

  it("classifies a publishable library and keeps the full tree", () => {
    writePkg({ name: "my-lib", main: "dist/index.js", exports: "./dist/index.js" });
    const r = classifyProject(tmp);
    expect(r.kind).toBe("library");
    expect(r.omitDev).toBe(false);
  });
});

describe("scanDependencies wiring", () => {
  it("passes --omit=dev for an app project when running npm audit", () => {
    writePkg({ name: "app", private: true, scripts: { start: "node ." } });
    let sawOmitDev = false;
    const runner: CommandRunner = (cmd, args) => {
      if (cmd === "npm" && args.includes("audit")) {
        sawOmitDev = args.includes("--omit=dev");
        return NPM_AUDIT_JSON;
      }
      return "";
    };
    const result = scanDependencies(tmp, { probe: noTools, runner });
    expect(result.projectKind).toBe("application");
    expect(result.omitDev).toBe(true);
    expect(sawOmitDev).toBe(true);
    expect(result.npmAuditRan).toBe(true);
    expect(result.epssWired).toBe(false);
  });

  it("defers to osv-scanner when present and merges with npm audit", () => {
    writePkg({ name: "lib", main: "index.js" });
    const runner: CommandRunner = (cmd, args) => {
      if (cmd === "osv-scanner") return OSV_JSON;
      if (cmd === "npm" && args.includes("audit")) return NPM_AUDIT_JSON;
      return "";
    };
    const result = scanDependencies(tmp, { probe: osvPresent, runner });
    expect(result.osvSource).toBe("osv-scanner");
    expect(result.findings).toHaveLength(1); // deduped
  });
});

describe("lockfile-churn rollback (Decision 20)", () => {
  it("re-stages an auto fix whose lockfile diff exceeds 50 lines", () => {
    expect(LOCKFILE_CHURN_LIMIT).toBe(50);
    const bigDiff = ["--- a/package-lock.json", "+++ b/package-lock.json"]
      .concat(Array.from({ length: 60 }, (_, i) => `+  "line${i}": true,`))
      .join("\n");
    expect(countDiffLines(bigDiff)).toBe(60); // headers excluded
    expect(shouldRollbackChurn(countDiffLines(bigDiff))).toBe(true);
  });

  it("lets a small churn auto-apply", () => {
    expect(shouldRollbackChurn(10)).toBe(false);
  });
});
