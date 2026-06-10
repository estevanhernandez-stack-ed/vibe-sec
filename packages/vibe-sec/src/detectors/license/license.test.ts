import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  classifyLicenseId,
  classifySpdxExpression,
  classifyLicenseField,
  type LicenseClass,
} from "./spdx.js";
import { detectDistributionModel } from "./distribution-model.js";
import { inventoryLicenses } from "./inventory.js";
import {
  scanLicenses,
  evaluateLicensePolicy,
  licenseCoverageAdvisory,
  type LicensePolicyFinding,
} from "./index.js";
import type { PackageLicenseRecord } from "./inventory.js";
import type { DistributionModelResult } from "./distribution-model.js";
import {
  licenseToFinding,
  licenseNotScannedToFinding,
  resetFindingIds,
} from "../to-findings.js";
import { validateFinding } from "../../state/findings.js";
import {
  isInScope,
  mandatoryConcerns,
} from "../../scoring/weighted-score.js";
import { foldConcernResults } from "../../gate/run-gate.js";
import { ALL_CONCERNS } from "../../types.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-license-"));
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

function writeRootPkg(pkg: object): void {
  write("package.json", JSON.stringify(pkg));
}

function writeInstalled(name: string, manifest: object): void {
  write(path.join("node_modules", name, "package.json"), JSON.stringify(manifest));
}

function record(partial: Partial<PackageLicenseRecord> & { name: string }): PackageLicenseRecord {
  return {
    version: "1.0.0",
    licenseExpression: "MIT",
    classification: "permissive",
    dev: false,
    manifestPath: `node_modules/${partial.name}/package.json`,
    ...partial,
  };
}

const SAAS: DistributionModelResult = {
  model: "saas",
  confidence: 0.7,
  signals: ["file: firebase.json"],
};
const BINARY: DistributionModelResult = {
  model: "distributed-binary",
  confidence: 0.9,
  signals: ["dependency: @capacitor/android"],
};
const UNKNOWN_MODEL: DistributionModelResult = {
  model: "unknown",
  confidence: 0.3,
  signals: [],
};

// ─── SPDX classifier table ───────────────────────────────────────────────────

describe("classifySpdxExpression — the classifier table", () => {
  const table: [string, LicenseClass][] = [
    // permissive family
    ["MIT", "permissive"],
    ["ISC", "permissive"],
    ["Apache-2.0", "permissive"],
    ["BSD-2-Clause", "permissive"],
    ["BSD-3-Clause", "permissive"],
    ["0BSD", "permissive"],
    ["Unlicense", "permissive"],
    ["CC0-1.0", "permissive"],
    ["CC-BY-4.0", "permissive"],
    ["BlueOak-1.0.0", "permissive"],
    // weak copyleft
    ["LGPL-3.0-or-later", "weak-copyleft"],
    ["LGPL-2.1-only", "weak-copyleft"],
    ["MPL-2.0", "weak-copyleft"],
    ["EPL-2.0", "weak-copyleft"],
    ["CDDL-1.0", "weak-copyleft"],
    ["CC-BY-SA-4.0", "weak-copyleft"],
    // strong copyleft
    ["GPL-2.0", "strong-copyleft"],
    ["GPL-3.0-only", "strong-copyleft"],
    ["GPL-3.0-or-later", "strong-copyleft"],
    ["GPL-2.0+", "strong-copyleft"], // legacy plus suffix
    // network copyleft
    ["AGPL-3.0-only", "network-copyleft"],
    ["AGPL-3.0", "network-copyleft"],
    ["SSPL-1.0", "network-copyleft"],
    ["OSL-3.0", "network-copyleft"],
    // proprietary / unknown / missing
    ["UNLICENSED", "proprietary"],
    ["CC-BY-NC-4.0", "proprietary"],
    ["TotallyMadeUp-9.9", "unknown"],
    ["LicenseRef-corp-internal", "unknown"],
    ["", "missing"],
  ];

  for (const [expr, expected] of table) {
    it(`classifies ${JSON.stringify(expr)} as ${expected}`, () => {
      expect(classifySpdxExpression(expr)).toBe(expected);
    });
  }

  it("is case-insensitive on ids and keywords", () => {
    expect(classifySpdxExpression("mit")).toBe("permissive");
    expect(classifySpdxExpression("mit or gpl-2.0")).toBe("permissive");
  });
});

describe("classifySpdxExpression — OR / AND / WITH combinations", () => {
  it("THE canonical trap: (BSD-3-Clause OR GPL-2.0) is PERMISSIVE, not copyleft", () => {
    // node-forge's real expression. Dual-license: the consumer picks BSD.
    expect(classifySpdxExpression("(BSD-3-Clause OR GPL-2.0)")).toBe("permissive");
  });

  it("the trap holds without parens: BSD-3-Clause OR GPL-2.0", () => {
    expect(classifySpdxExpression("BSD-3-Clause OR GPL-2.0")).toBe("permissive");
  });

  it("(MIT OR Apache-2.0) is permissive", () => {
    expect(classifySpdxExpression("(MIT OR Apache-2.0)")).toBe("permissive");
  });

  it("OR with no permissive arm stays copyleft", () => {
    expect(classifySpdxExpression("GPL-2.0-only OR GPL-3.0-only")).toBe("strong-copyleft");
    expect(classifySpdxExpression("LGPL-3.0-only OR GPL-3.0-only")).toBe("weak-copyleft");
  });

  it("a permissive arm rescues an unknown arm in OR", () => {
    expect(classifySpdxExpression("MIT OR TotallyMadeUp-9.9")).toBe("permissive");
  });

  it("AND takes the most restrictive term", () => {
    expect(classifySpdxExpression("MIT AND GPL-3.0-only")).toBe("strong-copyleft");
    expect(classifySpdxExpression("MIT AND LGPL-3.0-only")).toBe("weak-copyleft");
  });

  it("AND binds tighter than OR: MIT OR GPL-3.0-only AND AGPL-3.0-only", () => {
    // Parses as MIT OR (GPL AND AGPL) → permissive arm wins.
    expect(classifySpdxExpression("MIT OR GPL-3.0-only AND AGPL-3.0-only")).toBe("permissive");
  });

  it("parenthesized group composes into AND", () => {
    expect(classifySpdxExpression("(MIT OR GPL-2.0) AND Apache-2.0")).toBe("permissive");
  });

  it("WITH a linking exception downgrades strong copyleft to weak", () => {
    expect(classifySpdxExpression("GPL-2.0-only WITH Classpath-exception-2.0")).toBe(
      "weak-copyleft",
    );
    expect(classifySpdxExpression("GPL-3.0-only WITH GCC-exception-3.1")).toBe("weak-copyleft");
  });

  it("WITH on a non-strong base keeps the base class", () => {
    expect(classifySpdxExpression("Apache-2.0 WITH LLVM-exception")).toBe("permissive");
  });

  it("unbalanced parens / dangling operators classify unknown, never throw", () => {
    expect(classifySpdxExpression("(MIT OR")).toBe("unknown");
    expect(classifySpdxExpression("MIT OR")).toBe("unknown");
    expect(classifySpdxExpression("OR MIT")).toBe("unknown");
    expect(classifySpdxExpression("MIT )")).toBe("unknown");
  });

  it("'SEE LICENSE IN <file>' classifies unknown (present but unreadable statically)", () => {
    expect(classifySpdxExpression("SEE LICENSE IN LICENSE.txt")).toBe("unknown");
  });
});

describe("classifyLicenseField — package.json field forms", () => {
  it("string SPDX expression", () => {
    expect(classifyLicenseField("MIT")).toEqual({
      expression: "MIT",
      classification: "permissive",
    });
  });

  it("legacy { type } object form", () => {
    expect(classifyLicenseField({ type: "MIT", url: "https://x" })).toEqual({
      expression: "MIT",
      classification: "permissive",
    });
  });

  it("legacy licenses array: multiple entries are OR (dual-license) semantics", () => {
    const r = classifyLicenseField([
      { type: "GPL-2.0", url: "https://x" },
      { type: "MIT", url: "https://y" },
    ]);
    expect(r.classification).toBe("permissive");
    expect(r.expression).toBe("GPL-2.0 OR MIT");
  });

  it("legacy array of strings works too", () => {
    expect(classifyLicenseField(["BSD-3-Clause", "GPL-2.0"]).classification).toBe("permissive");
  });

  it("missing / empty forms classify missing", () => {
    expect(classifyLicenseField(undefined).classification).toBe("missing");
    expect(classifyLicenseField(null).classification).toBe("missing");
    expect(classifyLicenseField("").classification).toBe("missing");
    expect(classifyLicenseField([]).classification).toBe("missing");
    expect(classifyLicenseField({}).classification).toBe("missing");
  });
});

// ─── distribution model ──────────────────────────────────────────────────────

describe("detectDistributionModel", () => {
  it("capacitor dependency → distributed-binary", () => {
    writeRootPkg({ name: "app", dependencies: { "@capacitor/android": "5.0.0" } });
    const r = detectDistributionModel(tmp);
    expect(r.model).toBe("distributed-binary");
    expect(r.signals.some((s) => s.includes("@capacitor/android"))).toBe(true);
  });

  it("electron dependency → distributed-binary", () => {
    writeRootPkg({ name: "app", devDependencies: { electron: "30.0.0" } });
    expect(detectDistributionModel(tmp).model).toBe("distributed-binary");
  });

  it("capacitor.config.ts file hint alone → distributed-binary", () => {
    writeRootPkg({ name: "app" });
    write("capacitor.config.ts", "export default {};");
    expect(detectDistributionModel(tmp).model).toBe("distributed-binary");
  });

  it(".nuspec at root → distributed-binary (NuGet/MSIX hint)", () => {
    writeRootPkg({ name: "app" });
    write("App.nuspec", "<package/>");
    expect(detectDistributionModel(tmp).model).toBe("distributed-binary");
  });

  it("binary signal wins over saas signal when both exist", () => {
    writeRootPkg({ name: "app", dependencies: { "@capacitor/core": "5.0.0", next: "14.0.0" } });
    write("firebase.json", "{}");
    expect(detectDistributionModel(tmp).model).toBe("distributed-binary");
  });

  it("server framework / deploy config → saas", () => {
    writeRootPkg({ name: "app", dependencies: { express: "4.18.0" } });
    expect(detectDistributionModel(tmp).model).toBe("saas");
    fs.rmSync(path.join(tmp, "package.json"));
    writeRootPkg({ name: "app2" });
    write("vercel.json", "{}");
    expect(detectDistributionModel(tmp).model).toBe("saas");
  });

  it("plain web app defaults to saas", () => {
    writeRootPkg({ name: "app", dependencies: { react: "18.0.0", "react-dom": "18.0.0" } });
    const r = detectDistributionModel(tmp);
    expect(r.model).toBe("saas");
    expect(r.signals.some((s) => s.includes("default"))).toBe(true);
  });

  it("no signals → unknown", () => {
    writeRootPkg({ name: "mystery" });
    expect(detectDistributionModel(tmp).model).toBe("unknown");
  });
});

// ─── inventory walk ──────────────────────────────────────────────────────────

describe("inventoryLicenses — node_modules walk", () => {
  it("reads plain and scoped packages, including the legacy licenses array", () => {
    writeRootPkg({ name: "app", dependencies: { foo: "1.0.0", "@scope/bar": "2.0.0" } });
    writeInstalled("foo", { name: "foo", version: "1.0.0", license: "MIT" });
    writeInstalled("@scope/bar", {
      name: "@scope/bar",
      version: "2.0.0",
      licenses: [{ type: "BSD-3-Clause" }, { type: "GPL-2.0" }],
    });
    const r = inventoryLicenses(tmp);
    expect(r.nodeModulesPresent).toBe(true);
    expect(r.packages).toHaveLength(2);
    const bar = r.packages.find((p) => p.name === "@scope/bar")!;
    expect(bar.classification).toBe("permissive"); // OR semantics on the array
    expect(bar.licenseExpression).toBe("BSD-3-Clause OR GPL-2.0");
    expect(bar.manifestPath).toBe("node_modules/@scope/bar/package.json");
  });

  it("skips nested node_modules (depth-bounded)", () => {
    writeInstalled("foo", { name: "foo", version: "1.0.0", license: "MIT" });
    write(
      "node_modules/foo/node_modules/nested/package.json",
      JSON.stringify({ name: "nested", version: "0.0.1", license: "GPL-3.0-only" }),
    );
    const r = inventoryLicenses(tmp);
    expect(r.packages.map((p) => p.name)).toEqual(["foo"]);
  });

  it("skips dot-infrastructure entries (.bin, .package-lock.json)", () => {
    writeInstalled("foo", { name: "foo", version: "1.0.0", license: "MIT" });
    write("node_modules/.package-lock.json", "{}");
    fs.mkdirSync(path.join(tmp, "node_modules", ".bin"), { recursive: true });
    expect(inventoryLicenses(tmp).packages).toHaveLength(1);
  });

  it("records a missing license field as classification missing", () => {
    writeInstalled("nolicense", { name: "nolicense", version: "3.1.4" });
    const r = inventoryLicenses(tmp);
    expect(r.packages[0]!.classification).toBe("missing");
    expect(r.packages[0]!.licenseExpression).toBeNull();
  });

  it("records an unparseable manifest as classification unknown", () => {
    write("node_modules/broken/package.json", "{not json");
    const r = inventoryLicenses(tmp);
    expect(r.packages[0]!.name).toBe("broken");
    expect(r.packages[0]!.classification).toBe("unknown");
  });

  it("absent node_modules → nodeModulesPresent false, zero packages", () => {
    writeRootPkg({ name: "app" });
    const r = inventoryLicenses(tmp);
    expect(r.nodeModulesPresent).toBe(false);
    expect(r.packages).toHaveLength(0);
  });

  it("dev flag comes from the npm lockfile (covers transitives)", () => {
    writeRootPkg({ name: "app", devDependencies: { "build-tool": "1.0.0" } });
    write(
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app" },
          "node_modules/build-tool": { version: "1.0.0", dev: true },
          "node_modules/runtime-lib": { version: "2.0.0" },
        },
      }),
    );
    writeInstalled("build-tool", { name: "build-tool", version: "1.0.0", license: "GPL-3.0-only" });
    writeInstalled("runtime-lib", { name: "runtime-lib", version: "2.0.0", license: "MIT" });
    const r = inventoryLicenses(tmp);
    expect(r.packages.find((p) => p.name === "build-tool")!.dev).toBe(true);
    expect(r.packages.find((p) => p.name === "runtime-lib")!.dev).toBe(false);
  });

  it("defaults to prod (conservative) when no lockfile resolves the package", () => {
    writeInstalled("transitive", { name: "transitive", version: "1.0.0", license: "GPL-2.0" });
    expect(inventoryLicenses(tmp).packages[0]!.dev).toBe(false);
  });
});

// ─── policy matrix ───────────────────────────────────────────────────────────

describe("evaluateLicensePolicy — the policy matrix", () => {
  it("strong-copyleft × distributed-binary → HIGH", () => {
    const findings = evaluateLicensePolicy(
      [record({ name: "engine", licenseExpression: "GPL-3.0-or-later", classification: "strong-copyleft" })],
      BINARY,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.finding_type).toBe("strong-copyleft-in-distributed-binary");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.detail).toContain("distributed-binary");
    expect(findings[0]!.remediation).toMatch(/commercial license|swap|open/i);
  });

  it("network-copyleft → HIGH regardless of model (SaaS does not shield AGPL)", () => {
    for (const model of [SAAS, BINARY, UNKNOWN_MODEL]) {
      const findings = evaluateLicensePolicy(
        [record({ name: "agpl-lib", licenseExpression: "AGPL-3.0-only", classification: "network-copyleft" })],
        model,
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]!.finding_type).toBe("network-copyleft-dependency");
      expect(findings[0]!.severity).toBe("high");
    }
  });

  it("strong-copyleft × saas → MEDIUM advisory (document the position)", () => {
    const findings = evaluateLicensePolicy(
      [record({ name: "gpl-lib", licenseExpression: "GPL-2.0", classification: "strong-copyleft" })],
      SAAS,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.finding_type).toBe("strong-copyleft-server-side");
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.remediation).toMatch(/document/i);
  });

  it("strong-copyleft × unknown model → MEDIUM with confirm-the-model direction", () => {
    const findings = evaluateLicensePolicy(
      [record({ name: "gpl-lib", licenseExpression: "GPL-2.0", classification: "strong-copyleft" })],
      UNKNOWN_MODEL,
    );
    expect(findings[0]!.finding_type).toBe("strong-copyleft-unknown-distribution");
    expect(findings[0]!.severity).toBe("medium");
  });

  it("weak-copyleft production deps batch into ONE low advisory", () => {
    const findings = evaluateLicensePolicy(
      [
        record({ name: "lgpl-lib", licenseExpression: "LGPL-3.0-only", classification: "weak-copyleft" }),
        record({ name: "mpl-lib", licenseExpression: "MPL-2.0", classification: "weak-copyleft" }),
      ],
      BINARY,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.finding_type).toBe("weak-copyleft-dependencies");
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.members).toHaveLength(2);
    expect(findings[0]!.detail).toMatch(/dynamic linking/i);
  });

  it("missing + UNLICENSED + unparseable prod deps batch into ONE low advisory", () => {
    const findings = evaluateLicensePolicy(
      [
        record({ name: "no-field", licenseExpression: null, classification: "missing" }),
        record({ name: "locked", licenseExpression: "UNLICENSED", classification: "proprietary" }),
        record({ name: "weird", licenseExpression: "Custom-1.0", classification: "unknown" }),
      ],
      SAAS,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.finding_type).toBe("license-missing-or-unverifiable");
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.members).toHaveLength(3);
  });

  it("dual-licensed with a permissive arm → clean, no finding", () => {
    const findings = evaluateLicensePolicy(
      [
        record({
          name: "node-forge",
          licenseExpression: "(BSD-3-Clause OR GPL-2.0)",
          classification: "permissive", // the classifier already resolved the OR
        }),
      ],
      BINARY,
    );
    expect(findings).toHaveLength(0);
  });

  it("devDependency copyleft caps at LOW inform-only — never HIGH (not conveyed)", () => {
    const findings = evaluateLicensePolicy(
      [
        record({ name: "gpl-cli", licenseExpression: "GPL-3.0-only", classification: "strong-copyleft", dev: true }),
        record({ name: "agpl-tool", licenseExpression: "AGPL-3.0-only", classification: "network-copyleft", dev: true }),
      ],
      BINARY, // even in a distributed binary
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.finding_type).toBe("dev-dependency-copyleft");
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.fixClass).toBe("inform-only");
    expect(findings[0]!.detail).toMatch(/not conveyed/i);
    expect(findings[0]!.members).toHaveLength(2);
  });

  it("missing-license devDependencies produce no finding at all", () => {
    const findings = evaluateLicensePolicy(
      [record({ name: "dev-nolicense", licenseExpression: null, classification: "missing", dev: true })],
      SAAS,
    );
    expect(findings).toHaveLength(0);
  });

  it("clean permissive tree → zero findings", () => {
    const findings = evaluateLicensePolicy(
      [
        record({ name: "a", licenseExpression: "MIT", classification: "permissive" }),
        record({ name: "b", licenseExpression: "Apache-2.0", classification: "permissive" }),
      ],
      BINARY,
    );
    expect(findings).toHaveLength(0);
  });
});

// ─── scanLicenses end-to-end + coverage advisory ─────────────────────────────

describe("scanLicenses — end-to-end over a fixture", () => {
  it("flags a GPL engine HIGH in a capacitor app", () => {
    writeRootPkg({
      name: "app",
      private: true,
      dependencies: { "@capacitor/android": "5.0.0", engine: "0.0.2" },
    });
    writeInstalled("engine", { name: "engine", version: "0.0.2", license: "GPL-3.0-or-later" });
    writeInstalled("@capacitor/android", {
      name: "@capacitor/android",
      version: "5.0.0",
      license: "MIT",
    });
    const r = scanLicenses(tmp);
    expect(r.notScanned).toBe(false);
    expect(r.distribution.model).toBe("distributed-binary");
    const hit = r.findings.find((f) => f.package === "engine");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
    expect(hit!.finding_type).toBe("strong-copyleft-in-distributed-binary");
  });

  it("node_modules absent → notScanned, never a false-clean pass", () => {
    writeRootPkg({ name: "app", dependencies: { engine: "0.0.2" } });
    const r = scanLicenses(tmp);
    expect(r.nodeModulesPresent).toBe(false);
    expect(r.notScanned).toBe(true);
    expect(r.findings).toHaveLength(0); // the ADVISORY carries the signal, not findings
    const advisory = licenseCoverageAdvisory();
    expect(advisory.finding_type).toBe("license-scan-not-performed");
    expect(advisory.detail).toMatch(/npm\/pnpm install/);
  });

  it("forceModel overrides detection", () => {
    writeRootPkg({ name: "app", dependencies: { "@capacitor/core": "5.0.0" } });
    writeInstalled("gpl-lib", { name: "gpl-lib", version: "1.0.0", license: "GPL-2.0" });
    const r = scanLicenses(tmp, { forceModel: "saas" });
    expect(r.distribution.model).toBe("saas");
    expect(r.findings[0]!.finding_type).toBe("strong-copyleft-server-side");
  });
});

// ─── findings.jsonl mapping ──────────────────────────────────────────────────

describe("license → Finding mappers", () => {
  function policyFinding(partial: Partial<LicensePolicyFinding> = {}): LicensePolicyFinding {
    return {
      finding_type: "strong-copyleft-in-distributed-binary",
      severity: "high",
      fixClass: "advisory",
      package: "engine",
      version: "0.0.2",
      licenseExpression: "GPL-3.0-or-later",
      classification: "strong-copyleft",
      model: "distributed-binary",
      dev: false,
      detail: "engine@0.0.2 is licensed GPL-3.0-or-later (strong-copyleft).",
      remediation: "Purchase a commercial license, swap, or open the source.",
      members: null,
      ...partial,
    };
  }

  it("produces a valid Finding with the full GAP-26 payload", () => {
    const f = licenseToFinding(policyFinding(), "customer-facing-saas");
    expect(validateFinding(f)).toEqual([]);
    expect(f.primary_concern).toBe("license-compliance");
    expect(f.secondary_concerns).toContain("supply-chain");
    expect(f.severity_tier_adjusted).toBe("high");
    expect(f.surface).toBe("engine@0.0.2"); // package + version
    expect(f.description).toContain("GPL-3.0-or-later"); // license expression
    expect(f.description).toContain("strong-copyleft"); // classification
    expect(f.description).toMatch(/commercial license|swap|open/); // remediation
    expect(f.references).toContain("SPDX:GPL-3.0-or-later");
    expect(f.file).toBe("node_modules/engine/package.json");
    expect(f.fix_class).toBe("advisory");
    expect(f.owasp_2021).toBeNull(); // compliance, not an OWASP weakness
  });

  it("batched findings map with package.json as the file and a count in the title", () => {
    const f = licenseToFinding(
      policyFinding({
        finding_type: "weak-copyleft-dependencies",
        severity: "low",
        package: null,
        version: null,
        licenseExpression: null,
        classification: "weak-copyleft",
        members: [
          { package: "a", version: "1.0.0", licenseExpression: "MPL-2.0", classification: "weak-copyleft" },
          { package: "b", version: "2.0.0", licenseExpression: "LGPL-3.0-only", classification: "weak-copyleft" },
        ],
      }),
      "public-facing",
    );
    expect(validateFinding(f)).toEqual([]);
    expect(f.title).toContain("(2 packages)");
    expect(f.file).toBe("package.json");
    expect(f.surface).toBeNull();
    expect(f.confidence).toBe(1);
  });

  it("licenseNotScannedToFinding emits the inform-only advisory", () => {
    const f = licenseNotScannedToFinding(licenseCoverageAdvisory(), "customer-facing-saas");
    expect(validateFinding(f)).toEqual([]);
    expect(f.primary_concern).toBe("license-compliance");
    expect(f.finding_type).toBe("license-scan-not-performed");
    expect(f.fix_class).toBe("inform-only");
    expect(f.severity_tier_adjusted).toBe("low");
  });
});

// ─── tier gating — wired like every other concern ────────────────────────────

describe("license-compliance tier scope (GAP-26 gating)", () => {
  it("is registered as the 11th concern", () => {
    expect(ALL_CONCERNS).toContain("license-compliance");
  });

  it("prototype and internal skip it entirely (out of the score denominator)", () => {
    expect(isInScope("license-compliance", "prototype")).toBe(false);
    expect(isInScope("license-compliance", "internal")).toBe(false);
  });

  it("public-facing runs it advisory-weight; customer-facing+ at full weight", () => {
    expect(isInScope("license-compliance", "public-facing")).toBe(true);
    expect(isInScope("license-compliance", "customer-facing-saas")).toBe(true);
    expect(isInScope("license-compliance", "regulated")).toBe(true);
  });

  it("is never gate-mandatory — even at regulated (business decision, not a code fix)", () => {
    for (const tier of ["prototype", "internal", "public-facing", "customer-facing-saas", "regulated"] as const) {
      expect(mandatoryConcerns(tier)).not.toContain("license-compliance");
    }
  });

  it("folds into the gate's concern results at in-scope tiers only", () => {
    const atSaas = foldConcernResults([], "customer-facing-saas");
    expect(atSaas.some((r) => r.concern === "license-compliance")).toBe(true);
    const atProto = foldConcernResults([], "prototype");
    expect(atProto.some((r) => r.concern === "license-compliance")).toBe(false);
  });
});
