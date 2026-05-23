// Threat-model synthesis tests (checklist 4.1 verify bullets).
//
// Proves: (a) the synthesizer emits valid Mermaid with the locked shape
// convention; (b) the Threat-Dragon-compatible JSON sidecar has the right shape;
// (c) the <90%-coverage banner fires; (d) the Prototype stub; (e) LINDDUN only at
// Customer-facing+; (f) the end-to-end runThreatModel over a fixture writes both
// channels — and the Internal-tier opt-in (NOT auto-included in :audit) is the
// caller's contract, asserted via the SKILL + the audit pipeline test.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  synthesizeThreatModel,
  checkCompleteness,
  renderMermaidDfd,
  renderThreatModelMarkdown,
  toThreatDragon,
  runThreatModel,
  resetThreatIds,
  STRIDE_CATEGORIES,
  type ThreatModelInput,
} from "./index.js";
import type { Route } from "../detectors/auth-model/route-inventory.js";
import type { PiiField } from "../detectors/crypto-pii/pii-inventory.js";
import { threatModelStatePath, projectDocsDir } from "../state/paths.js";
import { makeFinding, type Finding } from "../state/findings.js";

function route(p: string, opts: Partial<Route> = {}): Route {
  return {
    path: p,
    method: "GET",
    framework: "next-app-router",
    file: `app${p}/route.ts`,
    line: 1,
    authStatus: "unknown",
    isAdmin: false,
    ...opts,
  };
}

function pii(field: string): PiiField {
  return { field, category: "contact", model: "User", source: "prisma", file: "schema.prisma", line: 1 };
}

function baseInput(overrides: Partial<ThreatModelInput> = {}): ThreatModelInput {
  return {
    tier: "public-facing",
    appName: "test-app",
    routes: [route("/api/users"), route("/api/admin/settings", { isAdmin: true })],
    piiFields: [pii("email")],
    integrations: ["Stripe"],
    findings: [],
    ...overrides,
  };
}

beforeEach(() => resetThreatIds());

describe("4.1 threat-model — completeness check", () => {
  it("fires the <90% banner when route coverage is below threshold", () => {
    const input = baseInput({
      routes: [route("/api/users")], // 1 inventoried
      totalRoutesDetected: 10, // 10 detected → 10% coverage
    });
    const check = checkCompleteness(input);
    expect(check.complete).toBe(false);
    expect(check.routeCoveragePct).toBe(10);
    expect(check.banner).toContain("Inventory completeness: 10%");
  });

  it("does not fire the banner at ≥90% coverage", () => {
    const input = baseInput({
      routes: [route("/a"), route("/b"), route("/c"), route("/d"), route("/e"), route("/f"), route("/g"), route("/h"), route("/i")],
      totalRoutesDetected: 10, // 90%
    });
    const check = checkCompleteness(input);
    expect(check.complete).toBe(true);
    expect(check.banner).toBeNull();
  });

  it("treats a no-route project as trivially complete", () => {
    const check = checkCompleteness(baseInput({ routes: [], totalRoutesDetected: 0 }));
    expect(check.complete).toBe(true);
  });
});

describe("4.1 threat-model — Mermaid emission (the locked shape convention)", () => {
  it("emits a valid Mermaid flowchart with the locked node shapes + subgraph boundaries", () => {
    const result = synthesizeThreatModel(baseInput());
    const mermaid = renderMermaidDfd(result.dfd);

    expect(mermaid).toContain("```mermaid");
    expect(mermaid).toContain("flowchart TD");
    // Locked convention: stadium (external entity).
    expect(mermaid).toMatch(/user\(\["User"\]\)/);
    // Rectangle (process).
    expect(mermaid).toMatch(/backend\["Backend \/ API"\]/);
    // Cylinder (data store) — present because there's PII.
    expect(mermaid).toMatch(/db\[\("Primary datastore"\)\]/);
    // Hexagon (third-party) — Stripe integration.
    expect(mermaid).toMatch(/\{\{"Stripe"\}\}/);
    // Subgraph (trust boundary).
    expect(mermaid).toContain('subgraph external["External user boundary"]');
    expect(mermaid).toContain("end");
    // Closes the fence.
    expect(mermaid.trim().endsWith("```")).toBe(true);
  });

  it("renders the full markdown with the documented convention + DFD + STRIDE table", () => {
    const result = synthesizeThreatModel(baseInput());
    const md = renderThreatModelMarkdown(result, { appName: "test-app" });
    expect(md).toContain("# Threat model — test-app");
    expect(md).toContain("## Data-flow diagram");
    expect(md).toContain("stadiums = external entities");
    expect(md).toContain("## Threats by STRIDE category");
    expect(md).toContain("```mermaid");
  });
});

describe("4.1 threat-model — STRIDE/DREAD synthesis", () => {
  it("enumerates all six STRIDE categories when an admin surface exists", () => {
    const result = synthesizeThreatModel(baseInput());
    const categories = new Set(result.threats.map((t) => t.category));
    for (const c of STRIDE_CATEGORIES) {
      expect(categories.has(c)).toBe(true);
    }
  });

  it("scores realized threats (backed by a finding) higher on DREAD", () => {
    const secretFinding: Finding = makeFinding({
      id: "secret-001",
      primary_concern: "secret-detection",
      severity_base: "critical",
      severity_tier_adjusted: "critical",
      confidence: 0.9,
      finding_type: "aws-key",
      title: "Committed AWS key",
      tier: "public-facing",
      fix_class: "inline",
      tool_of_record: "in-house",
    });
    const result = synthesizeThreatModel(baseInput({ findings: [secretFinding] }));
    const infoDisc = result.threats.find((t) => t.category === "Information Disclosure");
    expect(infoDisc).toBeDefined();
    expect(infoDisc!.realizedByFinding).toBe("secret-001");
    expect(infoDisc!.dread.total).toBeGreaterThanOrEqual(12); // realized → high across the board
  });

  it("prioritizes top-10 at Public-facing+ and top-3 at Internal", () => {
    const pub = synthesizeThreatModel(baseInput({ tier: "public-facing" }));
    const internal = synthesizeThreatModel(baseInput({ tier: "internal" }));
    expect(pub.prioritized.length).toBeLessThanOrEqual(10);
    expect(internal.prioritized.length).toBeLessThanOrEqual(3);
  });
});

describe("4.1 threat-model — tier applicability", () => {
  it("returns a stub at Prototype (no synthesis)", () => {
    const result = synthesizeThreatModel(baseInput({ tier: "prototype" }));
    expect(result.isStub).toBe(true);
    expect(result.threats).toHaveLength(0);
    const md = renderThreatModelMarkdown(result, { appName: "test-app" });
    expect(md).toContain("not recommended at Prototype tier");
  });

  it("adds the LINDDUN overlay only at Customer-facing+", () => {
    const pub = synthesizeThreatModel(baseInput({ tier: "public-facing" }));
    const cust = synthesizeThreatModel(baseInput({ tier: "customer-facing-saas" }));
    expect(pub.privacyThreats).toHaveLength(0);
    expect(cust.privacyThreats.length).toBeGreaterThan(0);
  });

  it("adds attack trees from Public-facing (top-3) and top-5 at Regulated", () => {
    const pub = synthesizeThreatModel(baseInput({ tier: "public-facing" }));
    const reg = synthesizeThreatModel(baseInput({ tier: "regulated" }));
    const internal = synthesizeThreatModel(baseInput({ tier: "internal" }));
    expect(internal.attackTrees).toHaveLength(0);
    expect(pub.attackTrees.length).toBeLessThanOrEqual(3);
    expect(pub.attackTrees.length).toBeGreaterThan(0);
    expect(reg.attackTrees.length).toBeLessThanOrEqual(5);
    expect(reg.pytmStub).toBe(true);
  });
});

describe("4.1 threat-model — Threat Dragon sidecar shape", () => {
  it("emits a Threat-Dragon-v2.5.0-compatible model", () => {
    const result = synthesizeThreatModel(baseInput());
    const td = toThreatDragon(result, "test-app");

    expect(td.version).toBe("2.5.0");
    expect(td.summary.title).toContain("test-app");
    expect(Array.isArray(td.detail.diagrams)).toBe(true);
    expect(td.detail.diagrams[0]!.diagramType).toBe("STRIDE");

    const cells = td.detail.diagrams[0]!.cells;
    // Cells carry the tm.* type vocabulary Threat Dragon expects.
    const types = new Set(cells.map((c) => c.data.type));
    expect(types.has("tm.Actor")).toBe(true);
    expect(types.has("tm.Process")).toBe(true);

    // At least one cell carries STRIDE threats.
    const withThreats = cells.filter((c) => (c.data.threats?.length ?? 0) > 0);
    expect(withThreats.length).toBeGreaterThan(0);
    const aThreat = withThreats[0]!.data.threats![0]!;
    expect(aThreat).toHaveProperty("type"); // STRIDE category
    expect(aThreat).toHaveProperty("mitigation");
    expect(aThreat).toHaveProperty("severity");

    // Round-trips through JSON cleanly (the sidecar is written as JSON).
    expect(() => JSON.parse(JSON.stringify(td))).not.toThrow();
  });
});

describe("4.1 threat-model — end-to-end run over a fixture", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-tm-"));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function write(rel: string, content: string): void {
    const full = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf8");
  }

  it("writes both channels (markdown + JSON sidecar) at Public-facing", () => {
    write("app/api/users/route.ts", `export async function GET() { return Response.json([]); }`);
    write("app/api/admin/settings/route.ts", `export async function POST() { return Response.json({}); }`);
    write("schema.prisma", `model User {\n  id Int @id\n  email String\n}`);
    write("package.json", JSON.stringify({ dependencies: { stripe: "^14.0.0" } }));

    const out = runThreatModel(tmp, { tier: "public-facing", write: true, appName: "fixture-app" });

    expect(out.result.isStub).toBe(false);
    expect(out.writtenPaths.length).toBe(2);

    const mdPath = path.join(projectDocsDir(tmp), "threat-model.md");
    expect(fs.existsSync(mdPath)).toBe(true);
    expect(fs.readFileSync(mdPath, "utf8")).toContain("```mermaid");

    const jsonPath = threatModelStatePath(tmp);
    expect(fs.existsSync(jsonPath)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
    expect(parsed.version).toBe("2.5.0");
  });

  it("at Prototype writes only the stub markdown, no JSON sidecar", () => {
    write("app/api/users/route.ts", `export async function GET() {}`);
    const out = runThreatModel(tmp, { tier: "prototype", write: true });
    expect(out.result.isStub).toBe(true);
    expect(out.sidecar).toBeNull();
    expect(fs.existsSync(threatModelStatePath(tmp))).toBe(false);
    const mdPath = path.join(projectDocsDir(tmp), "threat-model.md");
    expect(fs.existsSync(mdPath)).toBe(true);
  });
});
