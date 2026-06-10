import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  readVibeTestHandshake,
  shouldElevateForUncovered,
  handshakeStatusLine,
} from "./vibe-test.js";
import { vibeTestCoveredSurfacesPath } from "../state/paths.js";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-handshake-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function writeCoveredSurfaces(obj: unknown): void {
  const file = vibeTestCoveredSurfacesPath(tmp);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj), "utf8");
}

const NOW = Date.parse("2026-05-23T12:00:00Z");

// CONTRACT FIXTURE — mirrors the verbatim output shape of Vibe Test's
// extractCoveredSurfaces() (vibe-test repo: src/scanner/covered-surfaces.ts),
// which validates against skills/guide/schemas/covered-surfaces.schema.json
// (schema_version const 1, additionalProperties false). If Vibe Test changes
// its emitter, this fixture is the seam that must change WITH it — that
// coordination becomes a core-owned contract test in plugin-core Phase 2
// (vibe-plugins docs/spec-bank/plugin-core-phase2.md). Until then: this
// fixture is hand-synced to the v0.2.5 emitter. Do not invent fields the
// schema forbids — that drift is exactly the GAP-07 false-green this file
// exists to prevent.
function schemaV1Doc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: 1,
    plugin_version: "0.2.5",
    generated_at: "2026-05-23T06:00:00Z", // 6h old vs NOW → fresh
    surfaces: [
      {
        kind: "route",
        identifier: "GET /api/admin/users",
        file_path: "src/api/admin/users.ts",
        coverage_level: "none",
      },
      {
        kind: "route",
        identifier: "POST /api/login",
        file_path: "src/api/login.ts",
        coverage_level: "behavioral",
        test_files: ["tests/login.test.ts"],
      },
      {
        kind: "route",
        identifier: "POST /api/checkout",
        file_path: "src/api/checkout.ts",
        coverage_level: "edge",
        test_files: ["tests/checkout.test.ts"],
      },
      {
        kind: "route",
        identifier: "GET /api/health",
        file_path: "src/api/health.ts",
        coverage_level: "smoke",
        test_files: ["tests/smoke.test.ts"],
      },
      {
        kind: "component",
        identifier: "BadgeManager",
        file_path: "src/components/BadgeManager.tsx",
        coverage_level: "none",
      },
      {
        kind: "model",
        identifier: "userSchema",
        file_path: "src/models/user.ts",
        coverage_level: "smoke",
        test_files: ["tests/user.test.ts"],
      },
      {
        kind: "integration",
        identifier: "stripe",
        coverage_level: "none",
      },
    ],
    summary: {
      total_surfaces: 7,
      covered_surfaces: 4,
      coverage_by_kind: {
        route: { total: 4, covered: 3 },
        component: { total: 1, covered: 0 },
        model: { total: 1, covered: 1 },
        integration: { total: 1, covered: 0 },
      },
    },
    project: { repo_root: "/tmp/host", commit_hash: "abc1234" },
    ...overrides,
  };
}

describe("Vibe Test handshake reader — artifact schema v1", () => {
  it("fresh v1 artifact → present ok, coverage extracted from surfaces[]", () => {
    writeCoveredSurfaces(schemaV1Doc());

    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(true);
    expect(h.reason).toBe("ok");
    expect(h.schemaVersion).toBe(1);
    // Routes only — components/models/integrations are not endpoints.
    expect(h.uncoveredEndpoints).toEqual(["GET /api/admin/users"]);
    expect(h.endpointsWithBehavioralTests).toEqual([
      "POST /api/login",
      "POST /api/checkout", // edge implies behavioral-or-better
    ]);
    expect(h.endpointsWithEdgeCaseTests).toEqual(["POST /api/checkout"]);
    expect(h.surfaceTotals).toEqual({ total: 7, routes: 4, uncoveredRoutes: 1 });
  });

  it("v1 carries no tier/modifiers/stack — always null/empty, named in unavailable", () => {
    writeCoveredSurfaces(schemaV1Doc());

    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.inheritedTier).toBeNull();
    expect(h.modifiers).toEqual([]);
    expect(h.detectedStack).toEqual({
      frontend: [],
      backend: [],
      auth: [],
      integrations: [],
    });
    expect(h.unavailable).toEqual(["tier", "modifiers", "detected_stack"]);
  });

  it("REGRESSION TRIPWIRE: the pre-rewrite imaginary shape is rejected loudly", () => {
    // This is the exact fixture shape vibe-sec ≤0.7.0 tested against — keys
    // Vibe Test's schema forbids (additionalProperties: false) and never
    // emitted. The old reader green-lit it ("ok") while a REAL artifact
    // yielded zero data. It must now degrade as unsupported-schema, never ok.
    writeCoveredSurfaces({
      classification: {
        tier: "public-facing",
        modifiers: ["has-auth", "has-payments"],
        generated_at: "2026-05-23T06:00:00Z",
      },
      covered_surfaces: {
        endpoints_with_behavioral_tests: ["/api/login"],
        endpoints_with_edge_case_tests: ["/api/checkout"],
      },
      uncovered_surfaces: { endpoints: ["/api/admin/users"] },
      detected_stack: { frontend: ["next"], auth: ["clerk"], integrations: ["stripe"] },
    });

    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("unsupported-schema");
    expect(h.inheritedTier).toBeNull();
    expect(h.uncoveredEndpoints).toEqual([]);
  });

  it("future schema_version → unsupported-schema with the version surfaced", () => {
    writeCoveredSurfaces(schemaV1Doc({ schema_version: 2 }));
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("unsupported-schema");
    expect(h.schemaVersion).toBe(2);
  });

  it("absent → falls back to self-classify, never throws", () => {
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("absent");
    expect(h.inheritedTier).toBeNull();
  });

  it("stale (>24h) → ignored, self-classify", () => {
    writeCoveredSurfaces(
      schemaV1Doc({ generated_at: "2026-05-21T12:00:00Z" }), // 48h old
    );
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("stale");
  });

  it("undated artifact → fail-safe to stale (cannot prove freshness)", () => {
    const doc = schemaV1Doc();
    delete (doc as Record<string, unknown>)["generated_at"];
    writeCoveredSurfaces(doc);
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("stale");
  });

  it("corrupt JSON → never throws, reason corrupt", () => {
    const file = vibeTestCoveredSurfacesPath(tmp);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "{ not json ", "utf8");
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("corrupt");
  });

  it("surfaces missing/non-array → ok with zero signal (schema requires it, tolerate gently)", () => {
    writeCoveredSurfaces(schemaV1Doc({ surfaces: undefined }));
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(true);
    expect(h.surfaceTotals.total).toBe(0);
    expect(h.uncoveredEndpoints).toEqual([]);
  });

  it("uncovered routes elevate audit priority", () => {
    writeCoveredSurfaces(schemaV1Doc());
    const h = readVibeTestHandshake(tmp, NOW);
    expect(shouldElevateForUncovered(h)).toBe(true);
  });

  it("no uncovered routes → no elevation", () => {
    writeCoveredSurfaces(
      schemaV1Doc({
        surfaces: [
          {
            kind: "route",
            identifier: "POST /api/login",
            coverage_level: "behavioral",
          },
        ],
      }),
    );
    const h = readVibeTestHandshake(tmp, NOW);
    expect(shouldElevateForUncovered(h)).toBe(false);
  });
});

describe("handshakeStatusLine — the loud line, ok or degraded, never silent", () => {
  it("ok line names surfaces read, uncovered routes, and what v1 cannot supply", () => {
    writeCoveredSurfaces(schemaV1Doc());
    const line = handshakeStatusLine(readVibeTestHandshake(tmp, NOW));
    expect(line).toContain("vibe-test handshake: ok");
    expect(line).toContain("7 surfaces read");
    expect(line).toContain("1/4 routes uncovered");
    expect(line).toContain("tier self-classified");
  });

  it("degraded line names the reason", () => {
    const line = handshakeStatusLine(readVibeTestHandshake(tmp, NOW));
    expect(line).toContain("degraded (absent)");
    expect(line).toContain("self-classifying");
  });
});
