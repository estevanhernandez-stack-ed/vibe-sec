import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  readVibeTestHandshake,
  shouldElevateForUncovered,
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

describe("Vibe Test handshake reader", () => {
  it("present + fresh → inherits tier + modifiers", () => {
    writeCoveredSurfaces({
      classification: {
        tier: "public-facing",
        modifiers: ["has-auth", "has-payments"],
        generated_at: "2026-05-23T06:00:00Z", // 6h old → fresh
      },
      covered_surfaces: {
        endpoints_with_behavioral_tests: ["/api/login"],
        endpoints_with_edge_case_tests: ["/api/checkout"],
      },
      uncovered_surfaces: { endpoints: ["/api/admin/users"] },
      detected_stack: {
        frontend: ["next"],
        backend: ["next-api"],
        auth: ["clerk"],
        integrations: ["stripe"],
      },
    });

    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(true);
    expect(h.reason).toBe("ok");
    expect(h.inheritedTier).toBe("public-facing");
    expect(h.modifiers).toEqual(["has-auth", "has-payments"]);
    expect(h.endpointsWithBehavioralTests).toEqual(["/api/login"]);
    expect(h.detectedStack.integrations).toEqual(["stripe"]);
  });

  it("absent → falls back to self-classify, never throws", () => {
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("absent");
    expect(h.inheritedTier).toBeNull();
  });

  it("stale (>24h) → ignored, self-classify", () => {
    writeCoveredSurfaces({
      classification: {
        tier: "regulated",
        generated_at: "2026-05-21T12:00:00Z", // 48h old
      },
    });
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(false);
    expect(h.reason).toBe("stale");
    expect(h.inheritedTier).toBeNull();
  });

  it("undated handshake → fail-safe to stale (cannot prove freshness)", () => {
    writeCoveredSurfaces({ classification: { tier: "public-facing" } });
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

  it("invalid tier string → inheritedTier null but other fields still read", () => {
    writeCoveredSurfaces({
      classification: {
        tier: "ultra-mega-tier",
        generated_at: "2026-05-23T11:00:00Z",
      },
      uncovered_surfaces: { endpoints: ["/x"] },
    });
    const h = readVibeTestHandshake(tmp, NOW);
    expect(h.present).toBe(true);
    expect(h.inheritedTier).toBeNull();
    expect(h.uncoveredEndpoints).toEqual(["/x"]);
  });

  it("uncovered endpoints elevate audit priority", () => {
    writeCoveredSurfaces({
      classification: { tier: "public-facing", generated_at: "2026-05-23T11:00:00Z" },
      uncovered_surfaces: { endpoints: ["/api/admin/users", "/api/admin/billing"] },
    });
    const h = readVibeTestHandshake(tmp, NOW);
    expect(shouldElevateForUncovered(h)).toBe(true);
    expect(h.uncoveredEndpoints).toHaveLength(2);
  });

  it("no uncovered endpoints → no elevation", () => {
    writeCoveredSurfaces({
      classification: { tier: "public-facing", generated_at: "2026-05-23T11:00:00Z" },
    });
    const h = readVibeTestHandshake(tmp, NOW);
    expect(shouldElevateForUncovered(h)).toBe(false);
  });
});
