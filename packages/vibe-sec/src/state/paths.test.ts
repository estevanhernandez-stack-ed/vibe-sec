import { describe, it, expect } from "vitest";
import path from "node:path";
import {
  globalDataDir,
  projectStateDir,
  pendingFixesDir,
  findingsPath,
  auditStatePath,
  vibeTestCoveredSurfacesPath,
} from "./paths.js";

// These tests assert structural correctness using path.sep so they pass on
// both win32 and posix (the harness runs on win32; CI may run posix).
function seg(...parts: string[]): string {
  return parts.join(path.sep);
}

describe("data-dir resolution (win32 + posix)", () => {
  it("globalDataDir resolves under the supplied home", () => {
    const home = path.resolve("/some/home");
    const dir = globalDataDir(home);
    expect(dir).toBe(path.join(home, ".claude", "plugins", "data", "vibe-sec"));
    expect(dir.endsWith(seg(".claude", "plugins", "data", "vibe-sec"))).toBe(true);
  });

  it("projectStateDir resolves <project>/.vibe-sec/state", () => {
    const root = path.resolve("/proj");
    expect(projectStateDir(root)).toBe(path.join(root, ".vibe-sec", "state"));
  });

  it("projectStateDir scopes per-app with --app (Conflict 9 = C)", () => {
    const root = path.resolve("/proj");
    expect(projectStateDir(root, "web")).toBe(
      path.join(root, ".vibe-sec", "apps", "web", "state"),
    );
  });

  it("pendingFixesDir resolves the fixes dir", () => {
    const root = path.resolve("/proj");
    expect(pendingFixesDir(root)).toBe(
      path.join(root, ".vibe-sec", "pending", "fixes"),
    );
  });

  it("findingsPath + auditStatePath sit in the state dir", () => {
    const root = path.resolve("/proj");
    expect(findingsPath(root)).toBe(
      path.join(root, ".vibe-sec", "state", "findings.jsonl"),
    );
    expect(auditStatePath(root)).toBe(
      path.join(root, ".vibe-sec", "state", "audit.json"),
    );
  });

  it("vibeTestCoveredSurfacesPath points at the sibling handshake file", () => {
    const root = path.resolve("/proj");
    expect(vibeTestCoveredSurfacesPath(root)).toBe(
      path.join(root, ".vibe-test", "state", "covered-surfaces.json"),
    );
  });

  it("uses the platform separator (no hardcoded slashes)", () => {
    const dir = projectStateDir(path.resolve("/proj"));
    expect(dir.includes(path.sep)).toBe(true);
    // On win32 the resolved path must not contain forward slashes in segments.
    if (path.sep === "\\") {
      expect(dir.split(path.sep).every((s) => !s.includes("/"))).toBe(true);
    }
  });
});
