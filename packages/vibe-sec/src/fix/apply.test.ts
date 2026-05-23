import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyGitignoreAdd,
  scaBumpDecision,
  actionShaPinDecision,
  canAutoApply,
  isAutoApplyable,
  GITIGNORE_BANNER,
  type CommandRunner,
} from "./apply.js";
import { makeFinding, type Finding } from "../state/findings.js";
import type { Concern } from "../types.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-apply-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function mkFinding(primary_concern: Concern, finding_type: string, fix_class: Finding["fix_class"] = "auto"): Finding {
  return makeFinding({
    id: "f-1",
    primary_concern,
    severity_base: "high",
    severity_tier_adjusted: "high",
    confidence: 0.95,
    finding_type,
    title: finding_type,
    tier: "public-facing",
    fix_class,
    tool_of_record: "in-house",
  });
}

describe("3.5 --auto adds .gitignore + carries the future-commits banner", () => {
  it("creates .gitignore and appends entries", () => {
    const res = applyGitignoreAdd({ projectRoot: tmp }, [".env", "*.pem", "service-account*.json"]);
    expect(res.applied).toBe(true);
    const content = fs.readFileSync(path.join(tmp, ".gitignore"), "utf8");
    expect(content).toContain(".env");
    expect(content).toContain("*.pem");
    expect(content).toContain("service-account*.json");
  });

  it("ALWAYS returns the 'only prevents future commits' banner", () => {
    const res = applyGitignoreAdd({ projectRoot: tmp }, [".env"]);
    expect(res.banner).toBe(GITIGNORE_BANNER);
    expect(res.banner).toContain("rotate it now");
  });

  it("is idempotent — re-adding an existing entry is a no-op", () => {
    applyGitignoreAdd({ projectRoot: tmp }, [".env"]);
    const second = applyGitignoreAdd({ projectRoot: tmp }, [".env"]);
    expect(second.applied).toBe(false);
    const lines = fs.readFileSync(path.join(tmp, ".gitignore"), "utf8").split("\n").filter((l) => l.trim() === ".env");
    expect(lines).toHaveLength(1);
  });

  it("runs git rm --cached for added entries when a runner is wired", () => {
    const calls: string[][] = [];
    const runner: CommandRunner = (cmd, args) => {
      calls.push([cmd, ...args]);
      return { stdout: "", code: 0 };
    };
    applyGitignoreAdd({ projectRoot: tmp, runner }, [".env"]);
    expect(calls.some((c) => c[0] === "git" && c.includes("rm") && c.includes("--cached"))).toBe(true);
  });
});

describe("3.5 --auto REFUSES the destructive set (secret rotation)", () => {
  it("canAutoApply is false for a secret finding regardless of kind", () => {
    const secret = mkFinding("secret-detection", "aws-access-key");
    // Even if a caller mislabels the kind as an allowlisted one, the destructive
    // guard rejects it — the chokepoint holds.
    expect(canAutoApply(secret, "gitignore-add")).toBe(false);
  });

  it("canAutoApply is false for auth-logic findings", () => {
    expect(canAutoApply(mkFinding("auth-model", "idor-ref"), "additive-security-header")).toBe(false);
  });

  it("canAutoApply is true only for non-destructive + allowlisted + fix_class=auto", () => {
    expect(canAutoApply(mkFinding("config-posture", "missing-security-header"), "additive-security-header")).toBe(true);
  });

  it("non-allowlisted kind is rejected even when non-destructive", () => {
    expect(canAutoApply(mkFinding("config-posture", "missing-security-header"), "rewrite-everything")).toBe(false);
    expect(isAutoApplyable("rewrite-everything")).toBe(false);
  });

  it("a stage/inline-classed finding is never auto even if allowlisted", () => {
    expect(canAutoApply(mkFinding("config-posture", "missing-security-header", "stage"), "additive-security-header")).toBe(false);
  });
});

describe("3.5 SCA in-range bump — lockfile-churn rollback", () => {
  it("auto-applies when churn ≤ 50 lines", () => {
    const res = scaBumpDecision({ projectRoot: tmp, lockfileChurnLines: 12 });
    expect(res.applied).toBe(true);
    expect(res.rolledBackToStage).toBe(false);
  });

  it("re-stages when churn > 50 lines", () => {
    const res = scaBumpDecision({ projectRoot: tmp, lockfileChurnLines: 73 });
    expect(res.applied).toBe(false);
    expect(res.rolledBackToStage).toBe(true);
    expect(res.detail).toContain("re-staged");
  });
});

describe("3.5 SHA-pin a GitHub Action — CI-recency gate", () => {
  it("auto-pins only when CI passed recently", () => {
    expect(actionShaPinDecision({ projectRoot: tmp, ciPassedRecently: true }).applied).toBe(true);
  });
  it("stages the pin when no recent green CI", () => {
    const res = actionShaPinDecision({ projectRoot: tmp, ciPassedRecently: false });
    expect(res.applied).toBe(false);
    expect(res.detail).toContain("staged");
  });
});
