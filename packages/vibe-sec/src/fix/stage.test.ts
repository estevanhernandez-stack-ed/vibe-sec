import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stageFix, listStagedFixes, clearStagedFix, stagedFixRef } from "./stage.js";
import { recordSuppression, isSuppressed, GLOBAL_PROMPT_THRESHOLD } from "./suppression.js";
import { makeFinding, type Finding } from "../state/findings.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-stage-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function mk(id: string, finding_type: string): Finding {
  return makeFinding({
    id,
    primary_concern: "auth-model",
    severity_base: "high",
    severity_tier_adjusted: "high",
    confidence: 0.8,
    finding_type,
    title: finding_type,
    tier: "public-facing",
    fix_class: "stage",
    tool_of_record: "in-house",
  });
}

describe("3.5 stage — writes pending/fixes/*.diff", () => {
  it("writes a diff file under .vibe-sec/pending/fixes and returns the fix_ref", () => {
    const finding = mk("auth-7", "admin-route-no-auth");
    const staged = stageFix(tmp, finding, "--- a/route.ts\n+++ b/route.ts\n@@ +auth()\n");
    expect(fs.existsSync(staged.filePath)).toBe(true);
    expect(staged.fixRef).toBe(stagedFixRef(finding));
    expect(staged.fixRef).toContain(".vibe-sec/pending/fixes/");
    const content = fs.readFileSync(staged.filePath, "utf8");
    expect(content).toContain("Staged by vibe-sec");
    expect(content).toContain("auth-7");
  });

  it("re-staging overwrites the same file (id-keyed)", () => {
    const finding = mk("auth-7", "admin-route-no-auth");
    stageFix(tmp, finding, "diff v1");
    stageFix(tmp, finding, "diff v2");
    expect(listStagedFixes(tmp)).toHaveLength(1);
    expect(fs.readFileSync(stageFix(tmp, finding, "diff v3").filePath, "utf8")).toContain("diff v3");
  });

  it("clearStagedFix removes an applied diff", () => {
    const finding = mk("auth-7", "admin-route-no-auth");
    stageFix(tmp, finding, "diff");
    expect(clearStagedFix(tmp, finding)).toBe(true);
    expect(listStagedFixes(tmp)).toHaveLength(0);
  });
});

describe("3.5 suppression — per-project, prompt-global after 5", () => {
  it("suppresses per-project and reports it suppressed", () => {
    recordSuppression(tmp, { finding_type: "floating-version-pin", reason: "intentional latest in a sandbox" });
    expect(isSuppressed(tmp, "floating-version-pin")).toBe(true);
    expect(isSuppressed(tmp, "some-other-type")).toBe(false);
  });

  it("offers global suppression on the 5th repetition, not before or after", () => {
    let offered = 0;
    for (let i = 0; i < 7; i++) {
      const res = recordSuppression(tmp, { finding_type: "no-rate-limit-library", reason: "internal cron only" });
      if (res.offerGlobal) offered = res.repetitions;
    }
    expect(offered).toBe(GLOBAL_PROMPT_THRESHOLD);
  });
});
