import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanTree, scanText, downgradeForContext, maskMatch } from "./scan-tree.js";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-secrets-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

// Build live-looking fixtures via concatenation so this test file itself does
// not trip push-protection / secret scanners.
const AWS = "AKIA" + "ABCDEFGHIJ234567"; // AKIA + 16 chars
const GH_PAT = "ghp_" + "a".repeat(36);
const STRIPE = "sk_live_" + "0123456789abcdefABCDEF99";
const OPENAI = "sk-" + "proj-" + "a".repeat(40);

describe("Layer A secret detection", () => {
  it("catches AWS / GitHub / Stripe / OpenAI patterns", () => {
    write("config.js", `const aws = "${AWS}";`);
    write("ci.yml", `token: ${GH_PAT}`);
    write("billing.ts", `const k = "${STRIPE}";`);
    write("ai.ts", `const o = "${OPENAI}";`);

    const { findings } = scanTree(tmp);
    const patterns = findings.map((f) => f.pattern);
    expect(patterns).toContain("AWS_ACCESS_KEY_ID");
    expect(patterns).toContain("GITHUB_PAT_CLASSIC");
    expect(patterns).toContain("STRIPE_LIVE_SECRET");
    expect(patterns).toContain("OPENAI_API_KEY");
  });

  it("masks the matched secret — never persists the raw value", () => {
    write("config.js", `const aws = "${AWS}";`);
    const { findings } = scanTree(tmp);
    const aws = findings.find((f) => f.pattern === "AWS_ACCESS_KEY_ID");
    expect(aws?.match).not.toBe(AWS);
    expect(aws?.match).toContain("…");
    expect(aws?.preview).not.toContain(AWS);
  });

  it("downgrades severity in example/sample/mock paths", () => {
    write("examples/aws.example.js", `const aws = "${AWS}";`);
    const { findings } = scanTree(tmp);
    const aws = findings.find((f) => f.pattern === "AWS_ACCESS_KEY_ID");
    // Critical in a fixture filename → medium.
    expect(aws?.severity).toBe("medium");
  });

  it("downgradeForContext: critical→medium, high→low in hint paths", () => {
    expect(downgradeForContext("critical", "sample.env")).toBe("medium");
    expect(downgradeForContext("high", "mock-data.json")).toBe("low");
    expect(downgradeForContext("critical", "src/index.ts")).toBe("critical");
  });

  it("skips node_modules and other ignored dirs", () => {
    write("node_modules/pkg/index.js", `const aws = "${AWS}";`);
    const { findings } = scanTree(tmp);
    expect(findings).toHaveLength(0);
  });

  it("ignores known placeholder strings", () => {
    const placeholder = "AKIA" + "IOSFODNN7EXAMPLE";
    write("docs.md", `Example: ${placeholder}`);
    const findings = scanText(`Example: ${placeholder}`, "docs.md");
    expect(findings.find((f) => f.pattern === "AWS_ACCESS_KEY_ID")).toBeUndefined();
  });

  it("reports line/column for a match", () => {
    write("a.ts", `line1\nline2\nconst k = "${STRIPE}";`);
    const { findings } = scanTree(tmp);
    const f = findings.find((x) => x.pattern === "STRIPE_LIVE_SECRET");
    expect(f?.line).toBe(3);
  });

  it("maskMatch shortens long values, keeps head + tail", () => {
    expect(maskMatch("abcdefghijklmnop")).toBe("abcdef…mnop");
  });
});
