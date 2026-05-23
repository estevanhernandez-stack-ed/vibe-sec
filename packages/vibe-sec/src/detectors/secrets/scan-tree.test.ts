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

// ─── Regression: Firebase web API keys are public-by-design (WSYATM dogfood) ─
// An AIza… web key in a firebase config object was double-tagged: GOOGLE_API_KEY
// (high) AND FIREBASE_WEB_API_KEY (low). Per Decision 21 / spec §4.2 it must be a
// SINGLE informational/low tag routed to the rules companion — never a high
// secret, never double-counted. Server keys / private keys keep their severity.
describe("Firebase web API key classification (regression)", () => {
  // Build the AIza… literal by concatenation so this file doesn't trip scanners.
  const FIREBASE_WEB_KEY = "AIza" + "Sy" + "A".repeat(33); // AIza + 35 chars

  it("tags an apiKey: 'AIza…' web key as informational FIREBASE_WEB_API_KEY only", () => {
    const cfg = `const firebaseConfig = { apiKey: "${FIREBASE_WEB_KEY}", projectId: "demo" };`;
    const findings = scanText(cfg, "src/firebase.ts");
    const fb = findings.filter((f) => f.pattern === "FIREBASE_WEB_API_KEY");
    const google = findings.filter((f) => f.pattern === "GOOGLE_API_KEY");
    expect(fb.length).toBe(1);
    expect(fb[0]!.informational).toBe(true);
    expect(fb[0]!.companion).toBe("config-posture");
    expect(fb[0]!.severity).toBe("low");
    // The GOOGLE_API_KEY double-tag on the SAME literal/line must be suppressed.
    expect(google.length).toBe(0);
  });

  it("recognizes the env-fallback form: apiKey: import.meta.env.X || 'AIza…'", () => {
    const cfg = `apiKey: import.meta.env.VITE_CONTENT_DB_API_KEY || "${FIREBASE_WEB_KEY}",`;
    const findings = scanText(cfg, "src/contentDb/firebase.ts");
    expect(findings.filter((f) => f.pattern === "FIREBASE_WEB_API_KEY").length).toBe(1);
    expect(findings.filter((f) => f.pattern === "GOOGLE_API_KEY").length).toBe(0);
  });

  it("recognizes a VITE_FIREBASE_API_KEY=AIza… env assignment as a web key", () => {
    const env = `VITE_FIREBASE_API_KEY=${FIREBASE_WEB_KEY}`;
    const findings = scanText(env, "frontend/.env");
    expect(findings.filter((f) => f.pattern === "FIREBASE_WEB_API_KEY").length).toBe(1);
    expect(findings.filter((f) => f.pattern === "GOOGLE_API_KEY").length).toBe(0);
  });

  it("keeps a server GEMINI_API_KEY=AIza… at GOOGLE_API_KEY high (NOT downgraded)", () => {
    // Server-side Gemini key — billable, genuinely sensitive, not public-by-design.
    const env = `GEMINI_API_KEY=${FIREBASE_WEB_KEY}`;
    const findings = scanText(env, "functions/.env");
    expect(findings.filter((f) => f.pattern === "GOOGLE_API_KEY").length).toBe(1);
    expect(findings.find((f) => f.pattern === "GOOGLE_API_KEY")!.severity).toBe("high");
    expect(findings.some((f) => f.pattern === "FIREBASE_WEB_API_KEY")).toBe(false);
  });

  it("STILL flags a bare AIza… (non-apiKey context) as GOOGLE_API_KEY high", () => {
    // A loose AIza… not in an apiKey assignment — could be a real server key.
    const loose = `const k = "${FIREBASE_WEB_KEY}";`;
    const findings = scanText(loose, "scripts/batch.sh");
    const google = findings.filter((f) => f.pattern === "GOOGLE_API_KEY");
    expect(google.length).toBe(1);
    expect(google[0]!.severity).toBe("high");
    expect(findings.some((f) => f.pattern === "FIREBASE_WEB_API_KEY")).toBe(false);
  });

  it("keeps a service-account PRIVATE KEY at critical (not downgraded)", () => {
    const sa = `"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIabc\\n-----END PRIVATE KEY-----\\n"`;
    const findings = scanText(sa, "functions/service-account.json");
    const pk = findings.find((f) => f.pattern === "PRIVATE_KEY_BLOCK");
    expect(pk).toBeTruthy();
    expect(pk!.severity).toBe("critical");
  });
});
