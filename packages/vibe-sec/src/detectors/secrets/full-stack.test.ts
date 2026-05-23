import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanInhouseFull, scanSecrets } from "./index.js";
import { SECRET_PATTERNS } from "./patterns.js";
import type { ToolProbe } from "../../orchestration/tool-registry.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-fullstack-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

const noTools: ToolProbe = (tool) => ({ name: tool, present: false, version: null });

// Runtime-built fakes.
const SENDGRID = "SG." + "abcdefghijklmnopqrstuv" + "." + "a".repeat(43);
const NPM_TOKEN = "npm_" + "ZqWeRtYuIoP1234567890aSdFgHjKlZxCvBn";
const FAKE_JSX_KEY = "sk_" + "live_" + "0123456789abcdefABCDEF99";

describe("expanded provider catalog (Phase 2.1)", () => {
  it("has grown well past the Phase 1 baseline (40-50 target)", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(35);
  });

  it("catches new providers: SendGrid + NPM token", () => {
    write("mail.ts", `const sg = "${SENDGRID}";`);
    write(".npmrc-ish.txt", `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`);
    const { findings } = scanInhouseFull(tmp);
    const patterns = findings.map((f) => f.pattern);
    expect(patterns).toContain("SENDGRID_API_KEY");
    expect(patterns).toContain("NPM_ACCESS_TOKEN");
  });

  it("classifies Firebase web apiKey as informational + config-posture companion", () => {
    const fb = SECRET_PATTERNS.find((p) => p.name === "FIREBASE_WEB_API_KEY");
    expect(fb?.informational).toBe(true);
    expect(fb?.companion).toBe("config-posture");
    expect(fb?.severity).toBe("low");
  });

  it("does NOT double-count a Firebase web key across layers (one tag, low)", () => {
    // The full stack (A regex + B entropy) would otherwise tag the same AIza…
    // literal as FIREBASE_WEB_API_KEY (low) AND HIGH_ENTROPY_ASSIGN (medium).
    const webKey = "AIza" + "Sy" + "B".repeat(33);
    write("firebase.ts", `const firebaseConfig = { apiKey: "${webKey}" };`);
    const { findings } = scanInhouseFull(tmp);
    const onLine = findings.filter((f) => f.file === "firebase.ts");
    expect(onLine.filter((f) => f.pattern === "FIREBASE_WEB_API_KEY").length).toBe(1);
    expect(onLine.some((f) => f.pattern === "GOOGLE_API_KEY")).toBe(false);
    expect(onLine.some((f) => f.pattern === "HIGH_ENTROPY_ASSIGN")).toBe(false);
    // The single surviving secret tag is the low, public-by-design one.
    const webTags = onLine.filter((f) => f.pattern === "FIREBASE_WEB_API_KEY");
    expect(webTags[0]!.severity).toBe("low");
  });
});

describe("in-house full stack — A + B + C composed", () => {
  it("AST layer catches a JSX-prop leak the regex layer alone would miss", () => {
    // No `key = "..."` assignment; the secret lives in a JSX attribute.
    write(
      "Pay.tsx",
      `export const Pay = () => <Stripe apiKey="${FAKE_JSX_KEY}" />;`,
    );
    const { findings } = scanInhouseFull(tmp);
    expect(findings.some((f) => f.pattern === "AST_JSX_PROP_SECRET")).toBe(true);
  });

  it("dedupes overlapping matches by file:line:column (A wins over B)", () => {
    // A provider key assigned to a secret-shaped name — Layer A regex AND Layer
    // B entropy could both fire on the same range; dedup keeps one.
    const sg = SENDGRID;
    write("m.ts", `const apiKey = "${sg}";`);
    const { findings } = scanInhouseFull(tmp);
    const atSameSpot = findings.filter((f) => f.file === "m.ts" && f.line === 1);
    // Exactly one finding per line:column even if multiple layers matched.
    const cols = new Set(atSameSpot.map((f) => `${f.line}:${f.column}`));
    expect(atSameSpot.length).toBe(cols.size);
  });
});

describe("scanSecrets composition options", () => {
  it("forceInhouse runs the full stack even with no tool present", () => {
    write("Pay.tsx", `export const Pay = () => <Stripe apiKey="${FAKE_JSX_KEY}" />;`);
    const result = scanSecrets(tmp, { probe: noTools, forceInhouse: true });
    expect(result.deferred).toBe(false);
    expect(result.toolOfRecord).toBe("in-house");
    expect(result.findings.some((f) => f.pattern === "AST_JSX_PROP_SECRET")).toBe(true);
  });

  it("--verify skips gracefully when trufflehog is absent, with a reason", () => {
    write("a.ts", "const x = 1;");
    const result = scanSecrets(tmp, { probe: noTools, verify: true });
    expect(result.verifiedFindings).toEqual([]);
    expect(result.verifySkippedReason).toMatch(/trufflehog/i);
  });
});
