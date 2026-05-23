import { describe, it, expect } from "vitest";
import { scanAst, isParseable } from "./ast-walk.js";

// Build live-looking secrets at runtime so this test file doesn't trip
// push-protection. These are fake but long-and-entropy-ish enough to pass the
// looksSecret() gate (≥16 chars, no whitespace).
const FAKE_KEY = "sk_" + "live_" + "0123456789abcdefABCDEF99";
const FAKE_TOKEN = "ghp_" + "ZqWeRtYuIoP1234567890aSdFgHjKlZxCvBn";

describe("isParseable", () => {
  it("recognizes JS/TS/JSX/TSX/mjs/cjs", () => {
    expect(isParseable("a.ts")).toBe(true);
    expect(isParseable("a.tsx")).toBe(true);
    expect(isParseable("a.jsx")).toBe(true);
    expect(isParseable("a.mjs")).toBe(true);
    expect(isParseable("a.json")).toBe(false);
    expect(isParseable("a.py")).toBe(false);
  });
});

describe("Layer C AST — JSX prop leaks (regex misses these)", () => {
  it("catches a hardcoded secret in a JSX attribute", () => {
    const src = `
      export function App() {
        return <PaymentForm apiKey="${FAKE_KEY}" amount={100} />;
      }
    `;
    const findings = scanAst(src, "App.tsx");
    expect(findings.some((f) => f.pattern === "AST_JSX_PROP_SECRET")).toBe(true);
    const f = findings.find((x) => x.pattern === "AST_JSX_PROP_SECRET");
    expect(f?.match).not.toBe(FAKE_KEY); // masked
  });

  it("does not flag a JSX prop with a non-secret name", () => {
    const src = `export const X = () => <Img className="${FAKE_KEY}" />;`;
    const findings = scanAst(src, "X.tsx");
    expect(findings.filter((f) => f.pattern === "AST_JSX_PROP_SECRET")).toHaveLength(0);
  });
});

describe("Layer C AST — process.env.X overwrite (regex misses these)", () => {
  it("catches process.env.X = \"literal-secret\"", () => {
    const src = `process.env.STRIPE_KEY = "${FAKE_TOKEN}";`;
    const findings = scanAst(src, "boot.ts");
    expect(findings.some((f) => f.pattern === "AST_PROCESS_ENV_OVERWRITE")).toBe(true);
  });

  it("does not flag process.env.X = process.env.Y (no literal)", () => {
    const src = `process.env.A = process.env.B;`;
    expect(scanAst(src, "boot.ts").filter((f) => f.pattern === "AST_PROCESS_ENV_OVERWRITE")).toHaveLength(0);
  });
});

describe("Layer C AST — robustness", () => {
  it("returns [] for non-parseable extensions without throwing", () => {
    expect(scanAst(`apiKey: "${FAKE_KEY}"`, "config.yaml")).toEqual([]);
  });

  it("returns [] (not throw) on a syntax-error file", () => {
    expect(() => scanAst("const = = =;;; <<<", "broken.ts")).not.toThrow();
  });

  it("ignores placeholder-looking values", () => {
    const src = `process.env.KEY = "your-api-key-here";`;
    expect(scanAst(src, "boot.ts")).toHaveLength(0);
  });
});
