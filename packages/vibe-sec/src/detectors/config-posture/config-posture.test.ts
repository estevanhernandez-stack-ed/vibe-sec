import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanCors } from "./cors.js";
import { analyzeHeaders, headerFindings } from "./headers.js";
import { scanCookies } from "./cookies.js";
import { scanFirebaseRules } from "./firebase-rules.js";
import { checkNextVersion, detectCve202529927, parseSemVer } from "./cve-2025-29927.js";
import { scanConfigPosture } from "./index.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-config-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

describe("CORS — origin reflection with credentials = Critical", () => {
  it("flags origin: true + credentials: true as Critical", () => {
    const src = `app.use(cors({ origin: true, credentials: true }));`;
    const findings = scanCors(src, "server.ts");
    expect(findings[0]!.finding_type).toBe("cors-origin-reflection-with-credentials");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("flags a reflect-callback + credentials as Critical", () => {
    const src = `cors({ origin: (o, cb) => cb(null, true), credentials: true })`;
    const findings = scanCors(src, "server.ts");
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("wildcard origin WITHOUT credentials is only Medium", () => {
    const src = `cors({ origin: "*" })`;
    const findings = scanCors(src, "server.ts");
    expect(findings[0]!.severity).toBe("medium");
  });
});

describe("security headers — missing routes to Auto", () => {
  it("reports missing baseline headers and routes them to Auto", () => {
    const posture = analyzeHeaders("// no security headers here");
    expect(posture.missing.length).toBeGreaterThan(0);
    const findings = headerFindings(posture);
    expect(findings.every((f) => f.fix_class === "auto" || f.fix_class === "advisory")).toBe(true);
    // CSP missing → auto (report-only form).
    const csp = findings.find((f) => f.header === "content-security-policy");
    expect(csp?.fix_class).toBe("auto");
  });

  it("a bare helmet() registration declares most of the baseline", () => {
    const posture = analyzeHeaders("app.use(helmet());");
    expect(posture.present.has("x-content-type-options")).toBe(true);
    expect(posture.present.has("strict-transport-security")).toBe(true);
  });

  it("flags a deprecated X-XSS-Protection header as advisory, never recommends adding", () => {
    const posture = analyzeHeaders('res.setHeader("X-XSS-Protection", "1; mode=block")');
    expect(posture.hasDeprecatedXssHeader).toBe(true);
    const findings = headerFindings(posture);
    const xss = findings.find((f) => f.finding_type === "deprecated-xss-header");
    expect(xss?.fix_class).toBe("advisory");
  });
});

describe("cookies — missing flags, auth-related ownership", () => {
  it("flags a session cookie missing HttpOnly as auth-related High", () => {
    const src = `res.cookie('session', token, { secure: true, sameSite: 'lax' });`;
    const findings = scanCookies(src, "auth.ts");
    expect(findings[0]!.authRelated).toBe(true);
    expect(findings[0]!.missingFlags).toContain("HttpOnly");
    expect(findings[0]!.severity).toBe("high");
  });

  it("a fully-flagged cookie is clean", () => {
    const src = `res.cookie('x', v, { httpOnly: true, secure: true, sameSite: 'strict' });`;
    expect(scanCookies(src, "a.ts")).toHaveLength(0);
  });
});

describe("Firebase rules — allow if true = Critical", () => {
  it("flags `allow read, write: if true`", () => {
    const rules = `
      service cloud.firestore {
        match /databases/{db}/documents {
          match /{document=**} {
            allow read, write: if true;
          }
        }
      }`;
    const findings = scanFirebaseRules(rules, "firestore.rules");
    expect(findings[0]!.finding_type).toBe("firebase-open-rule");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("flags RTDB .read/.write: true", () => {
    const rules = JSON.stringify({ rules: { ".read": true, ".write": true } });
    const findings = scanFirebaseRules(rules, "database.rules.json");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("a scoped auth rule is clean", () => {
    const rules = `allow read, write: if request.auth != null;`;
    expect(scanFirebaseRules(rules, "firestore.rules")).toHaveLength(0);
  });
});

describe("CVE-2025-29927 — Next.js middleware bypass", () => {
  it("parses semver and range floors", () => {
    expect(parseSemVer("^14.2.0")).toEqual({ major: 14, minor: 2, patch: 0 });
    expect(parseSemVer("15")).toEqual({ major: 15, minor: 0, patch: 0 });
  });

  it("fires on a vulnerable next version", () => {
    expect(checkNextVersion("14.2.0").vulnerable).toBe(true);
    expect(checkNextVersion("13.4.0").vulnerable).toBe(true);
    expect(checkNextVersion("15.1.0").vulnerable).toBe(true);
  });

  it("does NOT fire on a patched version", () => {
    expect(checkNextVersion("14.2.25").vulnerable).toBe(false);
    expect(checkNextVersion("15.2.3").vulnerable).toBe(false);
    expect(checkNextVersion("16.0.0").vulnerable).toBe(false);
  });

  it("detects from package.json", () => {
    write("package.json", JSON.stringify({ dependencies: { next: "^14.1.0" } }));
    const r = detectCve202529927(tmp);
    expect(r.vulnerable).toBe(true);
    expect(r.recommendedFix).toBe("14.2.25");
  });
});

describe("scanConfigPosture — wired over a fixture project", () => {
  it("surfaces a Critical CORS + a vulnerable next + missing headers together", () => {
    write("package.json", JSON.stringify({ dependencies: { next: "14.1.0" } }));
    write("server.ts", `app.use(cors({ origin: true, credentials: true }));`);
    const result = scanConfigPosture(tmp);
    expect(result.cors.some((f) => f.severity === "critical")).toBe(true);
    expect(result.cve202529927.vulnerable).toBe(true);
    expect(result.headerFindings.length).toBeGreaterThan(0);
  });
});
