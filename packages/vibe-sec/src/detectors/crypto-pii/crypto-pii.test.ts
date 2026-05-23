import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanPrimitives } from "./primitives.js";
import { scanPasswordHashing } from "./password-hashing.js";
import { scanJwt } from "./jwt-audit.js";
import { scanPiiInventory, scanClientKeyLeak } from "./pii-inventory.js";
import { scanPiiInLogs } from "./pii-in-logs.js";
import { scanCryptoPii } from "./index.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-crypto-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf8");
}

const noProbe = { probe: () => ({ name: "semgrep" as const, present: false, version: null }) };

describe("password hashing — bcrypt cost below floor", () => {
  it("flags bcrypt.hash(pw, 10) as High", () => {
    const { findings } = scanPasswordHashing(`const h = await bcrypt.hash(pw, 10);`, "auth.ts");
    const f = findings.find((x) => x.finding_type === "bcrypt-cost-below-floor");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("high");
    expect(f!.observed).toBe(10);
  });

  it("does NOT flag bcrypt cost 12+", () => {
    const { findings } = scanPasswordHashing(`bcrypt.hash(pw, 12)`, "auth.ts");
    expect(findings.some((x) => x.finding_type === "bcrypt-cost-below-floor")).toBe(false);
  });

  it("legacy-hash migration is informational-not-finding", () => {
    const src = `if (user.passwordVersion === 1) { await rehash(pw); }`;
    const { findings, migrations } = scanPasswordHashing(src, "auth.ts");
    expect(migrations.length).toBeGreaterThan(0);
    expect(migrations[0]!.migration).toBe(true);
    // The migration branch itself is not emitted as a finding.
    expect(findings.some((x) => x.finding_type === "bcrypt-cost-below-floor")).toBe(false);
  });

  it("flags weak Argon2 memoryCost", () => {
    const { findings } = scanPasswordHashing(`argon2.hash(pw, { memoryCost: 4096 })`, "auth.ts");
    expect(findings.some((x) => x.finding_type === "argon2-weak-params")).toBe(true);
  });
});

describe("JWT audit — Critical findings", () => {
  it("flags the none algorithm as Critical", () => {
    const findings = scanJwt(`jwt.sign(payload, key, { algorithm: 'none' })`, "token.ts");
    const f = findings.find((x) => x.finding_type === "jwt-none-algorithm");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("critical");
  });

  it("flags jwt.verify without an algorithms: constraint as Critical", () => {
    const findings = scanJwt(`const claims = jwt.verify(token, secret);`, "token.ts");
    const f = findings.find((x) => x.finding_type === "jwt-verify-missing-algorithms");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("critical");
  });

  it("does NOT flag jwt.verify WITH an algorithms: constraint", () => {
    const findings = scanJwt(
      `jwt.verify(token, secret, { algorithms: ['HS256'] })`,
      "token.ts",
    );
    expect(findings.some((x) => x.finding_type === "jwt-verify-missing-algorithms")).toBe(false);
  });

  it("flags a short hardcoded HS256 secret as Critical (fake short secret)", () => {
    // obviously-fake short dev secret — exercises the byte-length path only.
    const findings = scanJwt(`jwt.sign(payload, "devsecret123")`, "token.ts");
    const f = findings.find((x) => x.finding_type === "jwt-short-secret");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("critical");
  });

  it("flags a constant secret fallback", () => {
    const findings = scanJwt(
      `const s = process.env.JWT_SECRET || "fallback-dev";`,
      "token.ts",
    );
    expect(findings.some((x) => x.finding_type === "jwt-secret-fallback")).toBe(true);
  });
});

describe("crypto primitives", () => {
  it("flags MD5 used for password (security context) as High", () => {
    const findings = scanPrimitives(
      `const h = crypto.createHash('md5').update(password).digest('hex');`,
      "auth.ts",
    );
    const f = findings.find((x) => x.finding_type === "weak-hash-primitive");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("high");
  });

  it("downgrades MD5 used for a checksum to Low", () => {
    const findings = scanPrimitives(
      `const etag = createHash('md5').update(body).digest('hex'); // cache key`,
      "cache.ts",
    );
    const f = findings.find((x) => x.finding_type === "weak-hash-primitive");
    expect(f!.severity).toBe("low");
  });

  it("flags a dead cipher (rc4) as High", () => {
    const findings = scanPrimitives(`crypto.createCipheriv("rc4", key, iv)`, "enc.ts");
    expect(findings.some((x) => x.finding_type === "dead-cipher")).toBe(true);
  });

  it("flags AES-ECB mode as High", () => {
    const findings = scanPrimitives(`createCipheriv("aes-256-ecb", key)`, "enc.ts");
    expect(findings.some((x) => x.finding_type === "ecb-mode")).toBe(true);
  });
});

describe("PII inventory + client key leakage", () => {
  it("inventories Prisma model PII fields", () => {
    const schema = `
      model User {
        id    Int    @id
        email String
        ssn   String?
        bio   String?
      }
    `;
    const fields = scanPiiInventory(schema, "schema.prisma");
    const names = fields.map((f) => f.field);
    expect(names).toContain("email");
    expect(names).toContain("ssn");
    expect(names).not.toContain("bio");
    expect(fields.find((f) => f.field === "ssn")!.category).toBe("government-id");
  });

  it("inventories Zod schema PII fields", () => {
    const src = `const s = z.object({ email: z.string().email(), phone: z.string() });`;
    const fields = scanPiiInventory(src, "validators.ts");
    expect(fields.map((f) => f.field)).toEqual(expect.arrayContaining(["email", "phone"]));
  });

  it("flags a NEXT_PUBLIC_ server-secret-shaped var as client key leak", () => {
    const findings = scanClientKeyLeak(`const k = process.env.NEXT_PUBLIC_API_SECRET;`, "client.ts");
    expect(findings.length).toBe(1);
    expect(findings[0]!.variable).toBe("NEXT_PUBLIC_API_SECRET");
  });

  it("does NOT flag a publishable/anon public var", () => {
    const findings = scanClientKeyLeak(
      `const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;`,
      "client.ts",
    );
    expect(findings.length).toBe(0);
  });
});

describe("PII in logs", () => {
  it("flags PII sent to a third-party tracker as High", () => {
    const findings = scanPiiInLogs(`Sentry.setUser({ email: user.email });`, "log.ts");
    const f = findings.find((x) => x.finding_type === "pii-in-third-party-tracker");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("high");
  });

  it("flags PII in a local console.log as Medium", () => {
    const findings = scanPiiInLogs(`console.log("user", user.ssn);`, "log.ts");
    const f = findings.find((x) => x.finding_type === "pii-in-local-log");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("medium");
  });
});

describe("crypto-pii orchestrator (in-house, Semgrep absent)", () => {
  it("assembles the full result over a project tree", () => {
    write("schema.prisma", `model User { id Int @id  email String  ssn String? }`);
    write("src/auth.ts", `await bcrypt.hash(pw, 8); jwt.verify(token, secret);`);
    write("src/client.ts", `const k = process.env.VITE_STRIPE_SECRET_KEY;`);
    const result = scanCryptoPii(tmp, noProbe);
    expect(result.semgrepAvailable).toBe(false);
    expect(result.piiInventory.map((f) => f.field)).toEqual(expect.arrayContaining(["email", "ssn"]));
    expect(result.passwordHashing.some((f) => f.finding_type === "bcrypt-cost-below-floor")).toBe(true);
    expect(result.jwt.some((f) => f.finding_type === "jwt-verify-missing-algorithms")).toBe(true);
    expect(result.clientKeyLeaks.length).toBeGreaterThan(0);
  });
});
