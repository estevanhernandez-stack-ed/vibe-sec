import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanRoutes } from "./route-inventory.js";
import { auditAdminRoutes } from "./admin-audit.js";
import {
  scanSupabaseMigration,
  scanFirestoreTenant,
  scanQueryTenantFilter,
} from "./tenant-isolation.js";
import { scanIdor } from "./idor.js";
import { scanSession, classifySessionLibrary } from "./session.js";
import { scanRoleHardcoding, rollupRoleHardcoding } from "./role-hardcoding.js";
import { buildAuthzMatrix, renderMatrixMarkdown } from "./authz-matrix.js";
import { fingerprintPlatform } from "../../scanner/platform-fingerprint.js";
import { scanAuthModel } from "./index.js";
import { tenantToFinding, idorToFinding, cve202529927ToFinding } from "../to-findings.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-auth-"));
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

// ─── Probe 1: route inventory ──────────────────────────────────────────────
describe("route inventory", () => {
  it("inventories a Next.js App Router handler and marks auth unknown when absent", () => {
    const routes = scanRoutes(
      `export async function GET(req) { return Response.json({}); }`,
      "app/api/users/route.ts",
    );
    expect(routes[0]!.framework).toBe("next-app-router");
    expect(routes[0]!.path).toBe("/api/users");
    expect(routes[0]!.authStatus).toBe("unknown");
  });

  it("marks a route enforced when an auth marker is present", () => {
    const routes = scanRoutes(
      `export async function GET(req) { const s = await getServerSession(); }`,
      "app/api/me/route.ts",
    );
    expect(routes[0]!.authStatus).toBe("enforced");
  });

  it("classifies a tRPC publicProcedure as auth absent", () => {
    const routes = scanRoutes(`const r = { list: publicProcedure.query(fn) };`, "server/router.ts");
    expect(routes[0]!.framework).toBe("trpc");
    expect(routes[0]!.authStatus).toBe("absent");
  });

  it("inventories an Express route", () => {
    const routes = scanRoutes(`app.post("/api/login", handler);`, "server.ts");
    expect(routes[0]!.framework).toBe("express");
    expect(routes[0]!.method).toBe("POST");
    expect(routes[0]!.path).toBe("/api/login");
  });
});

// ─── Probe 2: admin audit ───────────────────────────────────────────────────
describe("admin audit", () => {
  it("flags an unauthenticated admin route as Critical", () => {
    const routes = scanRoutes(`export async function GET(req) {}`, "app/admin/users/route.ts");
    const ft = new Map([["app/admin/users/route.ts", `export async function GET(req) {}`]]);
    const findings = auditAdminRoutes(routes, ft);
    expect(findings[0]!.finding_type).toBe("admin-route-no-auth");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("flags an authenticated admin route with no role gate as High", () => {
    const src = `export async function GET(req) { const s = await getServerSession(); }`;
    const routes = scanRoutes(src, "app/admin/route.ts");
    const ft = new Map([["app/admin/route.ts", src]]);
    const findings = auditAdminRoutes(routes, ft);
    expect(findings[0]!.finding_type).toBe("admin-route-no-role-gate");
    expect(findings[0]!.severity).toBe("high");
  });
});

// ─── Regression: Firebase / inline-Bearer auth recognition (WSYATM dogfood) ──
// The dominant FP driver: Express admin routes with an INLINE Bearer-token check
// + auth.verifyIdToken were flagged "no auth — anyone can reach it," because the
// detector didn't know Firebase's canonical auth shape and only looked ~400 chars
// past the route declaration. These mirror WSYATM's Backend/src/index.js shape.
describe("Firebase/inline-Bearer auth recognition (regression)", () => {
  // An admin route whose Bearer check + verifyIdToken + role gate sit ~25 lines
  // deep in the handler body (past the old 400-char window).
  const wsyatmAdminRoute = `
app.get('/api/admin/stats', strictLimiter, async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Unauthorized. Please provide a valid token." });
  }

  const idToken = authHeader.split('Bearer ')[1];

  try {
    const decodedToken = await auth.verifyIdToken(idToken);
    const uid = decodedToken.uid;

    // Check if user is an admin
    const userDocRef = db.collection("users").doc(uid);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found." });
    }

    const userData = userDoc.data();
    if (userData.role !== 'admin') {
      return res.status(403).json({ error: "Access denied. Admin role required." });
    }

    const usersSnapshot = await db.collection("users").count().get();
    res.status(200).json({ users: usersSnapshot.data().count });
  } catch (error) {
    res.status(500).json({ error: "Internal" });
  }
});
`;

  it("marks an inline-Bearer + verifyIdToken Express admin route as ENFORCED, not absent", () => {
    const routes = scanRoutes(wsyatmAdminRoute, "Backend/src/index.js");
    const adminRoute = routes.find((r) => r.path.includes("/admin/"))!;
    expect(adminRoute).toBeTruthy();
    expect(adminRoute.isAdmin).toBe(true);
    expect(adminRoute.authStatus).toBe("enforced"); // was "unknown" → 5 FPs
  });

  it("does NOT raise admin-route-no-auth on the inline-Bearer admin route", () => {
    const routes = scanRoutes(wsyatmAdminRoute, "Backend/src/index.js");
    const ft = new Map([["Backend/src/index.js", wsyatmAdminRoute]]);
    const findings = auditAdminRoutes(routes, ft);
    // The role gate (role !== 'admin') is present too → no role-gate finding either.
    expect(findings.some((f) => f.finding_type === "admin-route-no-auth")).toBe(false);
    expect(findings.some((f) => f.finding_type === "admin-route-no-role-gate")).toBe(false);
  });

  it("recognizes a Firebase v2 bare-onRequest verifyAuthToken + checkAdminRole handler", () => {
    const src = `
const {onRequest} = require("firebase-functions/v2/https");
const { verifyAuthToken, checkAdminRole } = require("../utils/helpers");

const adminThing = onRequest({cors: true}, async (req, res) => {
  const decodedToken = await verifyAuthToken(req);
  const uid = decodedToken.uid;
  await checkAdminRole(uid);
  return res.json({ ok: true });
});`;
    const routes = scanRoutes(src, "functions/src/admin/userManagement.js");
    // v2 bare onRequest (gated on firebase-functions import) → inventoried.
    const fbRoute = routes.find((r) => r.framework === "firebase-functions")!;
    expect(fbRoute).toBeTruthy();
    expect(fbRoute.authStatus).toBe("enforced");
  });

  it("scopes Firebase v2 auth per handler — an unauthed sibling stays unknown", () => {
    // quiz.js shape: imports verifyAuthToken (used by a later handler) but the
    // first onRequest handler has no auth in its OWN body.
    const src = `
const {onRequest} = require("firebase-functions/v2/https");
const { verifyAuthToken, geminiApiKey } = require("../utils/helpers");

const generateQuiz = onRequest({cors: true}, async (req, res) => {
  const {movieTitle} = req.body;
  const result = await model.generateContent(prompt);
  return res.json(result);
});

const getHistory = onRequest({cors: true}, async (req, res) => {
  const decodedToken = await verifyAuthToken(req);
  return res.json({ history: [] });
});`;
    const routes = scanRoutes(src, "functions/src/games/quiz.js").filter(
      (r) => r.framework === "firebase-functions",
    );
    expect(routes.length).toBe(2);
    // generateQuiz handler has NO auth in its body → unknown (not masked by the
    // file-level verifyAuthToken import used by getHistory).
    expect(routes[0]!.authStatus).toBe("unknown");
    expect(routes[1]!.authStatus).toBe("enforced");
  });

  it("STILL flags a genuinely unprotected Express admin route as Critical", () => {
    const open = `
app.delete('/api/admin/wipe', async (req, res) => {
  await db.collection("everything").drop();
  return res.json({ wiped: true });
});`;
    const routes = scanRoutes(open, "Backend/src/index.js");
    const ft = new Map([["Backend/src/index.js", open]]);
    const findings = auditAdminRoutes(routes, ft);
    expect(findings.some((f) => f.finding_type === "admin-route-no-auth")).toBe(true);
    expect(findings.find((f) => f.finding_type === "admin-route-no-auth")!.severity).toBe("critical");
  });
});

// ─── Probe 3: tenant isolation (the signature finding) ─────────────────────
describe("tenant isolation", () => {
  it("flags a Supabase table created without RLS as Critical", () => {
    const sql = `create table public.documents (id uuid primary key, owner_id uuid);`;
    const findings = scanSupabaseMigration(sql, "supabase/migrations/001.sql");
    const f = findings.find((x) => x.finding_type === "supabase-table-without-rls");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("critical");
  });

  it("does NOT flag a table that enables RLS", () => {
    const sql = `
      create table public.documents (id uuid primary key);
      alter table public.documents enable row level security;
    `;
    const findings = scanSupabaseMigration(sql, "supabase/migrations/001.sql");
    expect(findings.some((x) => x.finding_type === "supabase-table-without-rls")).toBe(false);
  });

  it("flags a using(true) RLS policy as Critical", () => {
    const sql = `create policy p on docs for select using (true);`;
    const findings = scanSupabaseMigration(sql, "001.sql");
    expect(findings.some((x) => x.finding_type === "supabase-rls-policy-true")).toBe(true);
  });

  it("flags a Firestore if-true rule", () => {
    const rules = `match /docs/{id} { allow read, write: if true; }`;
    const findings = scanFirestoreTenant(rules, "firestore.rules");
    expect(findings[0]!.finding_type).toBe("firestore-permissive-rule");
  });

  it("flags a tenant-scoped findMany with no tenant filter (only when tenantScoped)", () => {
    const src = `const docs = await prisma.document.findMany({ orderBy: { createdAt: 'desc' } });`;
    expect(scanQueryTenantFilter(src, "api.ts", false).length).toBe(0);
    const findings = scanQueryTenantFilter(src, "api.ts", true);
    expect(findings.some((x) => x.finding_type === "query-missing-tenant-filter")).toBe(true);
  });

  it("Supabase-without-RLS maps to Critical at Customer-facing, High below", () => {
    const sql = `create table public.docs (id uuid);`;
    const t = scanSupabaseMigration(sql, "001.sql")[0]!;
    expect(tenantToFinding(t, "customer-facing-saas").severity_tier_adjusted).toBe("critical");
    expect(tenantToFinding(t, "public-facing").severity_tier_adjusted).toBe("high");
  });
});

// ─── Probe 4: IDOR (Decision 18 gate) ──────────────────────────────────────
describe("IDOR — gated ≥0.9 confidence + Public-facing+", () => {
  const idorSrc = `
    export async function GET(req) {
      const id = req.params.id;
      return prisma.invoice.findUnique({ where: { id } });
    }
  `;

  it("scores high confidence when no ownership filter and no centralized authz", () => {
    const findings = scanIdor(idorSrc, "app/api/invoice/route.ts", false);
    expect(findings[0]!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("only fires as a Band-1 finding at Public-facing+ AND ≥0.9", () => {
    const i = scanIdor(idorSrc, "app/api/invoice/route.ts", false)[0]!;
    expect(idorToFinding(i, "internal")).toBeNull(); // tier below Public-facing
    expect(idorToFinding(i, "public-facing")).not.toBeNull();
  });

  it("drops to below-0.9 (Band 2) when an ownership filter is present", () => {
    const safe = `
      export async function GET(req) {
        const id = req.params.id;
        return prisma.invoice.findUnique({ where: { id, userId: session.user.id } });
      }
    `;
    const findings = scanIdor(safe, "app/api/invoice/route.ts", false);
    if (findings.length) {
      expect(findings[0]!.confidence).toBeLessThan(0.9);
      expect(idorToFinding(findings[0]!, "public-facing")).toBeNull();
    }
  });
});

// ─── Probe 5: session ──────────────────────────────────────────────────────
describe("session classification", () => {
  it("flags JWT in localStorage as High", () => {
    const findings = scanSession(`localStorage.setItem("authToken", jwt);`, "auth.ts");
    expect(findings[0]!.finding_type).toBe("jwt-in-web-storage");
    expect(findings[0]!.severity).toBe("high");
  });

  it("classifies the session library", () => {
    expect(classifySessionLibrary(`import { getServerSession } from "next-auth";`)).toBe("next-auth");
    expect(classifySessionLibrary(`import { useAuth } from "@clerk/nextjs";`)).toBe("clerk");
  });
});

// ─── Probe 6: role hardcoding ──────────────────────────────────────────────
describe("role hardcoding", () => {
  it("rolls up to an architectural finding at 3+ files", () => {
    const sites = [
      ...scanRoleHardcoding(`if (user.role === "admin") {}`, "a.ts"),
      ...scanRoleHardcoding(`if (session.user.role === "admin") {}`, "b.ts"),
      ...scanRoleHardcoding(`const ok = role === "editor";`, "c.ts"),
    ];
    const rollup = rollupRoleHardcoding(sites);
    expect(rollup).not.toBeNull();
    expect(rollup!.fileCount).toBe(3);
  });

  it("does NOT roll up below threshold", () => {
    const sites = scanRoleHardcoding(`if (role === "admin") {}`, "a.ts");
    expect(rollupRoleHardcoding(sites)).toBeNull();
  });
});

// ─── The authorization matrix (the signature artifact) ─────────────────────
describe("authorization matrix", () => {
  it("renders rows = routes × columns = authz dimensions", () => {
    const routes = [
      ...scanRoutes(`export async function GET(req) {}`, "app/admin/route.ts"),
      ...scanRoutes(`export async function POST(req) { await auth(); }`, "app/api/me/route.ts"),
    ];
    const fileText = new Map([
      ["app/admin/route.ts", `export async function GET(req) {}`],
      ["app/api/me/route.ts", `export async function POST(req) { await auth(); const x = session.user.role; }`],
    ]);
    const matrix = buildAuthzMatrix({ routes, fileText, rlsApplicable: false });
    expect(matrix.rows.length).toBe(2);
    expect(matrix.dimensions).toEqual([
      "auth-required",
      "role-gated",
      "ownership-enforced",
      "rls-applicable",
    ]);
    // The unauthenticated admin route shows auth-required absent/unknown.
    const adminRow = matrix.rows.find((r) => r.route.includes("admin"))!;
    expect(adminRow.cells["auth-required"]).toBe("unknown");
    // rls-applicable is n/a when the stack has no RLS.
    expect(adminRow.cells["rls-applicable"]).toBe("n/a");

    const md = renderMatrixMarkdown(matrix);
    expect(md).toContain("| Route | Method |");
    expect(md).toContain("auth-required");
  });
});

// ─── Platform fingerprint ──────────────────────────────────────────────────
describe("platform fingerprint", () => {
  it("fingerprints v0 (Next + shadcn, no backend) and elevates Server-Action auth", () => {
    write(
      "package.json",
      JSON.stringify({
        dependencies: { next: "15.0.0", "@radix-ui/react-dialog": "1.0.0", "class-variance-authority": "0.7.0" },
      }),
    );
    const fp = fingerprintPlatform(tmp);
    expect(fp.platform).toBe("v0");
    expect(fp.priors.elevateServerActionAuth).toBe(true);
  });

  it("fingerprints Lovable (Supabase + migrations) and elevates tenant isolation", () => {
    write("package.json", JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }));
    write("supabase/migrations/001.sql", "create table x (id int);");
    const fp = fingerprintPlatform(tmp);
    expect(fp.platform).toBe("lovable");
    expect(fp.priors.elevateTenantIsolation).toBe(true);
  });
});

// ─── CVE-2025-29927 joint finding (reuse config-posture rule) ───────────────
describe("CVE-2025-29927 joint finding", () => {
  it("fires once with primary=auth-model + cross-concern secondaries", () => {
    const c = { vulnerable: true, detectedVersion: "14.2.0", recommendedFix: "14.2.25", detail: "vulnerable" };
    const f = cve202529927ToFinding(c, "public-facing")!;
    expect(f.primary_concern).toBe("auth-model");
    expect(f.secondary_concerns).toEqual(
      expect.arrayContaining(["dependency-cve", "config-posture", "owasp-survey"]),
    );
    expect(f.severity_tier_adjusted).toBe("critical");
  });

  it("returns null when not vulnerable", () => {
    expect(
      cve202529927ToFinding(
        { vulnerable: false, detectedVersion: null, recommendedFix: null, detail: null },
        "public-facing",
      ),
    ).toBeNull();
  });
});

// ─── Orchestrator integration ──────────────────────────────────────────────
describe("auth-model orchestrator (in-house, Semgrep absent)", () => {
  it("assembles all probes + matrix over a Lovable project", () => {
    write("package.json", JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0", next: "14.2.0" } }));
    write("supabase/migrations/001.sql", `create table public.docs (id uuid, owner_id uuid);`);
    write("app/admin/users/route.ts", `export async function GET(req) {}`);
    write("app/api/me/route.ts", `export async function GET(req) { await getServerSession(); }`);
    const result = scanAuthModel(tmp, noProbe);
    expect(result.semgrepAvailable).toBe(false);
    expect(result.platform.platform).toBe("lovable");
    expect(result.routes.length).toBeGreaterThanOrEqual(2);
    expect(result.tenant.some((t) => t.finding_type === "supabase-table-without-rls")).toBe(true);
    expect(result.admin.some((a) => a.finding_type === "admin-route-no-auth")).toBe(true);
    expect(result.matrix.rows.length).toBeGreaterThanOrEqual(2);
    // next 14.2.0 is vulnerable to CVE-2025-29927.
    expect(result.cve202529927.vulnerable).toBe(true);
  });
});
