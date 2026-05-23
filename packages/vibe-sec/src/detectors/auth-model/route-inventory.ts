// Route inventory per framework (spec §4.8 probe 1, synthesis §3.8).
//
// The foundation the rest of auth-model builds on: enumerate the project's HTTP
// surfaces and record, per route, whether auth is enforced and how. The
// authorization matrix (authz-matrix.ts) is a projection of this inventory.
//
// Frameworks covered (synthesis §3.8):
//   - Next.js App Router  — app/**/route.ts, app/**/page.tsx Server Actions
//   - Next.js Pages Router — pages/api/**.ts
//   - Express / Fastify / Hono — app.get/post(...), router.METHOD(...)
//   - Firebase Functions — onRequest / onCall
//   - tRPC — publicProcedure / protectedProcedure
//
// "Auth enforced" is a heuristic: an auth() / getServerSession() / getUser() /
// requireAuth() / middleware-attachment / protectedProcedure marker in or around
// the handler. Absence is recorded as `unknown` (not "absent") unless the route
// is clearly public-by-shape — the matrix renders the honest enforcement status.

import { lineOf } from "../source-walk.js";

export type RouteFramework =
  | "next-app-router"
  | "next-pages-router"
  | "next-server-action"
  | "express"
  | "fastify"
  | "hono"
  | "firebase-functions"
  | "trpc"
  | "unknown";

export type AuthStatus = "enforced" | "absent" | "unknown";

export interface Route {
  /** Path or identifier of the route (URL path when derivable, else handler id). */
  path: string;
  method: string;
  framework: RouteFramework;
  file: string;
  line: number;
  /** Whether auth is enforced at the handler/middleware level. */
  authStatus: AuthStatus;
  /** True when the path or handler reads as admin-scoped. */
  isAdmin: boolean;
}

// Auth-enforcement markers we look for in/around a handler.
const AUTH_MARKER_RE =
  /\b(?:auth\s*\(|getServerSession\s*\(|getUser\s*\(|requireAuth|requireUser|requireSession|ensureAuthenticated|isAuthenticated|currentUser\s*\(|getToken\s*\(|verifyToken|authMiddleware|withAuth|protect\b|clerkClient|@UseGuards)/;
const ADMIN_RE = /\badmin\b/i;

// ─── Next.js App Router route handlers (app/**/route.ts) ──────────────────
const NEXT_HANDLER_RE = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
// Next.js Server Actions: a "use server" function (file-level or inline).
const SERVER_ACTION_FILE_RE = /^["']use server["']/m;
const SERVER_ACTION_FN_RE = /\b(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*["']use server["']/g;

// ─── Express / Fastify / Hono ─────────────────────────────────────────────
const EXPRESS_ROUTE_RE =
  /\b(?:app|router|server|fastify|api)\s*\.\s*(get|post|put|patch|delete|all|options|head)\s*\(\s*(["'`])([^"'`]+)\2/g;

// ─── Firebase Functions ───────────────────────────────────────────────────
const FIREBASE_FN_RE = /\b(?:functions\.https\.|https\.)(onRequest|onCall)\s*\(/g;

// ─── tRPC procedures ──────────────────────────────────────────────────────
const TRPC_PROC_RE = /\b(\w+)\s*:\s*(publicProcedure|protectedProcedure|authedProcedure|adminProcedure)\b/g;

/** Derive an App-Router URL path from app/foo/bar/route.ts. */
function appRouterPath(filePath: string): string {
  const m = filePath.match(/(?:^|\/)app\/(.+?)\/route\.[mc]?[jt]sx?$/);
  if (!m) return filePath;
  return "/" + (m[1] ?? "").replace(/\(.+?\)\//g, "").replace(/\[(\w+)\]/g, ":$1");
}

/** Derive a Pages-Router API path from pages/api/foo.ts. */
function pagesApiPath(filePath: string): string {
  const m = filePath.match(/(?:^|\/)pages\/api\/(.+?)\.[mc]?[jt]sx?$/);
  if (!m) return filePath;
  return "/api/" + (m[1] ?? "").replace(/\/index$/, "").replace(/\[(\w+)\]/g, ":$1");
}

function authStatusFor(scope: string): AuthStatus {
  return AUTH_MARKER_RE.test(scope) ? "enforced" : "unknown";
}

/** Scan one source file for routes across the supported frameworks. */
export function scanRoutes(text: string, filePath: string): Route[] {
  const routes: Route[] = [];
  const fileHasAuth = AUTH_MARKER_RE.test(text);

  // Next.js App Router handlers.
  if (/(?:^|\/)app\/.*\/route\.[mc]?[jt]sx?$/.test(filePath)) {
    const urlPath = appRouterPath(filePath);
    NEXT_HANDLER_RE.lastIndex = 0;
    for (const m of text.matchAll(NEXT_HANDLER_RE)) {
      routes.push({
        path: urlPath,
        method: m[1] ?? "GET",
        framework: "next-app-router",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        authStatus: authStatusFor(text),
        isAdmin: ADMIN_RE.test(urlPath) || ADMIN_RE.test(filePath),
      });
    }
  }

  // Next.js Pages Router API routes.
  if (/(?:^|\/)pages\/api\/.*\.[mc]?[jt]sx?$/.test(filePath)) {
    const urlPath = pagesApiPath(filePath);
    routes.push({
      path: urlPath,
      method: "ALL",
      framework: "next-pages-router",
      file: filePath,
      line: 1,
      authStatus: fileHasAuth ? "enforced" : "unknown",
      isAdmin: ADMIN_RE.test(urlPath) || ADMIN_RE.test(filePath),
    });
  }

  // Next.js Server Actions (the v0 UI-gated-backend-unprotected surface).
  if (SERVER_ACTION_FILE_RE.test(text) || SERVER_ACTION_FN_RE.test(text)) {
    SERVER_ACTION_FN_RE.lastIndex = 0;
    const fileLevel = SERVER_ACTION_FILE_RE.test(text);
    if (fileLevel) {
      // Whole-file server actions — each exported function is an action.
      const FN_RE = /\bexport\s+(?:async\s+)?function\s+(\w+)/g;
      for (const m of text.matchAll(FN_RE)) {
        routes.push({
          path: m[1] ?? "action",
          method: "ACTION",
          framework: "next-server-action",
          file: filePath,
          line: lineOf(text, m.index ?? 0),
          authStatus: fileHasAuth ? "enforced" : "unknown",
          isAdmin: ADMIN_RE.test(m[1] ?? ""),
        });
      }
    }
    for (const m of text.matchAll(SERVER_ACTION_FN_RE)) {
      routes.push({
        path: m[1] ?? "action",
        method: "ACTION",
        framework: "next-server-action",
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        authStatus: fileHasAuth ? "enforced" : "unknown",
        isAdmin: ADMIN_RE.test(m[1] ?? ""),
      });
    }
  }

  // Express / Fastify / Hono.
  EXPRESS_ROUTE_RE.lastIndex = 0;
  for (const m of text.matchAll(EXPRESS_ROUTE_RE)) {
    const routePath = m[3] ?? "/";
    // Auth status from the handler args span (auth middleware listed inline?).
    const after = text.slice(m.index ?? 0, (m.index ?? 0) + 400);
    routes.push({
      path: routePath,
      method: (m[1] ?? "get").toUpperCase(),
      framework: /\bfastify\b/.test(text) ? "fastify" : /\bhono\b/i.test(text) ? "hono" : "express",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      authStatus: AUTH_MARKER_RE.test(after) ? "enforced" : "unknown",
      isAdmin: ADMIN_RE.test(routePath),
    });
  }

  // Firebase Functions.
  FIREBASE_FN_RE.lastIndex = 0;
  for (const m of text.matchAll(FIREBASE_FN_RE)) {
    const kind = m[1] ?? "onRequest";
    routes.push({
      path: filePath,
      method: kind === "onCall" ? "CALL" : "REQUEST",
      framework: "firebase-functions",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      // onCall gets auth context for free; onRequest is raw and needs explicit checks.
      authStatus: kind === "onCall" ? "enforced" : authStatusFor(text),
      isAdmin: ADMIN_RE.test(filePath),
    });
  }

  // tRPC procedures.
  TRPC_PROC_RE.lastIndex = 0;
  for (const m of text.matchAll(TRPC_PROC_RE)) {
    const proc = m[2] ?? "publicProcedure";
    routes.push({
      path: m[1] ?? "procedure",
      method: "TRPC",
      framework: "trpc",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      authStatus: proc === "publicProcedure" ? "absent" : "enforced",
      isAdmin: proc === "adminProcedure" || ADMIN_RE.test(m[1] ?? ""),
    });
  }

  return routes;
}
