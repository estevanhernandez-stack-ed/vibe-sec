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
//
// Includes Firebase's canonical patterns (verifyAuthToken / verifyIdToken,
// getAuth().verifyIdToken, admin.auth(), getAuth(), checkAdminRole) plus inline
// Express Bearer-token extraction — these are *the* auth shape across Firebase
// Functions and hand-rolled Express admin servers, and missing them was the
// dominant false-positive driver (WSYATM dogfood, 2026-05-23).
const AUTH_MARKER_RE =
  /\b(?:auth\s*\(|getServerSession\s*\(|getUser\s*\(|requireAuth|requireUser|requireSession|ensureAuthenticated|isAuthenticated|currentUser\s*\(|getToken\s*\(|verifyToken|verifyAuthToken|verifyIdToken|checkAdminRole|checkManagerRole|verifyFirebaseToken|getAuth\s*\(|admin\.auth\s*\(|authMiddleware|withAuth|protect\b|clerkClient|@UseGuards|authorization|authHeader|Bearer\s)|(?:["'`]Bearer\s)/;
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
// v1 namespaced form (functions.https.onRequest) and the v2 destructured bare
// form (`const fn = onRequest(` after `require("firebase-functions/v2/https")`).
// The bare form is gated on a firebase-functions import to avoid matching an
// unrelated `onRequest(` in non-Firebase code (WSYATM uses the v2 bare style).
const FIREBASE_FN_RE = /\b(?:functions\.https\.|https\.)(onRequest|onCall)\s*\(/g;
const FIREBASE_FN_BARE_RE = /\b(onRequest|onCall)\s*\(/g;
const FIREBASE_IMPORT_RE = /firebase-functions/;

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
  // Collect every route-declaration offset first so the auth-detection window for
  // one route can extend to the START of the next route (or end-of-file) — the
  // inline Bearer/verifyIdToken check often sits well past the old fixed 400-char
  // window (WSYATM admin routes put the role gate ~25 lines into the handler body).
  EXPRESS_ROUTE_RE.lastIndex = 0;
  const expressMatches = [...text.matchAll(EXPRESS_ROUTE_RE)];
  // Hard cap so a single huge handler at end-of-file doesn't swallow the rest of
  // a monolith and over-attribute auth to a later, unrelated route.
  const MAX_HANDLER_WINDOW = 4000;
  for (let i = 0; i < expressMatches.length; i++) {
    const m = expressMatches[i]!;
    const routePath = m[3] ?? "/";
    const start = m.index ?? 0;
    const nextStart = i + 1 < expressMatches.length ? (expressMatches[i + 1]!.index ?? text.length) : text.length;
    // Window = up to the next route declaration, capped — this is the handler body.
    const windowEnd = Math.min(nextStart, start + MAX_HANDLER_WINDOW);
    const handlerBody = text.slice(start, windowEnd);
    routes.push({
      path: routePath,
      method: (m[1] ?? "get").toUpperCase(),
      framework: /\bfastify\b/.test(text) ? "fastify" : /\bhono\b/i.test(text) ? "hono" : "express",
      file: filePath,
      line: lineOf(text, start),
      authStatus: AUTH_MARKER_RE.test(handlerBody) ? "enforced" : "unknown",
      isAdmin: ADMIN_RE.test(routePath),
    });
  }

  // Firebase Functions. Match the v1 namespaced form; additionally match the v2
  // bare `onRequest(`/`onCall(` when the file imports firebase-functions. Auth is
  // scoped to the handler body (window to the next Firebase declaration) so a
  // file that imports verifyAuthToken for SOME handlers doesn't mark an unauthed
  // sibling handler as enforced (the quiz.js / generateQuiz shape).
  const usesFirebase = FIREBASE_IMPORT_RE.test(text);
  const fbRe = usesFirebase ? FIREBASE_FN_BARE_RE : FIREBASE_FN_RE;
  fbRe.lastIndex = 0;
  const fbMatches = [...text.matchAll(fbRe)];
  for (let fi = 0; fi < fbMatches.length; fi++) {
    const m = fbMatches[fi]!;
    const kind = m[1] ?? "onRequest";
    const start = m.index ?? 0;
    const nextStart = fi + 1 < fbMatches.length ? (fbMatches[fi + 1]!.index ?? text.length) : text.length;
    const handlerBody = text.slice(start, Math.min(nextStart, start + 4000));
    routes.push({
      path: filePath,
      method: kind === "onCall" ? "CALL" : "REQUEST",
      framework: "firebase-functions",
      file: filePath,
      line: lineOf(text, start),
      // onCall gets auth context for free; onRequest is raw and needs explicit
      // checks — scope the marker test to this handler's body.
      authStatus: kind === "onCall" ? "enforced" : (AUTH_MARKER_RE.test(handlerBody) ? "enforced" : "unknown"),
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
