// Typosquat + dependency-confusion detection (synthesis §3.6).
//
// 454,648 malicious npm packages were published in 2025 — typosquat detection
// is load-bearing, not optional. The mechanic: Levenshtein distance ≤2 against
// an embedded top-N popular-package list. `expres` (distance 1 from `express`)
// is the canonical catch. Distance 0 is the package itself (not a squat).
//
// Dependency-confusion: a scoped private package (@yourco/x) whose unscoped or
// public-registry twin could be hijacked, plus the inverse — an internal-looking
// dependency that resolves from the public registry. v0.2 flags the structural
// risk (scoped deps without a configured private registry); the public-registry
// HEAD probe is a network op deferred behind an injectable checker.

import { readDeclaredDeps } from "./lockfile.js";

/** Levenshtein edit distance (iterative, two-row). */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}

// Embedded popular-package list — a representative top slice. The real top-500
// would be bundled as a data file; this covers the high-traffic squat targets.
export const POPULAR_PACKAGES: readonly string[] = [
  "express", "react", "react-dom", "lodash", "axios", "chalk", "commander",
  "debug", "dotenv", "moment", "next", "vue", "webpack", "typescript", "eslint",
  "prettier", "jest", "vitest", "mocha", "chai", "request", "body-parser",
  "cors", "mongoose", "sequelize", "prisma", "redis", "ioredis", "socket.io",
  "ws", "node-fetch", "uuid", "nanoid", "zod", "yup", "joi", "bcrypt",
  "jsonwebtoken", "passport", "winston", "pino", "fastify", "koa", "nest",
  "rxjs", "graphql", "apollo-server", "styled-components", "tailwindcss",
  "vite", "rollup", "esbuild", "babel", "@babel/core", "postcss", "sass",
  "react-router", "react-router-dom", "redux", "zustand", "immer", "classnames",
];

const POPULAR_SET = new Set(POPULAR_PACKAGES);

export interface TyposquatFinding {
  package: string;
  /** The popular package it's suspiciously close to. */
  resembles: string;
  distance: number;
  dev: boolean;
}

/**
 * Flag declared dependencies whose name is within Levenshtein ≤2 of a popular
 * package but is NOT that package (distance 0 means it IS the package).
 */
export function findTyposquats(projectRoot: string, maxDistance = 2): TyposquatFinding[] {
  const deps = readDeclaredDeps(projectRoot);
  const out: TyposquatFinding[] = [];
  for (const dep of deps) {
    if (POPULAR_SET.has(dep.name)) continue; // it's the real one
    let best: { resembles: string; distance: number } | null = null;
    for (const popular of POPULAR_PACKAGES) {
      // Skip wildly different lengths — Levenshtein can't be ≤2 across them.
      if (Math.abs(dep.name.length - popular.length) > maxDistance) continue;
      const d = levenshtein(dep.name, popular);
      if (d >= 1 && d <= maxDistance && (!best || d < best.distance)) {
        best = { resembles: popular, distance: d };
      }
    }
    if (best) {
      out.push({ package: dep.name, resembles: best.resembles, distance: best.distance, dev: dep.dev });
    }
  }
  return out;
}

export interface DepConfusionFinding {
  package: string;
  finding_type: "scoped-without-private-registry";
  detail: string;
}

/**
 * Structural dependency-confusion check: scoped packages (@scope/x) declared
 * without a configured private registry mean an attacker who publishes the same
 * @scope/x to the public registry at a higher version could get pulled in.
 * v0.2 flags the structural risk; the public-registry HEAD probe is deferred.
 */
export function findDepConfusion(projectRoot: string, hasPrivateRegistry: boolean): DepConfusionFinding[] {
  if (hasPrivateRegistry) return [];
  const deps = readDeclaredDeps(projectRoot);
  const scoped = deps.filter((d) => d.name.startsWith("@") && d.name.includes("/"));
  // Only flag scopes that look organization-internal (not well-known public
  // scopes like @babel, @types, @vue, @angular, @nestjs, @remix-run).
  const PUBLIC_SCOPES = new Set([
    "@babel", "@types", "@vue", "@angular", "@nestjs", "@remix-run",
    "@sveltejs", "@apollo", "@reduxjs", "@tanstack", "@emotion", "@mui",
    "@radix-ui", "@testing-library", "@vitest", "@eslint", "@typescript-eslint",
  ]);
  const out: DepConfusionFinding[] = [];
  for (const d of scoped) {
    const scope = d.name.split("/")[0]!;
    if (PUBLIC_SCOPES.has(scope)) continue;
    out.push({
      package: d.name,
      finding_type: "scoped-without-private-registry",
      detail: `${d.name} is scoped but no private registry is configured. An attacker publishing ${scope}/* to the public registry at a higher version could be pulled in. Pin the registry for this scope in .npmrc.`,
    });
  }
  return out;
}
