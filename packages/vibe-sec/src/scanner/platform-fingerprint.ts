// Vibe-coding platform fingerprint (Decision 10; spec §4.8, synthesis §3.8).
//
// Which AI built this app shapes the prior on what's wrong with it:
//   - v0 (Vercel): Next.js + shadcn/ui, no backend deps, UI-gated-but-backend-
//     unprotected. Prior → elevate "Server Action missing auth()" detection.
//   - Lovable: @supabase/* + supabase/migrations/. Prior → RLS inconsistent or
//     absent; elevate multi-tenant-isolation, every RLS-less table a Critical
//     candidate at Customer-facing-SaaS+.
//   - Bolt: Bolt deployment markers. Prior → auth is bimodal (well-scaffolded or
//     entirely absent); run both "is there auth" and "is it correct" with equal
//     weight.
//   - Cursor / Claude Code / Windsurf / Copilot (IDE-embedded): no distinctive
//     fingerprint — default to the 2026 mix (Next.js + Clerk/Supabase Auth +
//     inconsistent middleware).
//
// Priors elevate priority ordering + FP allocation; they do NOT change which
// concerns apply at a tier (the tier matrix stays authoritative for scope).

import fs from "node:fs";
import path from "node:path";

export type Platform = "v0" | "lovable" | "bolt" | "ide-embedded" | "unknown";

export interface FingerprintResult {
  platform: Platform;
  confidence: number;
  signals: string[];
  /** Detection priors this platform raises (consumed by the auth-model passes). */
  priors: {
    elevateServerActionAuth: boolean;
    elevateTenantIsolation: boolean;
    authIsBimodal: boolean;
  };
}

interface PkgJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function readPkg(projectRoot: string): PkgJson {
  try {
    return JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
  } catch {
    return {};
  }
}

function exists(projectRoot: string, rel: string): boolean {
  try {
    fs.accessSync(path.join(projectRoot, rel));
    return true;
  } catch {
    return false;
  }
}

function hasDep(pkg: PkgJson, re: RegExp): boolean {
  const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  return Object.keys(all).some((d) => re.test(d));
}

const NO_PRIORS = {
  elevateServerActionAuth: false,
  elevateTenantIsolation: false,
  authIsBimodal: false,
};

/** Fingerprint the vibe-coding platform from package.json + file-structure signals. */
export function fingerprintPlatform(projectRoot: string): FingerprintResult {
  const pkg = readPkg(projectRoot);
  const signals: string[] = [];

  const hasNext = hasDep(pkg, /^next$/);
  const hasShadcn = hasDep(pkg, /^(?:@radix-ui\/|class-variance-authority|tailwind-merge)/);
  const hasSupabase = hasDep(pkg, /^@supabase\//);
  const hasSupabaseMigrations = exists(projectRoot, "supabase/migrations");
  const backendDeps = hasDep(pkg, /^(?:express|fastify|@nestjs\/|hono|@trpc\/server|prisma|drizzle-orm|mongoose)/);

  // Lovable: Supabase + migrations dir is the strongest signal.
  if (hasSupabase && hasSupabaseMigrations) {
    signals.push("@supabase/* dependency", "supabase/migrations/ present");
    return {
      platform: "lovable",
      confidence: 0.85,
      signals,
      priors: { ...NO_PRIORS, elevateTenantIsolation: true },
    };
  }

  // v0: Next.js + shadcn/ui, no backend deps → UI-gated-but-backend-unprotected.
  if (hasNext && hasShadcn && !backendDeps) {
    signals.push("Next.js + shadcn/ui", "no backend framework deps");
    if (exists(projectRoot, "components.json")) signals.push("components.json (shadcn)");
    return {
      platform: "v0",
      confidence: 0.7,
      signals,
      priors: { ...NO_PRIORS, elevateServerActionAuth: true },
    };
  }

  // Bolt: deployment markers (bimodal auth prior).
  if (exists(projectRoot, ".bolt") || exists(projectRoot, "bolt.config.json")) {
    signals.push("Bolt deployment markers");
    return {
      platform: "bolt",
      confidence: 0.6,
      signals,
      priors: { ...NO_PRIORS, authIsBimodal: true },
    };
  }

  // IDE-embedded: a Next.js app with an auth lib but no distinctive platform mark.
  if (hasNext && hasDep(pkg, /^(?:@clerk\/|next-auth|@auth\/|@supabase\/auth-helpers)/)) {
    signals.push("Next.js + auth library, no platform fingerprint");
    return {
      platform: "ide-embedded",
      confidence: 0.4,
      signals,
      priors: NO_PRIORS,
    };
  }

  return { platform: "unknown", confidence: 0.2, signals, priors: NO_PRIORS };
}
