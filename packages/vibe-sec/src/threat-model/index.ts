// Threat-model orchestrator + public surface (concern #9; checklist 4.1).
//
// The sink node's runtime entry. It assembles the inventory the synthesizer
// needs — route inventory (auth-model #8), PII fields (crypto-pii #4),
// integrations (Vibe Test detected_stack), and the deduped findings.jsonl — then
// synthesizes, renders the Mermaid markdown, builds the Threat Dragon sidecar,
// and writes both channels:
//   - docs/vibe-sec/threat-model.md           (Mermaid-in-markdown primary)
//   - .vibe-sec/state/threat-model.json       (Threat-Dragon-v2.5.0 sidecar)
//
// Tier applicability is enforced upstream: the :audit SKILL must NOT auto-run
// this at Internal (Conflict 2 = C — opt-in only). At Prototype the synthesizer
// returns a stub and we still write the stub markdown (no JSON sidecar).

import fs from "node:fs";
import path from "node:path";
import { type Tier } from "../types.js";
import { readFindingsDeduped } from "../state/findings.js";
import { readVibeTestHandshake } from "../composition/vibe-test.js";
import { projectDocsDir, threatModelStatePath } from "../state/paths.js";
import { scanAuthModel } from "../detectors/auth-model/index.js";
import { scanCryptoPii } from "../detectors/crypto-pii/index.js";
import { readDeclaredDeps } from "../detectors/supply-chain/lockfile.js";
import {
  synthesizeThreatModel,
  type ThreatModelInput,
  type ThreatModelResult,
} from "./synthesize.js";
import { renderThreatModelMarkdown } from "./mermaid.js";
import { toThreatDragon, type ThreatDragonModel } from "./threat-dragon.js";

// Known third-party SDK fingerprints → friendly names, for the integrations list.
const INTEGRATION_FINGERPRINTS: { re: RegExp; name: string }[] = [
  { re: /^stripe$/i, name: "Stripe" },
  { re: /^@stripe\//i, name: "Stripe" },
  { re: /^openai$/i, name: "OpenAI" },
  { re: /^@anthropic-ai\//i, name: "Anthropic" },
  { re: /^@supabase\//i, name: "Supabase" },
  { re: /^firebase$|^firebase-admin$/i, name: "Firebase" },
  { re: /^@clerk\//i, name: "Clerk" },
  { re: /^next-auth$|^@auth\//i, name: "Auth provider" },
  { re: /^twilio$/i, name: "Twilio" },
  { re: /^@sendgrid\//i, name: "SendGrid" },
  { re: /^resend$/i, name: "Resend" },
  { re: /^@aws-sdk\//i, name: "AWS" },
  { re: /^mongodb$|^mongoose$/i, name: "MongoDB" },
  { re: /^@prisma\/client$/i, name: "Database (Prisma)" },
];

/** Map declared deps + Vibe Test stack to a deduped integrations list. */
function gatherIntegrations(projectRoot: string, fromHandshake: string[]): string[] {
  const found = new Set<string>(fromHandshake);
  for (const dep of readDeclaredDeps(projectRoot)) {
    for (const fp of INTEGRATION_FINGERPRINTS) {
      if (fp.re.test(dep.name)) found.add(fp.name);
    }
  }
  return [...found];
}

export interface ThreatModelRunOptions {
  /** Tier — usually inherited from the audit; required (the sink consumes it). */
  tier: Tier;
  /** App display name; defaults to the project dir basename. */
  appName?: string;
  /** Monorepo app scope, mirrored to state paths. */
  app?: string;
  /** Whether to actually write the artifacts (false = dry-run, returns result only). */
  write?: boolean;
}

export interface ThreatModelRunResult {
  result: ThreatModelResult;
  markdown: string;
  sidecar: ThreatDragonModel | null;
  /** Paths written (empty when write === false or the run is a Prototype stub). */
  writtenPaths: string[];
}

/**
 * Assemble the inventory + synthesize + render + (optionally) write both channels.
 * Pure assembly over the real detectors — does not fabricate findings.
 */
export function runThreatModel(
  projectRoot: string,
  opts: ThreatModelRunOptions,
): ThreatModelRunResult {
  const appName = opts.appName ?? path.basename(path.resolve(projectRoot));
  const handshake = readVibeTestHandshake(projectRoot);

  // Route inventory (deepest input) + PII fields + integrations + findings.
  const auth = scanAuthModel(projectRoot);
  const crypto = scanCryptoPii(projectRoot);
  const integrations = gatherIntegrations(projectRoot, handshake.detectedStack.integrations);
  const findings = readFindingsDeduped(projectRoot, opts.app);

  const multiTenant =
    handshake.modifiers.includes("multi-tenant") ||
    auth.tenant.length > 0 ||
    handshake.detectedStack.auth.some((a) => /supabase|firebase/i.test(a));

  const input: ThreatModelInput = {
    tier: opts.tier,
    appName,
    routes: auth.routes,
    piiFields: crypto.piiInventory,
    integrations,
    findings,
    totalRoutesDetected: auth.routes.length,
    coveredEndpoints: handshake.endpointsWithBehavioralTests,
    multiTenant,
  };

  const result = synthesizeThreatModel(input);
  const markdown = renderThreatModelMarkdown(result, {
    appName,
    completenessBanner: result.completeness.banner,
  });
  const sidecar = result.isStub ? null : toThreatDragon(result, appName);

  const writtenPaths: string[] = [];
  if (opts.write) {
    // Primary markdown.
    const docsDir = projectDocsDir(projectRoot);
    fs.mkdirSync(docsDir, { recursive: true });
    const mdPath = path.join(docsDir, "threat-model.md");
    fs.writeFileSync(mdPath, markdown, "utf8");
    writtenPaths.push(mdPath);

    // JSON sidecar (only when not a Prototype stub).
    if (sidecar) {
      const jsonPath = threatModelStatePath(projectRoot, opts.app);
      fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
      fs.writeFileSync(jsonPath, JSON.stringify(sidecar, null, 2) + "\n", "utf8");
      writtenPaths.push(jsonPath);
    }
  }

  return { result, markdown, sidecar, writtenPaths };
}

// Re-export the synthesis + render surface.
export {
  synthesizeThreatModel,
  checkCompleteness,
  buildDfd,
  resetThreatIds,
  threatModelInAudit,
  STRIDE_CATEGORIES,
  type ThreatModelInput,
  type ThreatModelResult,
  type Threat,
  type PrivacyThreat,
  type AttackTree,
  type Dfd,
  type DfdNode,
  type DfdShape,
  type DfdFlow,
  type TrustBoundary,
  type StrideCategory,
  type LinddunCategory,
  type DreadScore,
  type DreadLevel,
  type CompletenessCheck,
} from "./synthesize.js";
export {
  renderThreatModelMarkdown,
  renderMermaidDfd,
  type MarkdownThreatModelOptions,
} from "./mermaid.js";
export { toThreatDragon, type ThreatDragonModel } from "./threat-dragon.js";
