// audit.json read/write (spec §1.4). The durable per-project audit record:
// last classification, score, freshness timestamp, and counts. Read by the
// router (state-aware next-step) and posture (cached summary).

import fs from "node:fs";
import path from "node:path";
import { type Concern, type Severity, type Tier } from "../types.js";
import { auditStatePath } from "./paths.js";

export interface AuditState {
  schema_version: 1;
  scanned_at: string;
  tier: Tier;
  tier_confidence: number;
  /** Final weighted score in [0,1] at scan time. */
  score: number;
  /** Whether the gate would pass at this tier. */
  gate_pass: boolean;
  counts: Record<Severity, number>;
  /** Total findings emitted (pre-dedup is fine; this is a summary). */
  findings_total: number;
  /** Tools that produced findings this run — for report crediting. */
  tools_used: string[];
  /**
   * Concerns whose applicability gate reported NOT APPLICABLE this run (GAP-09
   * — e.g. data-posture on an app with no persistence layer). Optional +
   * additive: absent on pre-0.9 records. The gate drops these from the score
   * denominator on cached runs — not-applicable is "nothing to evaluate," never
   * a hollow 1.0 pass.
   */
  not_applicable_concerns?: Concern[];
}

const FRESH_WINDOW_MS = 24 * 60 * 60 * 1000;

export function writeAuditState(
  projectRoot: string,
  state: AuditState,
  app?: string,
): void {
  const file = auditStatePath(projectRoot, app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(state, null, 2) + "\n", "utf8");
}

export function readAuditState(
  projectRoot: string,
  app?: string,
): AuditState | null {
  const file = auditStatePath(projectRoot, app);
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as AuditState;
  } catch {
    return null;
  }
}

/** True when audit.json exists and is ≤24h old. */
export function isAuditFresh(
  state: AuditState | null,
  now: number = Date.now(),
): boolean {
  if (!state) return false;
  const scanned = Date.parse(state.scanned_at);
  if (Number.isNaN(scanned)) return false;
  return now - scanned <= FRESH_WINDOW_MS;
}

export { FRESH_WINDOW_MS };
