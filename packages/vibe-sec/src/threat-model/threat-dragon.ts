// Threat-Dragon-v2.5.0-compatible JSON sidecar (Decision 26; spec §4.9; checklist 4.1).
//
// The machine-readable channel: .vibe-sec/state/threat-model.json. Schema aligned
// with OWASP Threat Dragon's JSON (v2.5.0, schema lineage 1.0.2) so builders who
// want a GUI can one-click import and continue from there — no bespoke schema
// nothing else reads.
//
// Threat Dragon's top-level shape:
//   { version, summary: { title, owner, description }, detail: { contributors, diagrams[] } }
// Each diagram carries `cells[]`; each cell has `data.type` ∈
//   { tm.Actor (external entity), tm.Process, tm.Store, tm.Flow, tm.Boundary }
// and `data.threats[]` of { id, title, type (STRIDE category), severity,
// description, mitigation, status }.
//
// We emit a single diagram named for the app, mapping the DFD nodes/flows to
// cells and attaching the synthesized STRIDE threats to the relevant cells.
// Pure: returns the object; the caller JSON-stringifies + writes it.

import type {
  ThreatModelResult,
  DfdNode,
  Threat,
  StrideCategory,
} from "./synthesize.js";

/** Threat Dragon STRIDE type strings (their `data.threats[].type` vocabulary). */
const STRIDE_TD_TYPE: Record<StrideCategory, string> = {
  Spoofing: "Spoofing",
  Tampering: "Tampering",
  Repudiation: "Repudiation",
  "Information Disclosure": "Information disclosure",
  "Denial of Service": "Denial of service",
  "Elevation of Privilege": "Elevation of privilege",
};

/** DFD shape → Threat Dragon cell `data.type`. */
function tdCellType(node: DfdNode): string {
  switch (node.shape) {
    case "external-entity":
      return "tm.Actor";
    case "process":
      return "tm.Process";
    case "data-store":
      return "tm.Store";
    case "third-party":
      return "tm.Process"; // Threat Dragon models third-parties as out-of-scope processes
  }
}

interface TdThreat {
  id: string;
  title: string;
  type: string;
  status: string;
  severity: string;
  description: string;
  mitigation: string;
}

interface TdCell {
  position: { x: number; y: number };
  id: string;
  shape: string;
  data: {
    name: string;
    type: string;
    threats?: TdThreat[];
    outOfScope?: boolean;
    isTrustBoundary?: boolean;
    hasOpenThreats?: boolean;
  };
}

export interface ThreatDragonModel {
  version: string;
  summary: { title: string; owner: string; description: string };
  detail: {
    contributors: { name: string }[];
    diagrams: {
      id: number;
      title: string;
      diagramType: string;
      placeholder: string;
      thumbnail: string;
      version: string;
      cells: TdCell[];
    }[];
    diagramTop: number;
    reviewer: string;
    threatTop: number;
  };
}

/** Severity passthrough for Threat Dragon (it uses High/Medium/Low). */
function tdSeverity(t: Threat): string {
  // Map DREAD total (5..15) to a coarse band Threat Dragon understands.
  if (t.dread.total >= 12) return "High";
  if (t.dread.total >= 8) return "Medium";
  return "Low";
}

function tdThreatOf(t: Threat): TdThreat {
  return {
    id: t.id,
    title: t.title,
    type: STRIDE_TD_TYPE[t.category],
    status: t.realizedByFinding ? "Open" : "Open",
    severity: tdSeverity(t),
    description: t.description,
    mitigation: t.mitigation,
  };
}

/**
 * Build a Threat-Dragon-compatible model from the synthesized result. Threats are
 * attached to the cell their `element` names; element-less threats fall to the
 * backend process so nothing is dropped.
 */
export function toThreatDragon(
  result: ThreatModelResult,
  appName: string,
): ThreatDragonModel {
  // Map element label → list of threats for that cell.
  const threatsByElement = new Map<string, Threat[]>();
  for (const t of result.threats) {
    const arr = threatsByElement.get(t.element) ?? [];
    arr.push(t);
    threatsByElement.set(t.element, arr);
  }

  // Which node label corresponds to which threat `element` string. The synthesize
  // step uses human labels ("Backend / API process", "External user boundary");
  // match loosely so threats land on a sensible cell.
  const matchNodeForElement = (element: string): string | null => {
    const e = element.toLowerCase();
    if (e.includes("backend") || e.includes("api")) return "backend";
    if (e.includes("datastore") || e.includes("data store") || e.includes("db")) return "db";
    if (e.includes("admin")) return "admin";
    if (e.includes("external") || e.includes("user")) return "user";
    if (e.includes("service")) return "backend";
    return "backend";
  };

  const nodeThreats = new Map<string, Threat[]>();
  for (const [element, ts] of threatsByElement) {
    const nodeId = matchNodeForElement(element);
    if (!nodeId) continue;
    const arr = nodeThreats.get(nodeId) ?? [];
    arr.push(...ts);
    nodeThreats.set(nodeId, arr);
  }

  let x = 80;
  let y = 80;
  const cells: TdCell[] = [];

  // Boundary cells first (Threat Dragon renders trust boundaries as their own cells).
  for (const b of result.boundaries) {
    cells.push({
      position: { x, y },
      id: `boundary-${b.id}`,
      shape: "trust-boundary-box",
      data: {
        name: b.label,
        type: "tm.BoundaryBox",
        isTrustBoundary: true,
      },
    });
    y += 40;
  }

  // Node cells.
  for (const node of result.dfd.nodes) {
    const ts = nodeThreats.get(node.id) ?? [];
    cells.push({
      position: { x, y },
      id: node.id,
      shape: node.shape === "data-store" ? "store" : node.shape === "external-entity" ? "actor" : "process",
      data: {
        name: node.label,
        type: tdCellType(node),
        outOfScope: node.shape === "third-party",
        hasOpenThreats: ts.length > 0,
        threats: ts.map(tdThreatOf),
      },
    });
    x += 160;
    if (x > 800) {
      x = 80;
      y += 160;
    }
  }

  // Flow cells.
  for (const f of result.dfd.flows) {
    cells.push({
      position: { x: 0, y: 0 },
      id: `flow-${f.from}-${f.to}`,
      shape: "flow",
      data: {
        name: f.label,
        type: "tm.Flow",
      },
    });
  }

  return {
    version: "2.5.0",
    summary: {
      title: `${appName} — threat model`,
      owner: "Vibe Sec",
      description: `Generated by Vibe Sec at ${result.tier} tier. STRIDE${
        result.privacyThreats.length ? " + LINDDUN" : ""
      } synthesis over the audit inventory.`,
    },
    detail: {
      contributors: [{ name: "Vibe Sec" }],
      diagrams: [
        {
          id: 0,
          title: "Main data-flow diagram",
          diagramType: "STRIDE",
          placeholder: "New STRIDE diagram description",
          thumbnail: "./public/content/images/thumbnail.stride.jpg",
          version: "2.5.0",
          cells,
        },
      ],
      diagramTop: 1,
      reviewer: "",
      threatTop: result.threats.length,
    },
  };
}
