// Mermaid-in-markdown renderer for the threat model (spec §4.9; checklist 4.1).
//
// The primary channel: docs/vibe-sec/threat-model.md. Builder-readable markdown
// with an embedded Mermaid DFD. Mermaid is the right call — native rendering on
// GitHub/GitLab/Obsidian, diff-friendly in git.
//
// Locked Mermaid shape convention (synthesis §3.9 — documented here so successive
// runs produce diff-friendly diagrams):
//   stadiums  (`id([label])`)  = external entities
//   rectangles(`id[label]`)    = processes
//   cylinders (`id[(label)]`)  = data stores
//   hexagons  (`id{{label}}`)  = third-parties
//   subgraphs                  = trust boundaries
//
// Pure: returns the markdown string; the caller writes it to disk.

import { type Tier } from "../types.js";
import { TIER_ASVS_LABEL } from "../scoring/weighted-score.js";
import type {
  Dfd,
  DfdNode,
  ThreatModelResult,
  Threat,
  AttackTree,
} from "./synthesize.js";

/** Render one DFD node with its shape-specific Mermaid syntax (the locked convention). */
function nodeShape(node: DfdNode): string {
  const label = node.label.replace(/["[\]{}()]/g, "");
  switch (node.shape) {
    case "external-entity":
      return `${node.id}(["${label}"])`; // stadium
    case "process":
      return `${node.id}["${label}"]`; // rectangle
    case "data-store":
      return `${node.id}[("${label}")]`; // cylinder
    case "third-party":
      return `${node.id}{{"${label}"}}`; // hexagon
  }
}

/** Render the DFD as a Mermaid `flowchart` with subgraphs for trust boundaries. */
export function renderMermaidDfd(dfd: Dfd): string {
  const lines: string[] = ["```mermaid", "flowchart TD"];

  // Group nodes by boundary; render each boundary as a subgraph.
  const byBoundary = new Map<string | null, DfdNode[]>();
  for (const n of dfd.nodes) {
    const arr = byBoundary.get(n.boundary) ?? [];
    arr.push(n);
    byBoundary.set(n.boundary, arr);
  }

  for (const b of dfd.boundaries) {
    const members = byBoundary.get(b.id) ?? [];
    if (members.length === 0) continue;
    lines.push(`  subgraph ${b.id}["${b.label}"]`);
    for (const n of members) lines.push(`    ${nodeShape(n)}`);
    lines.push("  end");
  }

  // Unboundaried nodes (processes, stores) at top level.
  for (const n of byBoundary.get(null) ?? []) {
    lines.push(`  ${nodeShape(n)}`);
  }

  // Flows.
  for (const f of dfd.flows) {
    const label = f.label.replace(/[|]/g, "");
    lines.push(`  ${f.from} -->|${label}| ${f.to}`);
  }

  lines.push("```");
  return lines.join("\n");
}

function dreadCell(t: Threat): string {
  const d = t.dread;
  return `D:${d.damage[0]} R:${d.reproducibility[0]} E:${d.exploitability[0]} A:${d.affectedUsers[0]} D:${d.discoverability[0]} (${d.total})`;
}

function renderAttackTree(tree: AttackTree): string {
  const lines: string[] = ["```mermaid", "flowchart TD"];
  const rootId = "goal";
  lines.push(`  ${rootId}["GOAL: ${tree.goal.replace(/["[\]{}()]/g, "")}"]`);
  tree.branches.forEach((branch, bi) => {
    const subId = `s${bi}`;
    lines.push(`  ${subId}["${branch.subGoal.replace(/["[\]{}()]/g, "")}"]`);
    lines.push(`  ${rootId} --> ${subId}`);
    branch.leaves.forEach((leaf, li) => {
      const leafId = `s${bi}_l${li}`;
      lines.push(`  ${leafId}(["${leaf.replace(/["[\]{}()]/g, "")}"])`);
      lines.push(`  ${subId} --> ${leafId}`);
    });
  });
  lines.push("```");
  return lines.join("\n");
}

export interface MarkdownThreatModelOptions {
  appName: string;
  generatedAt?: string;
  /** The completeness banner, surfaced at the top when coverage <90%. */
  completenessBanner?: string | null;
}

/**
 * Render the full threat model as Mermaid-in-markdown. The Prototype stub returns
 * the "not recommended at this tier" note (spec §4.9 tier applicability).
 */
export function renderThreatModelMarkdown(
  result: ThreatModelResult,
  opts: MarkdownThreatModelOptions,
): string {
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const out: string[] = [];

  out.push(`# Threat model — ${opts.appName}`);
  out.push("");
  out.push(`> Generated ${generatedAt}`);
  out.push("");
  out.push(`**Tier:** ${result.tier} (${TIER_ASVS_LABEL[result.tier]})`);
  out.push("");

  // Prototype stub.
  if (result.isStub) {
    out.push(
      "Threat modeling is not recommended at Prototype tier — not worth the tokens. " +
        "Re-run `/vibe-sec:threat-model` when graduating to Internal or above.",
    );
    out.push("");
    return out.join("\n");
  }

  // Completeness banner (the <90% safeguard).
  if (opts.completenessBanner) {
    out.push(`> **Inventory note:** ${opts.completenessBanner}`);
    out.push("");
  }

  // Mermaid convention documented inline so successive runs stay diff-friendly.
  out.push("## Data-flow diagram");
  out.push("");
  out.push(
    "_Convention: stadiums = external entities, rectangles = processes, " +
      "cylinders = data stores, hexagons = third-parties, subgraphs = trust boundaries._",
  );
  out.push("");
  out.push(renderMermaidDfd(result.dfd));
  out.push("");

  // Trust boundaries.
  out.push("## Trust boundaries");
  out.push("");
  for (const b of result.boundaries) out.push(`- **${b.label}**`);
  out.push("");

  // STRIDE threats by category.
  out.push("## Threats by STRIDE category");
  out.push("");
  out.push("| Category | Element | Threat | Mitigation | Owner | DREAD |");
  out.push("| --- | --- | --- | --- | --- | --- |");
  for (const t of result.threats) {
    const realized = t.realizedByFinding ? ` _(realized: ${t.realizedByFinding})_` : "";
    out.push(
      `| ${t.category} | ${t.element} | ${t.title}${realized} | ${t.mitigation} | ${t.remediationOwner} | ${dreadCell(t)} |`,
    );
  }
  out.push("");

  // Prioritized top threats.
  out.push(`## Prioritized threats (top ${result.prioritized.length}, DREAD-ordered)`);
  out.push("");
  result.prioritized.forEach((t, i) => {
    out.push(`${i + 1}. **${t.category}** — ${t.title} (DREAD ${t.dread.total}/15, owner: ${t.remediationOwner})`);
  });
  out.push("");

  // LINDDUN privacy overlay (Customer-facing+).
  if (result.privacyThreats.length > 0) {
    out.push("## Privacy threats (LINDDUN overlay)");
    out.push("");
    out.push("| Category | Element | Threat | Mitigation |");
    out.push("| --- | --- | --- | --- |");
    for (const p of result.privacyThreats) {
      out.push(`| ${p.category} | ${p.element} | ${p.title} | ${p.mitigation} |`);
    }
    out.push("");
  }

  // Attack trees (Public-facing+).
  if (result.attackTrees.length > 0) {
    out.push(`## Attack trees (top ${result.attackTrees.length})`);
    out.push("");
    result.attackTrees.forEach((tree, i) => {
      out.push(`### Attack tree ${i + 1}`);
      out.push("");
      out.push(renderAttackTree(tree));
      out.push("");
    });
  }

  // pytm stub note (Regulated).
  if (result.pytmStub) {
    out.push("## Threat-model-as-code (pytm)");
    out.push("");
    out.push(
      "At Regulated tier, maintain this model as code with OWASP pytm for git-tracked " +
        "diffs and formal-review-friendly exports. A pytm Python stub describing the " +
        "elements above is the starting point — Vibe Sec generates the initial model; " +
        "pytm and OWASP Threat Dragon own ongoing maintenance.",
    );
    out.push("");
  }

  // Pattern #13 complements (Band 4 deferral).
  out.push("## Continue in a dedicated tool");
  out.push("");
  out.push(
    "- **OWASP Threat Dragon** — import the JSON sidecar (`.vibe-sec/state/threat-model.json`) " +
      "for an interactive GUI and ongoing maintenance.",
  );
  out.push("- **pytm** — for Python-heavy teams wanting threat-model-as-code.");
  out.push("");
  out.push(
    "_Vibe Sec generates the initial model from your audit inventory; continue " +
      "maintaining it in Threat Dragon or pytm if you want._",
  );
  out.push("");

  return out.join("\n");
}
