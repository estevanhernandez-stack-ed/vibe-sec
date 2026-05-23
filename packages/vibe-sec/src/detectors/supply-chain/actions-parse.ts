// GitHub Actions hardening (synthesis §3.6, Decision 24).
//
// Post-tj-actions, the minimum bar moved: third-party Actions must be SHA-pinned
// (a tag is mutable — the tj-actions compromise rewrote tags under maintainers),
// and workflows should declare least-privilege `permissions`. We parse the YAML
// by hand (no yaml dep — keep the bundle lean) for two signals:
//   1. `uses:` ref style per step — sha / tag / branch / floating
//   2. top-level + job-level `permissions:` presence
//
// Severity is tier-gated by the caller: SHA-pin third-party at Public-facing+,
// first-party (actions/*) only at Regulated (Decision 24). This module produces
// the raw classification; tier calibration happens in scoring.

import fs from "node:fs";
import path from "node:path";

export type RefStyle = "sha" | "tag" | "branch" | "floating" | "local" | "docker";

export interface ActionUse {
  /** The full `uses:` value, e.g. "actions/checkout@v4". */
  raw: string;
  /** owner/repo (or local/docker marker). */
  action: string;
  ref: string;
  refStyle: RefStyle;
  /** True when owned by github (actions/*, github/*) — first-party. */
  firstParty: boolean;
  workflow: string;
  line: number;
}

export interface WorkflowParse {
  workflow: string;
  uses: ActionUse[];
  /** True when a top-level `permissions:` block is declared. */
  hasTopLevelPermissions: boolean;
}

const FIRST_PARTY_OWNERS = new Set(["actions", "github"]);
const SHA_RE = /^[0-9a-f]{40}$/i;
const SEMVER_TAG_RE = /^v?\d+(?:\.\d+){0,2}$/;
const FLOATING_TAG_RE = /^v\d+$/; // v4, v3 — major-only floating tag

/** Classify a ref string into a pin style. */
export function classifyRef(ref: string): RefStyle {
  if (SHA_RE.test(ref)) return "sha";
  if (FLOATING_TAG_RE.test(ref)) return "floating"; // v4 floats within the major
  if (SEMVER_TAG_RE.test(ref)) return "tag";
  if (ref === "main" || ref === "master" || /^[\w./-]+$/.test(ref)) return "branch";
  return "tag";
}

/** Parse a single workflow file's text for `uses:` + permissions signals. */
export function parseWorkflowText(text: string, workflow: string): WorkflowParse {
  const uses: ActionUse[] = [];
  let hasTopLevelPermissions = false;
  const lines = text.split("\n");

  lines.forEach((line, idx) => {
    // top-level permissions: a `permissions:` key at column 0.
    if (/^permissions\s*:/.test(line)) hasTopLevelPermissions = true;

    const m = line.match(/^\s*(?:-\s*)?uses\s*:\s*['"]?([^'"#\s]+)['"]?/);
    if (!m) return;
    const raw = m[1]!;
    if (raw.startsWith("./") || raw.startsWith("../")) {
      uses.push({
        raw,
        action: raw,
        ref: "",
        refStyle: "local",
        firstParty: true,
        workflow,
        line: idx + 1,
      });
      return;
    }
    if (raw.startsWith("docker://")) {
      uses.push({
        raw,
        action: raw,
        ref: "",
        refStyle: "docker",
        firstParty: false,
        workflow,
        line: idx + 1,
      });
      return;
    }
    const at = raw.lastIndexOf("@");
    const action = at > 0 ? raw.slice(0, at) : raw;
    const ref = at > 0 ? raw.slice(at + 1) : "";
    const owner = action.split("/")[0] ?? "";
    uses.push({
      raw,
      action,
      ref,
      refStyle: ref ? classifyRef(ref) : "branch",
      firstParty: FIRST_PARTY_OWNERS.has(owner),
      workflow,
      line: idx + 1,
    });
  });

  return { workflow, uses, hasTopLevelPermissions };
}

/** Find + parse all workflow YAML files under .github/workflows/. */
export function parseWorkflows(projectRoot: string): WorkflowParse[] {
  const dir = path.join(projectRoot, ".github", "workflows");
  let files: string[];
  try {
    files = fs.readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f));
  } catch {
    return [];
  }
  const out: WorkflowParse[] = [];
  for (const file of files) {
    let text = "";
    try {
      text = fs.readFileSync(path.join(dir, file), "utf8");
    } catch {
      continue;
    }
    out.push(parseWorkflowText(text, `.github/workflows/${file}`));
  }
  return out;
}

export interface ActionsFinding {
  workflow: string;
  line: number;
  finding_type:
    | "unpinned-third-party-action"
    | "unpinned-first-party-action"
    | "missing-permissions-block";
  action?: string;
  detail: string;
}

/**
 * Surface raw Actions hardening findings. Tier calibration (which of these
 * actually fail the gate) is the caller's job — Decision 24 says third-party
 * unpinned matters at Public-facing+, first-party only at Regulated.
 */
export function findActionsIssues(parses: readonly WorkflowParse[]): ActionsFinding[] {
  const out: ActionsFinding[] = [];
  for (const wf of parses) {
    if (!wf.hasTopLevelPermissions) {
      out.push({
        workflow: wf.workflow,
        line: 1,
        finding_type: "missing-permissions-block",
        detail:
          "No top-level permissions: block — the workflow runs with the repo default token scope. Add `permissions: contents: read` and widen per-job as needed.",
      });
    }
    for (const u of wf.uses) {
      if (u.refStyle === "local" || u.refStyle === "sha") continue;
      out.push({
        workflow: wf.workflow,
        line: u.line,
        finding_type: u.firstParty
          ? "unpinned-first-party-action"
          : "unpinned-third-party-action",
        action: u.action,
        detail: `${u.action}@${u.ref} is pinned by ${u.refStyle}, not SHA. A tag is mutable — pin to the full commit SHA to defeat tag-rewrite supply-chain attacks.`,
      });
    }
  }
  return out;
}
