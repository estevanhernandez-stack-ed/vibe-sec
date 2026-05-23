import { describe, it, expect } from "vitest";
import { buildBandedReport, bandFor, selectComplements } from "./bands.js";
import { renderBanner } from "./banner.js";
import { renderMarkdownReport, renderOwaspGrouped, alsoTaggedAs } from "./markdown.js";
import { makeFinding, type Finding } from "../state/findings.js";
import type { Concern, Severity } from "../types.js";
import type { AuthzMatrix } from "../detectors/auth-model/authz-matrix.js";

function mk(opts: {
  id: string;
  concern: Concern;
  sev: Severity;
  o21?: string | null;
  o25?: string | null;
  secondary?: Concern[];
  finding_type?: string;
}): Finding {
  return makeFinding({
    id: opts.id,
    primary_concern: opts.concern,
    secondary_concerns: opts.secondary ?? [],
    severity_base: opts.sev,
    severity_tier_adjusted: opts.sev,
    confidence: 0.9,
    finding_type: opts.finding_type ?? "x",
    title: `${opts.concern} ${opts.sev}`,
    description: "detail",
    tier: "public-facing",
    fix_class: "stage",
    tool_of_record: "in-house",
    owasp_2021: opts.o21 ?? null,
    owasp_2025: opts.o25 ?? null,
  });
}

describe("3.5 bands — four-band classification", () => {
  it("High/Critical in-scope → Band 1; Medium/Low in-scope → Band 2; out-of-scope → Band 3", () => {
    // At public-facing: auth-model in scope; threat-model is full but never gate-blocking.
    expect(bandFor(mk({ id: "a", concern: "auth-model", sev: "critical" }), "public-facing")).toBe(1);
    expect(bandFor(mk({ id: "b", concern: "auth-model", sev: "low" }), "public-facing")).toBe(2);
    // At prototype: owasp-survey is skip → Band 3.
    expect(bandFor(mk({ id: "c", concern: "owasp-survey", sev: "high" }), "prototype")).toBe(3);
  });

  it("suppressed findings are excluded from all bands", () => {
    const f = mk({ id: "s", concern: "auth-model", sev: "critical" });
    f.suppressed = true;
    expect(bandFor(f, "public-facing")).toBeNull();
  });

  it("buildBandedReport sorts Band 1 by severity descending", () => {
    const report = buildBandedReport(
      [
        mk({ id: "h", concern: "auth-model", sev: "high" }),
        mk({ id: "c", concern: "config-posture", sev: "critical" }),
      ],
      "public-facing",
    );
    expect(report.band1[0]!.severity_tier_adjusted).toBe("critical");
    expect(report.band1[1]!.severity_tier_adjusted).toBe("high");
  });
});

describe("3.5 bands — Band 4 complements lead by context", () => {
  it("Arcjet leads when LLM detected", () => {
    const cs = selectComplements({ llmDetected: true });
    expect(cs[0]!.tool).toBe("Arcjet");
  });
  it("Socket surfaces for SCA, Semgrep for injection", () => {
    const cs = selectComplements({ hasDependencies: true, injectionSurfaced: true });
    expect(cs.some((c) => c.tool.includes("Socket"))).toBe(true);
    expect(cs.some((c) => c.tool.includes("Semgrep"))).toBe(true);
  });
  it("does not re-recommend a tool already used", () => {
    const cs = selectComplements({ injectionSurfaced: true, toolsUsed: ["semgrep"] });
    expect(cs.some((c) => c.tool.includes("Semgrep"))).toBe(false);
  });
});

describe("3.5 markdown — four-band + OWASP grouping (Conflict 10 = A)", () => {
  it("renders all four band headings", () => {
    const report = buildBandedReport([mk({ id: "a", concern: "auth-model", sev: "critical", o21: "A01", o25: "A01" })], "public-facing");
    const md = renderMarkdownReport(report, { command: "audit", score: 0.6, gatePass: false });
    expect(md).toContain("## Band 1 — action needed now");
    expect(md).toContain("## Band 2 — tier-appropriate, worth reading");
    expect(md).toContain("## Band 3 — if you graduate");
    expect(md).toContain("## Band 4 — tools that catch what the baseline misses");
    expect(md).toContain("## By OWASP category");
  });

  it("renders one finding under EVERY applicable OWASP category with 'also tagged as'", () => {
    // A crypto finding: A02-2021 → A04-2025. It should appear under both A02 and A04.
    const crypto = mk({ id: "crypto-1", concern: "crypto-pii", sev: "high", o21: "A02", o25: "A04" });
    const md = renderOwaspGrouped([crypto]);
    expect(md).toContain("### A02 — Cryptographic Failures");
    expect(md).toContain("### A04 — Insecure Design");
    expect(md).toContain("also tagged as:");
    // Under A02 it names A04-2025; under A04 it names A02-2021.
    expect(md).toContain("A04-2025");
    expect(md).toContain("A02-2021");
  });

  it("alsoTaggedAs names the primary concern + secondaries", () => {
    const f = mk({ id: "z", concern: "auth-model", sev: "high", o21: "A01", o25: "A01", secondary: ["owasp-survey", "config-posture"] });
    const note = alsoTaggedAs(f, "A01");
    expect(note).toContain("primary concern: auth-model");
    expect(note).toContain("secondary: owasp-survey, config-posture");
  });

  it("a single-category finding renders once under its category (not duplicated)", () => {
    const f = mk({ id: "single", concern: "auth-model", sev: "high", o21: "A01", o25: "A01" });
    const md = renderOwaspGrouped([f]);
    const occurrences = md.split("auth-model high").length - 1;
    expect(occurrences).toBe(1);
  });
});

describe("3.5 banner — terminal channel", () => {
  it("renders the verdict, band-1 items, and the authz matrix abbreviated", () => {
    const report = buildBandedReport(
      [mk({ id: "a", concern: "auth-model", sev: "critical", finding_type: "admin-route-no-auth" })],
      "public-facing",
    );
    const matrix: AuthzMatrix = {
      dimensions: ["auth-required", "role-gated", "ownership-enforced", "rls-applicable"],
      rows: [
        {
          route: "/api/admin/users",
          method: "GET",
          framework: "next-app",
          file: "app/api/admin/users/route.ts",
          cells: { "auth-required": "absent", "role-gated": "absent", "ownership-enforced": "unknown", "rls-applicable": "n/a" },
        },
      ],
    };
    const banner = renderBanner(report, { score: 0.4, threshold: 0.7, gatePass: false, authzMatrix: matrix, noColor: true });
    expect(banner).toContain("FAIL");
    expect(banner).toContain("Band 1 — action needed now");
    expect(banner).toContain("authorization matrix (abbreviated)");
    expect(banner).toContain("/api/admin/users");
  });

  it("clean report says clean, no color codes when noColor", () => {
    const report = buildBandedReport([], "internal");
    const banner = renderBanner(report, { score: 0.9, threshold: 0.55, gatePass: true, noColor: true });
    expect(banner).toContain("clean");
    expect(banner).not.toContain("\x1b[");
  });
});
