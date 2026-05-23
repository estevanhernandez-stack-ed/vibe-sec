// Dual OWASP 2021/2025 tagging (Decision 3; spec §4.3, synthesis §3.3).
//
// Every owasp-survey finding carries both an owasp_2021 (primary, what reports
// group by) and an owasp_2025 (annotated; surfaced in Band-2 education when the
// reclassification is meaningful). This module is the mapping table + the helper
// that produces both tags from a single category.
//
// The 2021 → 2025 shifts worth teaching (synthesis §3.3 + Decision 3):
//   - A06-2021 Vulnerable Components → A03-2025 (now "Supply Chain Failures")
//   - A10-2021 SSRF                  → A01-2025 (folded into Broken Access Control)
//   - A05-2021 Misconfiguration      → A02-2025 (rose in the 2025 ranking)
//   - A04-2021 Insecure Design       → A04-2025 (stable)
//   - A09-2021 Logging Failures      → A09-2025 (stable)
// The full table below is conservative: where the 2025 list hadn't moved a
// category we keep the same letter, so a finding always carries a defined pair.

export type Owasp2021 =
  | "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";

export interface OwaspTags {
  owasp_2021: string;
  owasp_2025: string;
  /** True when the 2021 → 2025 move is meaningful enough to name in Band-2 copy. */
  reclassified: boolean;
  /** One-line education string when reclassified, else null. */
  shiftNote: string | null;
}

const MAP: Record<Owasp2021, { to: string; note: string | null }> = {
  A01: { to: "A01", note: null },
  A02: { to: "A04", note: "Cryptographic Failures (A02-2021) maps to A04-2025." },
  A03: { to: "A03", note: null },
  A04: { to: "A04", note: null },
  A05: { to: "A02", note: "Security Misconfiguration rose to A02 in the 2025 list." },
  A06: {
    to: "A03",
    note: "Vulnerable Components (A06-2021) is now part of Supply Chain Failures (A03-2025).",
  },
  A07: { to: "A07", note: null },
  A08: { to: "A08", note: null },
  A09: { to: "A09", note: null },
  A10: {
    to: "A01",
    note: "SSRF (A10-2021) was folded into Broken Access Control (A01-2025).",
  },
};

/** Produce the dual tags for a 2021 category. */
export function dualTag(category: Owasp2021): OwaspTags {
  const entry = MAP[category];
  return {
    owasp_2021: category,
    owasp_2025: entry.to,
    reclassified: entry.note !== null,
    shiftNote: entry.note,
  };
}
