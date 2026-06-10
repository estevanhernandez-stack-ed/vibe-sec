// SPDX expression parser + license classifier (GAP-26; concern #11).
//
// Parses package.json `license` fields — string SPDX expressions, the legacy
// `licenses` array, and the `{ type }` object form — into one of seven
// compliance classes. The parser is correctness-bounded to what the policy
// needs: OR / AND / WITH with parens, legacy `+` suffixes, `-only`/`-or-later`
// suffixes, and case-insensitive keywords. Anything it can't parse classifies
// as `unknown` — never throws, mirroring the tolerant-parser house rule
// (lockfile.ts).
//
// THE canonical trap this module exists to get right: an OR expression with at
// least one permissive arm is PERMISSIVE. `(BSD-3-Clause OR GPL-2.0)`
// (node-forge's real expression) is a dual-license where the consumer picks the
// BSD arm — it must NOT flag as copyleft. OR takes the most permissive arm;
// AND takes the most restrictive.

/** Compliance classes, ordered from least to most restrictive. */
export type LicenseClass =
  | "permissive"
  | "weak-copyleft"
  | "strong-copyleft"
  | "network-copyleft"
  | "unknown"
  | "proprietary"
  | "missing";

/**
 * Restrictiveness rank. OR-combination takes the minimum (most permissive arm
 * wins — the consumer chooses); AND-combination takes the maximum (every term
 * binds). `unknown` ranks above the copylefts: an unknown arm can't rescue an
 * expression, but a permissive arm rescues an unknown one.
 */
const CLASS_RANK: Record<LicenseClass, number> = {
  permissive: 0,
  "weak-copyleft": 1,
  "strong-copyleft": 2,
  "network-copyleft": 3,
  unknown: 4,
  proprietary: 5,
  missing: 6,
};

function moreRestrictive(a: LicenseClass, b: LicenseClass): LicenseClass {
  return CLASS_RANK[a] >= CLASS_RANK[b] ? a : b;
}

function morePermissive(a: LicenseClass, b: LicenseClass): LicenseClass {
  return CLASS_RANK[a] <= CLASS_RANK[b] ? a : b;
}

// ─── single-id classification ────────────────────────────────────────────────
// Families are matched after stripping the SPDX modifier suffixes (`-only`,
// `-or-later`, legacy trailing `+`). The lists cover what actually shows up in
// npm trees; an unrecognized id classifies `unknown` (surfaced in the batched
// advisory), never silently `permissive`.

const PERMISSIVE_EXACT = new Set([
  "MIT",
  "MIT-0",
  "ISC",
  "0BSD",
  "UNLICENSE",
  "ZLIB",
  "WTFPL",
  "X11",
  "PYTHON-2.0",
  "PSF-2.0",
  "ARTISTIC-2.0",
  "BSL-1.0", // Boost
  "UPL-1.0",
]);

const PERMISSIVE_FAMILIES: RegExp[] = [
  /^BSD-\d/, // BSD-2-Clause, BSD-3-Clause, BSD-3-Clause-Clear, BSD-4-Clause…
  /^APACHE-/,
  /^CC0-/,
  /^CC-BY-\d/, // CC-BY-3.0 / CC-BY-4.0 — but NOT CC-BY-SA / CC-BY-NC (below)
  /^BLUEOAK-/,
];

const WEAK_COPYLEFT_FAMILIES: RegExp[] = [
  /^LGPL/,
  /^MPL-/,
  /^EPL-/,
  /^CDDL-/,
  /^CC-BY-SA/, // share-alike
  /^EUPL-/, // copyleft with broad compatibility — weak for policy purposes
];

const STRONG_COPYLEFT_FAMILIES: RegExp[] = [/^GPL-\d/, /^GPL$/];

const NETWORK_COPYLEFT_FAMILIES: RegExp[] = [
  /^AGPL/,
  /^SSPL/,
  /^OSL-/, // OSL §5: network deployment counts as distribution
];

// Use-restricted (non-commercial) Creative Commons — treated as proprietary
// for a commercial-app policy: no general right to use.
const USE_RESTRICTED_FAMILIES: RegExp[] = [/^CC-BY-NC/];

/**
 * Classify a single SPDX license id (no operators). Case-insensitive; strips
 * `-only` / `-or-later` / trailing `+` modifiers before family matching.
 */
export function classifyLicenseId(idRaw: string): LicenseClass {
  const trimmed = idRaw.trim();
  if (trimmed === "") return "missing";
  if (/^UNLICENSED$/i.test(trimmed)) return "proprietary";
  // SPDX LicenseRef-… custom references can't be classified statically.
  if (/^LicenseRef-/i.test(trimmed)) return "unknown";

  const id = trimmed
    .toUpperCase()
    .replace(/\+$/, "")
    .replace(/-(ONLY|OR-LATER)$/, "");

  if (PERMISSIVE_EXACT.has(id)) return "permissive";
  if (USE_RESTRICTED_FAMILIES.some((re) => re.test(id))) return "proprietary";
  if (NETWORK_COPYLEFT_FAMILIES.some((re) => re.test(id))) return "network-copyleft";
  // LGPL must be tested before GPL families would ever see it — the weak list
  // runs first by construction.
  if (WEAK_COPYLEFT_FAMILIES.some((re) => re.test(id))) return "weak-copyleft";
  if (STRONG_COPYLEFT_FAMILIES.some((re) => re.test(id))) return "strong-copyleft";
  if (PERMISSIVE_FAMILIES.some((re) => re.test(id))) return "permissive";
  return "unknown";
}

// ─── SPDX expression parser ──────────────────────────────────────────────────
// Grammar (precedence per the SPDX spec — WITH binds tightest, then AND, then OR):
//   or-expr   := and-expr  ( "OR"  and-expr )*
//   and-expr  := with-expr ( "AND" with-expr )*
//   with-expr := primary   ( "WITH" exception-id )?
//   primary   := "(" or-expr ")" | license-id

function tokenize(expr: string): string[] {
  return expr
    .replace(/\(/g, " ( ")
    .replace(/\)/g, " ) ")
    .split(/\s+/)
    .filter(Boolean);
}

class ExpressionParser {
  private i = 0;
  constructor(private readonly tokens: string[]) {}

  parse(): LicenseClass {
    const result = this.parseOr();
    if (this.i !== this.tokens.length) throw new Error("trailing tokens");
    return result;
  }

  private peekKeyword(kw: string): boolean {
    const t = this.tokens[this.i];
    return t !== undefined && t.toUpperCase() === kw;
  }

  private parseOr(): LicenseClass {
    let left = this.parseAnd();
    while (this.peekKeyword("OR")) {
      this.i += 1;
      // The trap, encoded: OR keeps the MOST permissive arm.
      left = morePermissive(left, this.parseAnd());
    }
    return left;
  }

  private parseAnd(): LicenseClass {
    let left = this.parseWith();
    while (this.peekKeyword("AND")) {
      this.i += 1;
      left = moreRestrictive(left, this.parseWith());
    }
    return left;
  }

  private parseWith(): LicenseClass {
    const base = this.parsePrimary();
    if (this.peekKeyword("WITH")) {
      this.i += 1;
      const exception = this.tokens[this.i];
      if (exception === undefined) throw new Error("WITH without exception id");
      this.i += 1;
      // SPDX exceptions (Classpath-exception-2.0, LLVM-exception, GCC
      // exceptions, …) exist to narrow copyleft reach for linking/embedding.
      // Policy call: a strong-copyleft base WITH any exception downgrades to
      // weak-copyleft — the obligation profile becomes LGPL-shaped. Other base
      // classes keep their class.
      if (base === "strong-copyleft") return "weak-copyleft";
    }
    return base;
  }

  private parsePrimary(): LicenseClass {
    const t = this.tokens[this.i];
    if (t === undefined) throw new Error("unexpected end of expression");
    if (t === "(") {
      this.i += 1;
      const inner = this.parseOr();
      if (this.tokens[this.i] !== ")") throw new Error("unbalanced parens");
      this.i += 1;
      return inner;
    }
    if (t === ")" || /^(OR|AND|WITH)$/i.test(t)) {
      throw new Error(`unexpected token ${t}`);
    }
    this.i += 1;
    return classifyLicenseId(t);
  }
}

/**
 * Classify a full SPDX expression string. Unparseable input → `unknown`
 * (never throws). Empty/blank → `missing`.
 */
export function classifySpdxExpression(expr: string): LicenseClass {
  const trimmed = expr.trim();
  if (trimmed === "") return "missing";
  // npm's "SEE LICENSE IN <file>" convention — a license exists but can't be
  // read statically from the field.
  if (/^SEE LICENSE/i.test(trimmed)) return "unknown";
  try {
    return new ExpressionParser(tokenize(trimmed)).parse();
  } catch {
    return "unknown";
  }
}

// ─── package.json field handling ─────────────────────────────────────────────

export interface ClassifiedLicenseField {
  /** Normalized raw expression (legacy arrays join with " OR "); null = absent. */
  expression: string | null;
  classification: LicenseClass;
}

/** Extract a license id string from a legacy entry (string or `{ type }`). */
function legacyEntryType(entry: unknown): string | null {
  if (typeof entry === "string") return entry;
  if (typeof entry === "object" && entry !== null) {
    const t = (entry as { type?: unknown }).type;
    if (typeof t === "string") return t;
  }
  return null;
}

/**
 * Classify a package.json `license` (or legacy `licenses`) field value.
 * Handles: string SPDX expression, `{ type: "MIT" }` object, legacy
 * `licenses: [{ type, url }, …]` array (multiple entries are historically
 * dual-licensing → OR semantics), and missing/empty.
 */
export function classifyLicenseField(field: unknown): ClassifiedLicenseField {
  if (field === undefined || field === null) {
    return { expression: null, classification: "missing" };
  }
  if (typeof field === "string") {
    const expression = field.trim();
    if (expression === "") return { expression: null, classification: "missing" };
    return { expression, classification: classifySpdxExpression(expression) };
  }
  if (Array.isArray(field)) {
    const types = field
      .map(legacyEntryType)
      .filter((t): t is string => t !== null && t.trim() !== "");
    if (types.length === 0) return { expression: null, classification: "missing" };
    // Legacy multi-entry array = "pick one" = OR semantics.
    const expression = types.join(" OR ");
    let cls = classifySpdxExpression(types[0]!);
    for (const t of types.slice(1)) {
      cls = morePermissive(cls, classifySpdxExpression(t));
    }
    return { expression, classification: cls };
  }
  if (typeof field === "object") {
    const t = legacyEntryType(field);
    if (t === null || t.trim() === "") return { expression: null, classification: "missing" };
    return { expression: t.trim(), classification: classifySpdxExpression(t) };
  }
  return { expression: String(field), classification: "unknown" };
}
