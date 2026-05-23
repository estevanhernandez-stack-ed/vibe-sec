// PII inventory — schema parse + client-side key leakage (spec §4.4, synthesis §3.4).
//
// The signature crypto-pii artifact: a per-field map of which model fields hold
// PII, extracted from the project's schema definitions. We parse the four common
// shapes vibe-coded apps use:
//   - Prisma  — `model User { email String  ssn String? }`
//   - Drizzle — `email: text('email')`, `ssn: varchar('ssn')`
//   - Zod     — `email: z.string().email()`, `phone: z.string()`
//   - Yup     — `email: yup.string()`, `dob: yup.date()`
//
// Field names match against a practical CCPA ∪ HIPAA ∪ GDPR pattern library:
// email, phone, ssn, dob/birth, address, name, ip, card/cvv, passport,
// driver-license, health/diagnosis, geolocation, gender, race. The classifier is
// name-based (not value-based) — the inventory is the deliverable, not a finding
// per field. Findings come from PII *handling* (in logs, in client keys), not
// from PII *existence*.
//
// Client-side key leakage is its own finding: a NEXT_PUBLIC_* / VITE_* / EXPO_PUBLIC_*
// env var whose name reads like a server secret (KEY/SECRET/TOKEN/PASSWORD) ships
// that value to the browser bundle. Public-prefixed env vars are public by
// design — naming a secret with that prefix leaks it.

import { lineOf, isSourceFile } from "../source-walk.js";
import type { Severity } from "../../types.js";

export type PiiCategory =
  | "contact"
  | "government-id"
  | "financial"
  | "health"
  | "biometric"
  | "location"
  | "demographic"
  | "credential";

export interface PiiField {
  field: string;
  category: PiiCategory;
  model: string | null;
  source: "prisma" | "drizzle" | "zod" | "yup" | "interface";
  file: string;
  line: number;
}

export interface ClientKeyLeak {
  finding_type: "client-side-key-leak";
  severity: Severity;
  variable: string;
  file: string;
  line: number;
  detail: string;
}

// CCPA ∪ HIPAA ∪ GDPR practical union — field-name → category.
const PII_PATTERNS: { re: RegExp; category: PiiCategory }[] = [
  { re: /^(?:email|e_?mail|emailAddress)$/i, category: "contact" },
  { re: /^(?:phone|phoneNumber|mobile|telephone|tel)$/i, category: "contact" },
  { re: /^(?:address|street|addr|zip|zipcode|postal(?:Code)?|city)$/i, category: "contact" },
  { re: /^(?:fullName|firstName|lastName|name|surname|givenName)$/i, category: "contact" },
  { re: /^(?:ssn|socialSecurity(?:Number)?|nationalId|taxId|ein)$/i, category: "government-id" },
  { re: /^(?:passport(?:Number)?|driverLicense|driversLicense|licenseNumber)$/i, category: "government-id" },
  { re: /^(?:card(?:Number)?|creditCard|cardNumber|cvv|cvc|iban|accountNumber|routingNumber)$/i, category: "financial" },
  { re: /^(?:dob|dateOfBirth|birth(?:Date|day)?)$/i, category: "demographic" },
  { re: /^(?:gender|sex|race|ethnicity|religion|nationality)$/i, category: "demographic" },
  { re: /^(?:diagnosis|healthRecord|medical(?:Record)?|prescription|bloodType|allerg\w*)$/i, category: "health" },
  { re: /^(?:latitude|longitude|lat|lng|geo|coordinates|location|gpsCoord\w*)$/i, category: "location" },
  { re: /^(?:fingerprint|faceId|biometric|retina|voiceprint)$/i, category: "biometric" },
  { re: /^(?:password|passwd|pwd|secret|apiKey|accessToken|refreshToken)$/i, category: "credential" },
];

function classifyField(name: string): PiiCategory | null {
  for (const p of PII_PATTERNS) if (p.re.test(name)) return p.category;
  return null;
}

// ─── schema parsers ──────────────────────────────────────────────────────

// Prisma: inside `model X {  field Type  }` blocks. Fields are `name Type` pairs;
// tolerate both one-per-line and same-line declarations. We skip block-level
// attributes (`@@index`) and field lines starting with `@`.
const PRISMA_MODEL_RE = /\bmodel\s+(\w+)\s*\{([^}]*)\}/g;
const PRISMA_FIELD_RE = /(?:^|\n|\s)(\w+)\s+(?:String|Int|BigInt|Float|Decimal|Boolean|DateTime|Json|Bytes|\w+)(?:\?|\[\])?/g;

function parsePrisma(text: string, filePath: string): PiiField[] {
  const out: PiiField[] = [];
  PRISMA_MODEL_RE.lastIndex = 0;
  for (const model of text.matchAll(PRISMA_MODEL_RE)) {
    const modelName = model[1] ?? null;
    const body = model[2] ?? "";
    const bodyStart = (model.index ?? 0) + (model[0].indexOf("{") + 1);
    PRISMA_FIELD_RE.lastIndex = 0;
    for (const f of body.matchAll(PRISMA_FIELD_RE)) {
      const field = f[1] ?? "";
      const cat = classifyField(field);
      if (cat) {
        out.push({
          field,
          category: cat,
          model: modelName,
          source: "prisma",
          file: filePath,
          line: lineOf(text, bodyStart + (f.index ?? 0)),
        });
      }
    }
  }
  return out;
}

// Drizzle: `email: text('email')` / `ssn: varchar('ssn', …)`.
const DRIZZLE_FIELD_RE =
  /\b(\w+)\s*:\s*(?:text|varchar|char|integer|bigint|date|timestamp|json|jsonb|numeric|real)\s*\(/g;

// Zod / Yup: `email: z.string()` / `phone: yup.string()`.
const VALIDATOR_FIELD_RE = /\b(\w+)\s*:\s*(?:z|yup)\s*\./g;

function parseFieldShape(
  text: string,
  filePath: string,
  re: RegExp,
  source: PiiField["source"],
): PiiField[] {
  const out: PiiField[] = [];
  re.lastIndex = 0;
  for (const m of text.matchAll(re)) {
    const field = m[1] ?? "";
    const cat = classifyField(field);
    if (cat) {
      out.push({
        field,
        category: cat,
        model: null,
        source,
        file: filePath,
        line: lineOf(text, m.index ?? 0),
      });
    }
  }
  return out;
}

/** Parse the PII inventory out of one schema/source file. */
export function scanPiiInventory(text: string, filePath: string): PiiField[] {
  const out: PiiField[] = [];
  if (/\.prisma$/i.test(filePath) || /\bmodel\s+\w+\s*\{/.test(text)) {
    out.push(...parsePrisma(text, filePath));
  }
  if (isSourceFile(filePath)) {
    out.push(...parseFieldShape(text, filePath, DRIZZLE_FIELD_RE, "drizzle"));
    out.push(...parseFieldShape(text, filePath, VALIDATOR_FIELD_RE, /\.string|yup/.test(text) ? "zod" : "zod"));
  }
  // Dedup by field+file+line — a field can match more than one parser shape.
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.file}:${f.line}:${f.field}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── client-side key leakage ─────────────────────────────────────────────

// NEXT_PUBLIC_* / VITE_* / EXPO_PUBLIC_* / REACT_APP_* / PUBLIC_* env var refs.
const PUBLIC_ENV_RE =
  /\b(?:process\.env\.|import\.meta\.env\.)((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|PUBLIC)_\w+)/g;
// A name that reads like a server secret (vs a publishable/anon key, which is fine).
const SECRET_NAME_RE = /(SECRET|PRIVATE|SERVICE[_-]?ROLE|API[_-]?KEY|ACCESS[_-]?TOKEN|PASSWORD|CLIENT[_-]?SECRET)/i;
// Names that are public by design even with a secret-ish word — allowlist.
const PUBLISHABLE_RE = /(PUBLISHABLE|ANON|PUBLIC[_-]?KEY|MEASUREMENT|MAPBOX|SENTRY[_-]?DSN)/i;

/** Scan one source file for client-bundle key leakage via public env prefixes. */
export function scanClientKeyLeak(text: string, filePath: string): ClientKeyLeak[] {
  const out: ClientKeyLeak[] = [];
  PUBLIC_ENV_RE.lastIndex = 0;
  for (const m of text.matchAll(PUBLIC_ENV_RE)) {
    const variable = m[1] ?? "";
    if (SECRET_NAME_RE.test(variable) && !PUBLISHABLE_RE.test(variable)) {
      out.push({
        finding_type: "client-side-key-leak",
        severity: "high",
        variable,
        file: filePath,
        line: lineOf(text, m.index ?? 0),
        detail: `${variable} uses a public env prefix, so its value is inlined into the client bundle and visible to anyone. A name like this reads as a server secret — if it is one, rename it without the public prefix, read it server-side only, and rotate it.`,
      });
    }
  }
  return out;
}
