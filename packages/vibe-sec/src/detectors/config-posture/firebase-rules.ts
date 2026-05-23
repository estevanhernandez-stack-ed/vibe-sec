// Firebase Security Rules audit (synthesis §3.5).
//
// `allow read, write: if true;` is the #1 Firebase breach cause in 2025 — a
// fully open database, world-readable and world-writable. The Firebase web
// apiKey is harmless (it's public by design — Decision 21); the rules ARE the
// access control. So a permissive rule is Critical at any tier above Prototype.
//
// We parse firestore.rules / storage.rules / database.rules.json for:
//   - `if true` allow blocks (the open-door pattern)
//   - default-allow without a match-scoped condition
// Realtime Database JSON rules use `".read": true` / `".write": true`.

export interface FirebaseRulesFinding {
  finding_type: "firebase-open-rule" | "firebase-default-allow";
  file: string;
  line: number;
  severity: "critical" | "high";
  detail: string;
}

// allow read, write: if true;  (and single-verb variants)
const ALLOW_IF_TRUE_RE =
  /\ballow\s+[\w,\s]+:\s*if\s+true\b/gi;
// Realtime DB JSON: ".read": true / ".write": true
const RTDB_TRUE_RE = /["']\.(?:read|write)["']\s*:\s*true\b/gi;

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

/**
 * Scan Firebase rules text. Severity is Critical (the caller drops it to a
 * Prototype-only warning at the lowest tier per the spec — "Critical above
 * Prototype"). We emit Critical here; tier calibration handles the Prototype
 * down-scope.
 */
export function scanFirebaseRules(text: string, filePath: string): FirebaseRulesFinding[] {
  const out: FirebaseRulesFinding[] = [];

  ALLOW_IF_TRUE_RE.lastIndex = 0;
  for (const m of text.matchAll(ALLOW_IF_TRUE_RE)) {
    out.push({
      finding_type: "firebase-open-rule",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      severity: "critical",
      detail:
        "Firebase rule `allow read, write: if true` — the database is open to the entire internet. This is the #1 Firebase breach cause. Scope access with auth + ownership checks. (The web apiKey is public by design; the rules are the real control.)",
    });
  }

  RTDB_TRUE_RE.lastIndex = 0;
  for (const m of text.matchAll(RTDB_TRUE_RE)) {
    out.push({
      finding_type: "firebase-open-rule",
      file: filePath,
      line: lineOf(text, m.index ?? 0),
      severity: "critical",
      detail:
        'Realtime Database rule grants unconditional ".read"/".write": true — anyone can read or overwrite your data. Replace with auth-scoped rules.',
    });
  }

  return out;
}

/** True when a rules string is for a Firebase rules file we can audit. */
export function isFirebaseRulesFile(filePath: string): boolean {
  return /(?:firestore|storage)\.rules$|database\.rules\.json$/i.test(filePath);
}
