// Secret-detection Layer A — promoted regex catalog (spec §4.2, checklist 1.6).
//
// Lifted verbatim-in-spirit from the CLI's 404-line baseline
// (packages/vibe-sec-cli/src/index.js). Layer B (entropy) + Layer C (AST) are
// Phase 2; this file is the high-precision provider-prefix regex layer only.
//
// severity is the Vibe-Sec-native level; remediation is the inline runbook
// hint surfaced when a match lands.

import type { Severity } from "../../types.js";

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  remediation: string;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: "AWS_ACCESS_KEY_ID",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "critical",
    remediation:
      "Rotate this AWS access key in IAM. Move secrets to environment variables or AWS Secrets Manager.",
  },
  {
    name: "GITHUB_PAT_CLASSIC",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    remediation:
      "Revoke at github.com/settings/tokens and regenerate. Use GITHUB_TOKEN env var in CI.",
  },
  {
    name: "GITHUB_PAT_FINEGRAINED",
    regex: /\bgithub_pat_[A-Za-z0-9_]{80,120}\b/g,
    severity: "critical",
    remediation:
      "Revoke at github.com/settings/personal-access-tokens and regenerate.",
  },
  {
    name: "STRIPE_LIVE_SECRET",
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/g,
    severity: "critical",
    remediation:
      "Roll this Stripe key in dashboard.stripe.com/apikeys. Live keys can charge real cards.",
  },
  {
    name: "STRIPE_TEST_SECRET",
    regex: /\bsk_test_[A-Za-z0-9]{24,}\b/g,
    severity: "medium",
    remediation:
      "Test keys are lower-risk but still leak billing access. Rotate at dashboard.stripe.com/apikeys.",
  },
  {
    name: "SLACK_TOKEN",
    regex: /\bxox[abpr]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]{20,}\b/g,
    severity: "high",
    remediation: "Revoke in Slack's App settings → OAuth & Permissions.",
  },
  {
    name: "OPENAI_API_KEY",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    remediation: "Revoke at platform.openai.com/api-keys. Billing runs on these.",
  },
  {
    name: "ANTHROPIC_API_KEY",
    regex: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g,
    severity: "critical",
    remediation: "Revoke at console.anthropic.com/settings/keys. Billing runs on these.",
  },
  {
    name: "GOOGLE_API_KEY",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "high",
    remediation: "Restrict or regenerate at console.cloud.google.com/apis/credentials.",
  },
  {
    name: "GOOGLE_OAUTH_CLIENT_ID",
    regex: /\b[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b/g,
    severity: "low",
    remediation:
      "Client IDs are public by design, but pair them with a secret that should not be here.",
  },
  {
    name: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: "medium",
    remediation:
      "If this is a real session token, rotate your signing secret. If it's an example, comment it.",
  },
  {
    name: "PRIVATE_KEY_BLOCK",
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----/g,
    severity: "critical",
    remediation: "Rotate this key pair. Treat the old key as compromised.",
  },
  {
    name: "DATABASE_URL_WITH_CREDENTIALS",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^:\s@"']+:[^@\s"']+@[^\s"']+/g,
    severity: "high",
    remediation: "Move DB URL to an env var (DATABASE_URL) and rotate the DB password.",
  },
  {
    name: "GENERIC_API_KEY_ASSIGN",
    regex:
      /\b(?:api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi,
    severity: "medium",
    remediation: "Move this key to an environment variable or secret manager.",
  },
  {
    name: "GENERIC_SECRET_ASSIGN",
    regex: /\b(?:secret|password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    severity: "medium",
    remediation: "If this is a real credential, rotate it. Move to env vars.",
  },
];

// ─── false-positive filters (preserved from CLI) ──────────────────────────
export const PATH_SKIP_REGEX =
  /(^|[\\/])(node_modules|\.git|\.venv|venv|dist|build|coverage|\.next|\.nuxt|\.turbo|\.cache|\.pytest_cache|__pycache__|\.vibe-sec)([\\/]|$)/i;

export const FILENAME_HINT_REGEX =
  /(example|sample|mock|fake|placeholder|dummy|template|fixture)/i;

export const BINARY_EXT = new Set<string>([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
  ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
  ".mp3", ".mp4", ".mov", ".wav", ".avi", ".ogg", ".webm",
  ".ttf", ".woff", ".woff2", ".eot",
  ".so", ".dll", ".dylib", ".bin",
  ".pyc", ".class",
]);

// Known-safe placeholder strings — publicly documented examples. Split across
// concatenation so push-protection doesn't flag this source file itself.
export const KNOWN_PLACEHOLDERS = new Set<string>([
  "AKIA" + "IOSFODNN7EXAMPLE",
  "wJalrXUt" + "nFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "sk_te" + "st_4eC39HqLyjWDarjtT1zdp7dc",
]);
