// Secret-detection Layer A — provider regex catalog (spec §4.2, synthesis §3.2).
//
// Phase 1 promoted the CLI's 15-pattern baseline; Phase 2.1 expands it to the
// 40-50 canonical provider patterns synthesis §3.2 calls for (AWS, GitHub,
// Stripe, Slack, OpenAI, Anthropic, Google, Firebase, Supabase, Twilio,
// SendGrid, Postman, NPM, PyPI, Docker Hub, Vercel, Heroku, Discord, Mailgun,
// DeepSeek, HuggingFace, JWT, PEM private keys, DB URLs with embedded creds).
//
// Layer B (entropy) lives in entropy.ts; Layer C (AST) in ast-walk.ts. This
// file is the high-precision provider-prefix regex layer.
//
// severity is the Vibe-Sec-native level; remediation is the inline runbook
// hint surfaced when a match lands.

import type { Severity } from "../../types.js";

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  remediation: string;
  /**
   * Informational-only patterns (Decision 21): matched + surfaced, never a
   * blocker on their own. Firebase web client keys are the canonical case —
   * public by design, the real control is Security Rules. A match emits a
   * companion "audit your rules" hint rather than a severity escalation.
   */
  informational?: boolean;
  /** Companion concern this informational match should route an audit toward. */
  companion?: string;
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
  // ─── expanded provider catalog (Phase 2.1, synthesis §3.2) ──────────────
  {
    name: "AWS_SECRET_ACCESS_KEY_ASSIGN",
    // The 40-char base64-ish secret, only when assigned to an aws-secret-ish name.
    regex:
      /\baws_?secret_?access_?key\s*[:=]\s*["']([A-Za-z0-9/+]{40})["']/gi,
    severity: "critical",
    remediation:
      "Rotate this AWS secret access key in IAM immediately. Pair it with the access key id you also need to roll.",
  },
  {
    name: "GITHUB_OAUTH_TOKEN",
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    remediation: "Revoke this GitHub OAuth token. Treat any session it backs as compromised.",
  },
  {
    name: "GITHUB_APP_TOKEN",
    regex: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    remediation: "Revoke this GitHub App / refresh token at the app's settings.",
  },
  {
    name: "GITLAB_PAT",
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    remediation: "Revoke at gitlab.com → Settings → Access Tokens and regenerate.",
  },
  {
    name: "SUPABASE_SERVICE_KEY",
    // Supabase service_role / anon keys are JWTs with a service_role claim; the
    // assignment form is the high-signal catch (the bare JWT is handled above).
    regex: /\bsbp_[A-Za-z0-9]{40,}\b/g,
    severity: "critical",
    remediation:
      "Rotate this Supabase access token in the dashboard. service_role keys bypass RLS — treat as root.",
  },
  {
    name: "TWILIO_API_KEY",
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
    severity: "high",
    remediation: "Revoke at twilio.com/console → API keys. Pair with the account SID it signs for.",
  },
  {
    name: "TWILIO_ACCOUNT_SID",
    regex: /\bAC[0-9a-fA-F]{32}\b/g,
    severity: "low",
    remediation:
      "Account SIDs are identifiers, not secrets — but they pair with an auth token that should not be here.",
  },
  {
    name: "SENDGRID_API_KEY",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: "high",
    remediation: "Revoke at app.sendgrid.com → Settings → API Keys.",
  },
  {
    name: "MAILGUN_API_KEY",
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
    severity: "high",
    remediation: "Rotate at app.mailgun.com → Settings → API Keys.",
  },
  {
    name: "POSTMAN_API_KEY",
    regex: /\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b/g,
    severity: "high",
    remediation: "Revoke at postman.com → Settings → API Keys.",
  },
  {
    name: "NPM_ACCESS_TOKEN",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    remediation:
      "Revoke at npmjs.com → Access Tokens. A leaked publish token lets an attacker push malicious versions.",
  },
  {
    name: "PYPI_API_TOKEN",
    regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
    severity: "critical",
    remediation: "Revoke at pypi.org → Account settings → API tokens.",
  },
  {
    name: "DOCKER_HUB_PAT",
    regex: /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g,
    severity: "critical",
    remediation: "Revoke at hub.docker.com → Account Settings → Security.",
  },
  {
    name: "VERCEL_TOKEN",
    regex: /\b(?:vercel|vc)_[A-Za-z0-9]{24}\b/g,
    severity: "high",
    remediation: "Revoke at vercel.com → Account Settings → Tokens.",
  },
  {
    name: "HEROKU_API_KEY",
    // Heroku keys are UUIDs assigned to a heroku-ish name (UUID alone is noisy).
    regex:
      /\bheroku[_-]?(?:api[_-]?key|token)\s*[:=]\s*["']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']/gi,
    severity: "high",
    remediation: "Regenerate at dashboard.heroku.com → Account → API Key.",
  },
  {
    name: "DISCORD_BOT_TOKEN",
    regex: /\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g,
    severity: "high",
    remediation: "Reset at discord.com/developers → your application → Bot → Reset Token.",
  },
  {
    name: "DISCORD_WEBHOOK",
    regex:
      /\bhttps:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,}\b/g,
    severity: "medium",
    remediation: "Delete and recreate the webhook in the channel's integration settings.",
  },
  {
    name: "DEEPSEEK_API_KEY",
    regex: /\bsk-[a-f0-9]{32}\b/g,
    severity: "high",
    remediation: "Revoke at platform.deepseek.com → API keys. Billing runs on these.",
  },
  {
    name: "HUGGINGFACE_TOKEN",
    regex: /\bhf_[A-Za-z0-9]{34,}\b/g,
    severity: "high",
    remediation: "Revoke at huggingface.co → Settings → Access Tokens.",
  },
  {
    name: "SHOPIFY_TOKEN",
    regex: /\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b/g,
    severity: "high",
    remediation: "Rotate this Shopify token in the app/partner dashboard.",
  },
  {
    name: "SQUARE_ACCESS_TOKEN",
    regex: /\b(?:EAAA|sq0atp-)[A-Za-z0-9_-]{22,}\b/g,
    severity: "high",
    remediation: "Revoke at developer.squareup.com → your app → Credentials.",
  },
  {
    name: "LINEAR_API_KEY",
    regex: /\blin_api_[A-Za-z0-9]{40,}\b/g,
    severity: "high",
    remediation: "Revoke at linear.app → Settings → API.",
  },
  {
    name: "DATABASE_URL_SQLSERVER",
    regex: /\bServer=[^;\s"']+;.*?Password=[^;\s"']+/gi,
    severity: "high",
    remediation: "Move this connection string to an env var and rotate the DB password.",
  },
  {
    name: "FIREBASE_WEB_API_KEY",
    // Firebase web client keys look like Google API keys but are public by
    // design — informational, with a rules-audit companion (Decision 21). The
    // assignment-context form keeps this from double-firing GOOGLE_API_KEY by
    // proximity to a Firebase config key. Recognized contexts (all on one line,
    // an AIza… literal within a short window of a Firebase-web-key marker):
    //   - `apiKey: "AIza…"`                  (direct config object assignment)
    //   - `apiKey: import.meta.env.X || "AIza…"` (the env-fallback form)
    //   - `VITE_FIREBASE_API_KEY=AIza…`      (Vite/CRA env var, name says firebase)
    //   - `FIREBASE_API_KEY = "AIza…"`       (any *FIREBASE*_API_KEY env name)
    // The capture group is the AIza… literal so the de-double-tag step can match
    // it against the GOOGLE_API_KEY hit on the same line and drop the duplicate.
    regex:
      /(?:\bapiKey\s*[:=][^\n"'`]{0,80}|\b\w*FIREBASE\w*_?API_?KEY\s*[:=][^\n"'`]{0,80})["'`]?(AIza[0-9A-Za-z_-]{35})["'`]?/gi,
    severity: "low",
    informational: true,
    companion: "config-posture",
    remediation:
      "Firebase web API keys are public by design — they identify the project, they don't grant access. The real control is your Security Rules. Run /vibe-sec:audit and check the rules companion finding.",
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
