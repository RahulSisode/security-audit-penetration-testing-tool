/**
 * Sentinel Security - Secret and PII Redaction Engine
 * Ensures discovered credentials, API keys, private keys, and passwords
 * are never exposed in plaintext in logs, UI, reports, JSON, SARIF, or AI prompts.
 */

const SECRET_PATTERNS = [
  // AWS Access Key ID
  { name: 'AWS_ACCESS_KEY', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
  // AWS Secret Access Key
  { name: 'AWS_SECRET_KEY', regex: /(aws_secret_access_key\s*[:=]\s*["']?)([A-Za-z0-9\/+=]{40})(["']?)/gi },
  // GitHub Personal Access Token / Fine Grained Token
  { name: 'GITHUB_TOKEN', regex: /(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/g },
  // Slack Token
  { name: 'SLACK_TOKEN', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g },
  // Stripe API Key
  { name: 'STRIPE_KEY', regex: /(?:sk_live_[0-9a-zA-Z]{24,99}|rk_live_[0-9a-zA-Z]{24,99})/g },
  // OpenAI API Key
  { name: 'OPENAI_KEY', regex: /sk-(?:proj-|live-)?[a-zA-Z0-9]{20,80}T3BlbkFJ[a-zA-Z0-9]{20,50}|sk-[a-zA-Z0-9]{48}/g },
  // Generic Private Key Headers
  { name: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  // Generic Bearer Token
  { name: 'BEARER_TOKEN', regex: /(Bearer\s+)([a-zA-Z0-9_\-\.]{20,})/gi },
  // Database Connection URL with Password
  { name: 'DB_CONNECTION_STRING', regex: /((?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^:\/\s]+:)([^@\s]+)(@[^\/\s]+)/gi },
  // Password in assignment
  { name: 'PASSWORD_ASSIGNMENT', regex: /((?:password|passwd|secret|api_key|apikey|auth_token)\s*[:=]\s*["'])([^"'\s]{4,})(["'])/gi },
  // JWT tokens
  { name: 'JWT_TOKEN', regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g }
];

/**
 * Mask secret string preserving first 3 and last 2 characters if long enough.
 */
export function maskSecretString(secret: string): string {
  if (!secret || typeof secret !== 'string') return '';
  if (secret.length <= 6) return '******';
  const prefix = secret.substring(0, 3);
  const suffix = secret.substring(secret.length - 2);
  const stars = '*'.repeat(Math.min(secret.length - 5, 12));
  return `${prefix}${stars}${suffix}`;
}

/**
 * Redacts any detected secrets in text or code snippets.
 */
export function redactSecrets(text: string): string {
  if (!text || typeof text !== 'string') return text;
  let redacted = text;

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    redacted = redacted.replace(pattern.regex, (...args: any[]) => {
      const match = args[0];
      const captures = args.slice(1, -2);

      if (captures.length === 3 && typeof captures[0] === 'string' && typeof captures[1] === 'string') {
        return `${captures[0]}${maskSecretString(captures[1])}${captures[2] || ''}`;
      }
      if (captures.length === 2 && typeof captures[0] === 'string' && typeof captures[1] === 'string') {
        return `${captures[0]}${maskSecretString(captures[1])}`;
      }
      return maskSecretString(match);
    });
  }

  return redacted;
}

/**
 * Redacts sensitive fields in finding objects before exporting or displaying.
 */
export function sanitizeFindingEvidence(evidence: {
  rawMatch?: string;
  snippet?: string;
  [key: string]: any;
}): {
  rawMatch?: string;
  redactedMatch?: string;
  snippet?: string;
  redactedSnippet?: string;
  [key: string]: any;
} {
  const sanitized = { ...evidence };
  if (evidence.rawMatch) {
    sanitized.redactedMatch = redactSecrets(evidence.rawMatch);
  }
  if (evidence.snippet) {
    sanitized.redactedSnippet = redactSecrets(evidence.snippet);
  }
  return sanitized;
}
