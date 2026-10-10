import * as crypto from 'crypto';
import * as path from 'path';

/**
 * Generates a stable, deterministic fingerprint for a finding.
 * Normalizes file paths (relative to workspace), category, and rule identifiers
 * so that fingerprint remains identical across scans, platforms, and minor whitespace changes.
 */
export function generateFingerprint(
  category: string,
  ruleId: string,
  filePath: string,
  startLine: number,
  normalizedCodeOrSignature?: string
): string {
  // Normalize file path to forward slashes and relative format
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  
  // Normalize code token / signature (strip extraneous whitespace)
  const normCode = (normalizedCodeOrSignature || '')
    .trim()
    .replace(/\s+/g, ' ')
    .substring(0, 160);

  const rawString = `${category.toUpperCase()}|${ruleId.toLowerCase()}|${normalizedPath}|${startLine}|${normCode}`;
  
  return crypto.createHash('sha256').update(rawString).digest('hex').substring(0, 24);
}

/**
 * Computes Shannon Entropy of a string to detect high-entropy keys/passwords.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
