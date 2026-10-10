import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { WorkspaceScanner } from '../../utils/workspace';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence } from '../../core/redaction';

interface CryptoRule {
  id: string;
  name: string;
  pattern: RegExp;
  description: string;
  cwe: string[];
  remediation: string;
}

const CRYPTO_RULES: CryptoRule[] = [
  {
    id: 'SENTINEL-CRYPTO-STATIC-IV',
    name: 'Hardcoded or Static Initialization Vector (IV)',
    pattern: /(?:iv|initialization_vector)\s*[:=]\s*(?:Buffer\.from\(["'][0-9a-fA-F]{16,32}["']\)|["']0000000000000000["']|b?["'][a-zA-Z0-9]{16}["'])/i,
    description: 'Using a static or predictable Initialization Vector (IV) in CBC/GCM cipher modes destroys confidentiality.',
    cwe: ['CWE-329'],
    remediation: 'Generate a unique, cryptographically random IV for every encryption operation (e.g. crypto.randomBytes(16)).'
  },
  {
    id: 'SENTINEL-CRYPTO-SHORT-RSA',
    name: 'Insufficient RSA Key Length (< 2048 bits)',
    pattern: /(?:generateKeyPair|RSA\.generate|modulusLength)\s*\([^)]*(?:512|1024)/i,
    description: 'RSA key length under 2048 bits is vulnerable to factorization attacks.',
    cwe: ['CWE-326'],
    remediation: 'Use RSA key size of at least 2048 bits (prefer 3072 or 4096 bits), or modern elliptic curve cryptography (Ed25519).'
  },
  {
    id: 'SENTINEL-CRYPTO-DES',
    name: 'Use of Deprecated DES or 3DES Cipher',
    pattern: /createCipheriv?\s*\(\s*["'](?:des|des-ede|des-ede3|des3|3des)/i,
    description: 'DES and 3DES have known structural weaknesses and small 64-bit block size (Sweet32 vulnerability).',
    cwe: ['CWE-327'],
    remediation: 'Migrate to AES-256-GCM or ChaCha20-Poly1305.'
  }
];

export class CryptoMisuseScanner extends BaseScanner {
  public readonly id = 'sentinel-crypto-misuse';
  public readonly name = 'Sentinel Cryptographic Misuse Analyzer';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (Cryptographic Pattern & Key Engine)';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];
    const workspaceRoot = options.targetDirectory;

    try {
      const discovery = WorkspaceScanner.discoverFiles(
        workspaceRoot,
        options.maxFileSizeMb,
        options.customIgnorePatterns
      );

      for (const filePath of discovery.scannableFiles) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        const relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');

        for (const rule of CRYPTO_RULES) {
          const globalRegex = new RegExp(rule.pattern.source, 'gi');
          let match: RegExpExecArray | null;

          while ((match = globalRegex.exec(content)) !== null) {
            const startLine = content.substring(0, match.index).split('\n').length;
            const lineText = lines[startLine - 1] || '';
            const fingerprint = generateFingerprint('CRYPTOGRAPHY', rule.id, relPath, startLine, match[0]);

            const evidence = sanitizeFindingEvidence({
              location: { filePath: relPath, startLine },
              snippet: lineText.trim(),
              rawMatch: match[0]
            });

            findings.push({
              fingerprint,
              title: rule.name,
              description: rule.description,
              category: 'CRYPTOGRAPHY',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              evidence: evidence as any,
              affectedComponent: relPath,
              references: {
                cwe: rule.cwe,
                owasp: ['A02:2021-Cryptographic Failures']
              },
              exploitPreconditions: 'Cryptographic primitive invoked in application encryption pipeline.',
              impact: 'Plaintext recovery, key factorization, or cipher forgery.',
              remediation: rule.remediation,
              engineId: this.id,
              engineName: this.name,
              ruleId: rule.id,
              verificationStatus: 'CONFIRMED',
              reachability: 'UNKNOWN',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        }
      }

      return {
        findings,
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'EXECUTED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: findings.length
        }
      };
    } catch (err: any) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: err?.message || String(err)
        }
      };
    }
  }
}
