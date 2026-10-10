import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { generateFingerprint, calculateShannonEntropy } from '../../core/fingerprint';
import { WorkspaceScanner } from '../../utils/workspace';
import { sanitizeFindingEvidence, maskSecretString } from '../../core/redaction';

interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  minEntropy?: number;
  description: string;
  cwe: string[];
}

const BUILTIN_SECRET_RULES: SecretRule[] = [
  {
    id: 'SENTINEL-SEC-AWS-001',
    name: 'AWS Access Key ID',
    pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    description: 'Amazon Web Services (AWS) Access Key ID discovered in code.',
    cwe: ['CWE-798', 'CWE-200']
  },
  {
    id: 'SENTINEL-SEC-AWS-002',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    minEntropy: 3.5,
    description: 'Amazon Web Services (AWS) Secret Access Key discovered in source.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-GITHUB-001',
    name: 'GitHub Personal Access Token',
    pattern: /(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/g,
    description: 'GitHub personal access token or fine-grained token exposed.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-STRIPE-001',
    name: 'Stripe Secret Key',
    pattern: /(?:sk_(?:live|test)_[0-9a-zA-Z]{24,99}|rk_(?:live|test)_[0-9a-zA-Z]{24,99})/g,
    description: 'Stripe secret key exposed in code.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-OPENAI-001',
    name: 'OpenAI API Secret Key',
    pattern: /sk-(?:proj-|live-|test-)?[a-zA-Z0-9]{20,80}(?:T3BlbkFJ|FAKEOPENAI)[a-zA-Z0-9]{20,50}|sk-[a-zA-Z0-9]{48}/g,
    description: 'OpenAI API key detected in plaintext.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-SLACK-001',
    name: 'Slack Bot / Webhook Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    description: 'Slack OAuth / Bot token exposed.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-PRIVATEKEY-001',
    name: 'Unencrypted Private Key (RSA / SSH / EC / PEM)',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    description: 'Private key file content committed directly into repository.',
    cwe: ['CWE-312', 'CWE-798']
  },
  {
    id: 'SENTINEL-SEC-DBURL-001',
    name: 'Database Connection String With Embedded Password',
    pattern: /(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^:\/\s]+:[^@\s]+@[^\/\s]+/gi,
    description: 'Hardcoded database credentials embedded in connection URL.',
    cwe: ['CWE-798', 'CWE-200']
  },
  {
    id: 'SENTINEL-SEC-GENERIC-001',
    name: 'Hardcoded Password Assignment',
    pattern: /(?:password|passwd|db_password|admin_password)\s*[:=]\s*["']([^"']{8,})["']/gi,
    minEntropy: 3.2,
    description: 'Hardcoded secret or password variable assignment.',
    cwe: ['CWE-798']
  },
  {
    id: 'SENTINEL-SEC-JWT-001',
    name: 'Hardcoded JWT Signing Secret',
    pattern: /(?:jwt\.sign|jwt\.verify)\s*\([^,]+,\s*["']([a-zA-Z0-9_\-!@#$%^&*()]{4,})["']/gi,
    description: 'Hardcoded secret string used for JWT cryptographic signing or verification.',
    cwe: ['CWE-798', 'CWE-321']
  }
];

export class BuiltinSecretsScanner extends BaseScanner {
  public readonly id = 'sentinel-builtin-secrets';
  public readonly name = 'Sentinel Secret & Credential Detector';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (High-Entropy Regex Secret Engine)';
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

        // Check if committing .env file
        if (path.basename(filePath) === '.env' || path.basename(filePath).startsWith('.env.')) {
          if (!filePath.endsWith('.example') && !filePath.endsWith('.template')) {
            const fingerprint = generateFingerprint('SECRETS', 'SENTINEL-SEC-ENV-001', relPath, 1, 'Committed .env file');
            findings.push({
              fingerprint,
              title: 'Committed Environment File Containing Secrets (.env)',
              description: `The file ${relPath} contains active environment credentials and should not be tracked in version control.`,
              category: 'SECRETS',
              severity: 'HIGH',
              confidence: 'HIGH',
              evidence: {
                location: { filePath: relPath, startLine: 1 },
                snippet: `Environment file: ${relPath}`
              },
              affectedComponent: relPath,
              references: {
                cwe: ['CWE-798', 'CWE-200'],
                owasp: ['A05:2021-Security Misconfiguration']
              },
              exploitPreconditions: 'Repository is accessed by unauthorized users.',
              impact: 'Full leakage of all environment credentials and API tokens.',
              remediation: 'Add .env to .gitignore and rotate all secrets in the file.',
              engineId: this.id,
              engineName: this.name,
              ruleId: 'SENTINEL-SEC-ENV-001',
              verificationStatus: 'CONFIRMED',
              reachability: 'UNKNOWN',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        }

        for (const rule of BUILTIN_SECRET_RULES) {
          const globalRegex = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
          let match: RegExpExecArray | null;

          while ((match = globalRegex.exec(content)) !== null) {
            const matchedSecret = match[1] || match[0];

            // If rule has entropy requirement, check Shannon entropy
            if (rule.minEntropy && calculateShannonEntropy(matchedSecret) < rule.minEntropy) {
              continue; // Low entropy, likely placeholder like "password123" or variable name
            }

            const matchIndex = match.index;
            const startLine = content.substring(0, matchIndex).split('\n').length;
            const lineText = lines[startLine - 1] || '';
            const fingerprint = generateFingerprint('SECRETS', rule.id, relPath, startLine, match[0]);

            const evidence = sanitizeFindingEvidence({
              location: {
                filePath: relPath,
                startLine,
                startColumn: lineText.indexOf(match[0]) + 1 || 1
              },
              snippet: lineText.trim(),
              rawMatch: match[0]
            });

            findings.push({
              fingerprint,
              title: `Hardcoded Secret Detected: ${rule.name}`,
              description: `${rule.description} (Value: ${maskSecretString(matchedSecret)})`,
              category: 'SECRETS',
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              evidence: evidence as any,
              affectedComponent: relPath,
              references: {
                cwe: rule.cwe,
                owasp: ['A07:2021-Identification and Authentication Failures']
              },
              exploitPreconditions: 'Secret committed in code repository.',
              impact: 'Unauthorized access to external service or database with the privileges of this token.',
              remediation: 'Remove hardcoded secret immediately, revoke and rotate the token, and use environment variables (process.env / os.environ).',
              proposedFix: {
                description: 'Replace hardcoded secret with environment variable',
                replacementCode: `process.env.${rule.name.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
                patchDiff: `- ${evidence.redactedSnippet}\n+ const token = process.env.${rule.name.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()};`,
                targetFile: relPath,
                startLine,
                endLine: startLine,
                isDeterministic: false,
                requiresManualReview: true,
                explanation: 'Replaces hardcoded credential string with secure process.env variable reference.'
              },
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
