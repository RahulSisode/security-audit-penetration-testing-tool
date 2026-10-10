import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity } from '../../core/types';
import { WorkspaceScanner } from '../../utils/workspace';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence } from '../../core/redaction';

interface IaCRule {
  id: string;
  name: string;
  fileMatcher: (filename: string, content: string) => boolean;
  patterns: RegExp[];
  severity: Severity;
  description: string;
  cwe: string[];
  remediation: string;
}

const IAC_RULES: IaCRule[] = [
  // Dockerfile: Root user
  {
    id: 'SENTINEL-IAC-DOCKER-001',
    name: 'Container Running as Root User',
    fileMatcher: (f) => path.basename(f).toLowerCase().includes('dockerfile'),
    patterns: [
      /USER\s+root/i,
      /^FROM\s+[^\n]+(?!(?:[\s\S]*?\nUSER\s+(?!root\b)[a-zA-Z0-9_\-]+))/i
    ],
    severity: 'HIGH',
    description: 'Container does not specify a non-root USER instruction, running process as root.',
    cwe: ['CWE-250', 'CWE-269'],
    remediation: 'Add a dedicated non-root user (e.g. USER node or USER nonroot) before CMD/ENTRYPOINT.'
  },
  // Docker Compose / K8s: Privileged Container
  {
    id: 'SENTINEL-IAC-K8S-001',
    name: 'Privileged Container Execution Allowed',
    fileMatcher: (f) => f.endsWith('.yaml') || f.endsWith('.yml'),
    patterns: [
      /privileged\s*:\s*true/i,
      /allowPrivilegeEscalation\s*:\s*true/i
    ],
    severity: 'CRITICAL',
    description: 'Container granted privileged mode which allows full access to host devices and kernel capabilities.',
    cwe: ['CWE-250'],
    remediation: 'Set privileged: false and allowPrivilegeEscalation: false.'
  },
  // Kubernetes: Missing Resource Limits
  {
    id: 'SENTINEL-IAC-K8S-002',
    name: 'Missing CPU and Memory Resource Limits',
    fileMatcher: (f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && !f.includes('.github'),
    patterns: [
      /kind\s*:\s*Deployment[\s\S]*?spec\s*:\s*(?![\s\S]*?limits\s*:)/i
    ],
    severity: 'LOW',
    description: 'Kubernetes workload does not specify resource limits, risking node resource exhaustion and DoS.',
    cwe: ['CWE-400'],
    remediation: 'Define resources.limits.cpu and resources.limits.memory for all containers.'
  },
  // Terraform: Open Security Group to 0.0.0.0/0
  {
    id: 'SENTINEL-IAC-TF-001',
    name: 'Security Group Ingress Open to World (0.0.0.0/0)',
    fileMatcher: (f) => f.endsWith('.tf'),
    patterns: [
      /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/i,
      /cidr_blocks\s*=\s*\[\s*"::\/0"\s*\]/i
    ],
    severity: 'HIGH',
    description: 'Infrastructure security group allows unrestricted inbound traffic from any IP address.',
    cwe: ['CWE-284'],
    remediation: 'Restrict ingress cidr_blocks to specific VPC CIDR ranges or authorized IP addresses.'
  },
  // Terraform / AWS: IAM Wildcard Permission
  {
    id: 'SENTINEL-IAC-IAM-001',
    name: 'IAM Policy Allows Full Administrative Wildcard (*)',
    fileMatcher: (f) => f.endsWith('.tf') || f.endsWith('.json'),
    patterns: [
      /"Action"\s*:\s*"\*"/i,
      /"Resource"\s*:\s*"\*"/i,
      /actions\s*=\s*\[\s*"\*"\s*\]/i
    ],
    severity: 'HIGH',
    description: 'IAM Policy grants broad wildcard actions or resources, violating principle of least privilege.',
    cwe: ['CWE-732', 'CWE-250'],
    remediation: 'Grant only specific required IAM action verbs and scoped ARN resources.'
  },
  // GitHub Actions: Insecure pull_request_target checkout
  {
    id: 'SENTINEL-IAC-GHA-001',
    name: 'Insecure pull_request_target with Code Checkout',
    fileMatcher: (f) => f.includes('.github/workflows'),
    patterns: [
      /pull_request_target[\s\S]*?actions\/checkout/i
    ],
    severity: 'CRITICAL',
    description: 'Triggering workflow on pull_request_target while checking out untrusted PR head ref permits repository secret theft.',
    cwe: ['CWE-829'],
    remediation: 'Use pull_request trigger instead of pull_request_target when executing PR code.'
  },
  // CORS Misconfiguration: Access-Control-Allow-Origin: * with credentials
  {
    id: 'SENTINEL-IAC-CORS-001',
    name: 'Insecure CORS Policy with Wildcard Origin',
    fileMatcher: () => true,
    patterns: [
      /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]\s*,\s*credentials\s*:\s*true/i,
      /setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/i,
      /header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\)/i
    ],
    severity: 'MEDIUM',
    description: 'CORS header configured with wildcard * origin, exposing sensitive API responses to cross-origin requests.',
    cwe: ['CWE-346', 'CWE-942'],
    remediation: 'Specify explicit trusted origins in Access-Control-Allow-Origin rather than wildcard *.'
  },
  // Security Headers: Missing Helmet or CSP
  {
    id: 'SENTINEL-IAC-HEADER-001',
    name: 'Disabled Helmet / Security Headers in Web Server',
    fileMatcher: (f) => f.endsWith('.js') || f.endsWith('.ts'),
    patterns: [
      /helmet\.contentSecurityPolicy\s*\(\s*\{\s*directives\s*:\s*\{\s*defaultSrc\s*:\s*\[\s*['"]\*['"]/i,
      /app\.use\(helmet\(\{[\s\S]*?contentSecurityPolicy:\s*false/i
    ],
    severity: 'LOW',
    description: 'Content Security Policy (CSP) disabled or configured with wildcard sources.',
    cwe: ['CWE-693'],
    remediation: 'Enable Content Security Policy with restrictive default-src and script-src directives.'
  }
];

export class BuiltinIaCScanner extends BaseScanner {
  public readonly id = 'sentinel-builtin-iac';
  public readonly name = 'Sentinel Infrastructure & Cloud Configuration Scanner';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (Cloud & IaC Policy Analyzer)';
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

        for (const rule of IAC_RULES) {
          if (!rule.fileMatcher(relPath, content)) continue;

          for (const pattern of rule.patterns) {
            const globalRegex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
            let match: RegExpExecArray | null;

            while ((match = globalRegex.exec(content)) !== null) {
              const matchIndex = match.index;
              const startLine = content.substring(0, matchIndex).split('\n').length;
              const lineText = lines[startLine - 1] || '';
              const fingerprint = generateFingerprint('IAC_MISCONFIGURATION', rule.id, relPath, startLine, match[0]);

              const evidence = sanitizeFindingEvidence({
                location: {
                  filePath: relPath,
                  startLine,
                  startColumn: lineText.indexOf(match[0].trim()) + 1 || 1
                },
                snippet: lineText.trim(),
                rawMatch: match[0]
              });

              findings.push({
                fingerprint,
                title: rule.name,
                description: rule.description,
                category: 'IAC_MISCONFIGURATION',
                severity: rule.severity,
                confidence: 'CONFIRMED',
                evidence: evidence as any,
                affectedComponent: relPath,
                references: {
                  cwe: rule.cwe,
                  owasp: ['A05:2021-Security Misconfiguration']
                },
                exploitPreconditions: 'Infrastructure deployed with insecure configuration.',
                impact: 'Privilege escalation, unauthorized container breakout, or network exposure.',
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
