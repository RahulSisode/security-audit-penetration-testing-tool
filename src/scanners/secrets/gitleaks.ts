import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence, maskSecretString } from '../../core/redaction';

export class GitleaksScanner extends BaseScanner {
  public readonly id = 'gitleaks';
  public readonly name = 'Gitleaks Secret Scanner';

  public async isAvailable(): Promise<boolean> {
    const tools = await ToolDiscovery.discover();
    return !!tools.gitleaks;
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (!tools.gitleaks) return 'Not installed';
    const res = await executeSafeProcess(tools.gitleaks, ['version'], { timeoutMs: 3000 });
    return res.stdout.trim() || 'Unknown';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const tools = await ToolDiscovery.discover(options.targetDirectory);

    if (!tools.gitleaks) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'UNAVAILABLE',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'Gitleaks CLI is not installed in system PATH.'
        }
      };
    }

    try {
      const gitleaksArgs = [
        'directory',
        options.targetDirectory,
        '--no-git',
        '--report-format', 'json',
        '--report-path', '-'
      ];

      const res = await executeSafeProcess(tools.gitleaks, gitleaksArgs, {
        cwd: options.targetDirectory,
        timeoutMs: options.timeoutMs || 60000
      });

      const findings: SecurityFinding[] = [];
      if (res.stdout) {
        try {
          const results = JSON.parse(res.stdout);
          for (const item of results) {
            const relPath = path.relative(options.targetDirectory, item.File || 'unknown').replace(/\\/g, '/');
            const startLine = item.StartLine || 1;
            const ruleId = item.RuleID || 'gitleaks-secret';
            const secretVal = item.Secret || '';

            const fingerprint = generateFingerprint('SECRETS', ruleId, relPath, startLine, item.Match);

            const evidence = sanitizeFindingEvidence({
              location: {
                filePath: relPath,
                startLine,
                startColumn: item.StartColumn || 1,
                endLine: item.EndLine || startLine,
                endColumn: item.EndColumn || 1
              },
              snippet: item.Match || '',
              rawMatch: item.Match || ''
            });

            findings.push({
              fingerprint,
              title: `Gitleaks: ${item.Description || ruleId}`,
              description: `Hardcoded credential identified (${maskSecretString(secretVal)})`,
              category: 'SECRETS',
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              evidence: evidence as any,
              affectedComponent: relPath,
              references: {
                cwe: ['CWE-798', 'CWE-200'],
                owasp: ['A07:2021-Identification and Authentication Failures']
              },
              exploitPreconditions: 'Secret committed in code files.',
              impact: 'Unauthorized access to external service.',
              remediation: 'Revoke and rotate secret; replace with environment variable.',
              engineId: this.id,
              engineName: this.name,
              ruleId,
              verificationStatus: 'CONFIRMED',
              reachability: 'UNKNOWN',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        } catch {}
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
