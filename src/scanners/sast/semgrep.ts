import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity, Confidence } from '../../core/types';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence } from '../../core/redaction';

export class SemgrepScanner extends BaseScanner {
  public readonly id = 'semgrep';
  public readonly name = 'Semgrep Static Analyzer';

  public async isAvailable(): Promise<boolean> {
    const tools = await ToolDiscovery.discover();
    return !!tools.semgrep;
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (!tools.semgrep) return 'Not installed';
    const res = await executeSafeProcess(tools.semgrep, ['--version'], { timeoutMs: 5000 });
    return res.stdout.trim() || 'Unknown';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const tools = await ToolDiscovery.discover(options.targetDirectory);

    if (!tools.semgrep) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'UNAVAILABLE',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'Semgrep CLI is not installed or not found in PATH.'
        }
      };
    }

    try {
      const semgrepArgs = [
        'scan',
        '--json',
        '--quiet',
        '--config', 'auto',
        '--metrics=off',
        '--disable-version-check',
        options.targetDirectory
      ];

      const res = await executeSafeProcess(tools.semgrep, semgrepArgs, {
        cwd: options.targetDirectory,
        timeoutMs: options.timeoutMs || 120000
      });

      if (res.timedOut) {
        return {
          findings: [],
          executionResult: {
            scannerId: this.id,
            scannerName: this.name,
            version: await this.getVersion(),
            status: 'FAILED',
            executionTimeMs: Date.now() - startTime,
            findingsCount: 0,
            errorMessage: 'Semgrep scan timed out.'
          }
        };
      }

      const findings: SecurityFinding[] = [];
      if (res.stdout) {
        try {
          const parsed = JSON.parse(res.stdout);
          const results = parsed.results || [];

          for (const item of results) {
            const relPath = path.relative(options.targetDirectory, item.path).replace(/\\/g, '/');
            const startLine = item.start?.line || 1;
            const startCol = item.start?.col || 1;
            const endLine = item.end?.line || startLine;
            const endCol = item.end?.col || startCol;
            const ruleId = item.check_id || 'semgrep-rule';
            const rawMessage = item.extra?.message || 'Semgrep finding';
            const severity = this.mapSeverity(item.extra?.severity);

            const fingerprint = generateFingerprint('INJECTION', ruleId, relPath, startLine, item.extra?.lines);

            const evidence = sanitizeFindingEvidence({
              location: {
                filePath: relPath,
                startLine,
                startColumn: startCol,
                endLine,
                endColumn: endCol
              },
              snippet: item.extra?.lines?.trim() || '',
              rawMatch: item.extra?.lines || ''
            });

            findings.push({
              fingerprint,
              title: item.extra?.metadata?.shortlink || ruleId,
              description: rawMessage,
              category: 'INJECTION',
              severity,
              confidence: 'HIGH',
              evidence: evidence as any,
              affectedComponent: relPath,
              references: {
                cwe: item.extra?.metadata?.cwe ? (Array.isArray(item.extra.metadata.cwe) ? item.extra.metadata.cwe : [item.extra.metadata.cwe]) : [],
                owasp: item.extra?.metadata?.owasp ? (Array.isArray(item.extra.metadata.owasp) ? item.extra.metadata.owasp : [item.extra.metadata.owasp]) : [],
                urls: item.extra?.metadata?.references || []
              },
              exploitPreconditions: 'Code pattern matches security-critical rule condition.',
              impact: rawMessage,
              remediation: item.extra?.fix || 'Review and sanitize parameter usage.',
              engineId: this.id,
              engineName: this.name,
              ruleId,
              verificationStatus: 'CONFIRMED',
              reachability: 'UNKNOWN',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        } catch (parseErr: any) {
          // If JSON parse failed
          return {
            findings: [],
            executionResult: {
              scannerId: this.id,
              scannerName: this.name,
              status: 'FAILED',
              executionTimeMs: Date.now() - startTime,
              findingsCount: 0,
              errorMessage: `Failed to parse Semgrep JSON output: ${parseErr.message}`
            }
          };
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
          findingsCount: findings.length,
          commandExecuted: `${tools.semgrep} ${semgrepArgs.join(' ')}`
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

  private mapSeverity(sev: string): Severity {
    switch ((sev || '').toUpperCase()) {
      case 'ERROR': return 'CRITICAL';
      case 'WARNING': return 'HIGH';
      case 'INFO': return 'MEDIUM';
      default: return 'MEDIUM';
    }
  }
}
