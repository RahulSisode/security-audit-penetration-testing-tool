import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity } from '../../core/types';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';

export class CheckovScanner extends BaseScanner {
  public readonly id = 'checkov';
  public readonly name = 'Checkov Infrastructure Policy Scanner';

  public async isAvailable(): Promise<boolean> {
    const tools = await ToolDiscovery.discover();
    return !!tools.checkov;
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (!tools.checkov) return 'Not installed';
    const res = await executeSafeProcess(tools.checkov, ['-v'], { timeoutMs: 3000 });
    return res.stdout.trim() || 'Unknown';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const tools = await ToolDiscovery.discover(options.targetDirectory);

    if (!tools.checkov) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'UNAVAILABLE',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'Checkov CLI is not installed in system PATH.'
        }
      };
    }

    try {
      const checkovArgs = ['-d', options.targetDirectory, '--output', 'json', '--quiet', '--compact'];
      const res = await executeSafeProcess(tools.checkov, checkovArgs, {
        cwd: options.targetDirectory,
        timeoutMs: options.timeoutMs || 120000
      });

      const findings: SecurityFinding[] = [];
      if (res.stdout) {
        try {
          const parsed = JSON.parse(res.stdout);
          const reports = Array.isArray(parsed) ? parsed : [parsed];

          for (const report of reports) {
            const checks = report.results?.failed_checks || [];
            for (const c of checks) {
              const relPath = path.relative(options.targetDirectory, c.file_path || 'iac').replace(/\\/g, '/');
              const startLine = c.file_line_range?.[0] || 1;
              const ruleId = c.check_id || 'CKV_CHECK';

              const fingerprint = generateFingerprint('IAC_MISCONFIGURATION', ruleId, relPath, startLine, c.check_name);

              findings.push({
                fingerprint,
                title: `${ruleId}: ${c.check_name}`,
                description: c.guideline || c.check_name || 'Infrastructure misconfiguration detected.',
                category: 'IAC_MISCONFIGURATION',
                severity: this.mapSeverity(c.severity),
                confidence: 'CONFIRMED',
                evidence: {
                  location: { filePath: relPath, startLine },
                  snippet: c.code_block?.map((cb: any) => cb[1]).join('\n') || c.resource
                },
                affectedComponent: relPath,
                references: {
                  cwe: ['CWE-250', 'CWE-732'],
                  urls: c.guideline ? [c.guideline] : []
                },
                exploitPreconditions: 'Cloud resource deployed with misconfiguration.',
                impact: c.check_name,
                remediation: c.guideline ? `Consult guidelines: ${c.guideline}` : 'Review and apply least privilege configuration.',
                engineId: this.id,
                engineName: this.name,
                ruleId,
                verificationStatus: 'CONFIRMED',
                reachability: 'UNKNOWN',
                firstDetectedAt: new Date().toISOString(),
                lastDetectedAt: new Date().toISOString()
              });
            }
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

  private mapSeverity(sev?: string): Severity {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      default: return 'MEDIUM';
    }
  }
}
