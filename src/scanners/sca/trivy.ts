import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity } from '../../core/types';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';

export class TrivySCAScanner extends BaseScanner {
  public readonly id = 'trivy-sca';
  public readonly name = 'Trivy Supply Chain & Vulnerability Scanner';

  public async isAvailable(): Promise<boolean> {
    const tools = await ToolDiscovery.discover();
    return !!tools.trivy;
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (!tools.trivy) return 'Not installed';
    const res = await executeSafeProcess(tools.trivy, ['--version'], { timeoutMs: 3000 });
    return res.stdout.trim() || 'Unknown';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const tools = await ToolDiscovery.discover(options.targetDirectory);

    if (!tools.trivy) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'UNAVAILABLE',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'Trivy CLI is not installed in system PATH.'
        }
      };
    }

    try {
      const trivyArgs = ['fs', '--format', 'json', '--scanners', 'vuln', '--quiet', options.targetDirectory];
      const res = await executeSafeProcess(tools.trivy, trivyArgs, {
        cwd: options.targetDirectory,
        timeoutMs: options.timeoutMs || 120000
      });

      const findings: SecurityFinding[] = [];
      if (res.stdout) {
        try {
          const parsed = JSON.parse(res.stdout);
          const results = parsed.Results || [];

          for (const result of results) {
            const targetFile = path.relative(options.targetDirectory, result.Target || 'manifest').replace(/\\/g, '/');
            const vulns = result.Vulnerabilities || [];

            for (const v of vulns) {
              const ruleId = v.VulnerabilityID || 'TRIVY-VULN';
              const pkgName = v.PkgName || 'unknown';
              const installedVer = v.InstalledVersion || '0.0.0';
              const fixedVer = v.FixedVersion;
              const severity = this.mapSeverity(v.Severity);

              const fingerprint = generateFingerprint('DEPENDENCY_VULNERABILITY', ruleId, targetFile, 1, `${pkgName}@${installedVer}`);

              findings.push({
                fingerprint,
                title: `${pkgName}@${installedVer}: ${v.Title || ruleId}`,
                description: v.Description || 'Known security vulnerability in dependency.',
                category: 'DEPENDENCY_VULNERABILITY',
                severity,
                confidence: 'CONFIRMED',
                evidence: {
                  location: { filePath: targetFile, startLine: 1 },
                  snippet: `${pkgName}: ${installedVer} -> ${fixedVer || 'No fix available'}`
                },
                affectedComponent: `${pkgName}@${installedVer}`,
                references: {
                  cve: [ruleId],
                  cwe: v.CweIDs || [],
                  cvss: v.CVSS?.nvd?.V3Score || v.CVSS?.redhat?.V3Score,
                  urls: v.References || []
                },
                exploitPreconditions: `Application references dependency ${pkgName}@${installedVer}.`,
                impact: v.Description || 'Vulnerability in third-party library.',
                remediation: fixedVer ? `Upgrade ${pkgName} to version ${fixedVer} or higher.` : 'Check for vendor patches or alternative libraries.',
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
        } catch (parseErr: any) {
          return {
            findings: [],
            executionResult: {
              scannerId: this.id,
              scannerName: this.name,
              status: 'FAILED',
              executionTimeMs: Date.now() - startTime,
              findingsCount: 0,
              errorMessage: `Trivy JSON output parse failure: ${parseErr.message}`
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

  private mapSeverity(sev: string): Severity {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      default: return 'INFO';
    }
  }
}
