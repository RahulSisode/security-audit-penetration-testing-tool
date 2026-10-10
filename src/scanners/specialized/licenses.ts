import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { ManifestParser } from '../sca/manifest-parser';
import { generateFingerprint } from '../../core/fingerprint';

const DEFAULT_PROHIBITED_LICENSES = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'SSPL-1.0', 'EUPL-1.2'];

export class LicenseComplianceScanner extends BaseScanner {
  public readonly id = 'sentinel-license-policy';
  public readonly name = 'Sentinel Supply Chain License Policy Auditor';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (SPDX License Policy Engine)';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];
    const workspaceRoot = options.targetDirectory;

    try {
      const prohibited = new Set(
        (options.licensePolicy?.prohibitedLicenses || DEFAULT_PROHIBITED_LICENSES).map(l => l.toUpperCase())
      );

      const packages = ManifestParser.parseAll(workspaceRoot);

      for (const pkg of packages) {
        if (pkg.license && prohibited.has(pkg.license.toUpperCase())) {
          const fingerprint = generateFingerprint('LICENSE_VIOLATION', 'SENTINEL-LIC-POLICY', pkg.manifestPath, 1, `${pkg.name}@${pkg.license}`);

          findings.push({
            fingerprint,
            title: `Prohibited Copyleft / Reciprocal License: ${pkg.name} (${pkg.license})`,
            description: `Dependency '${pkg.name}' uses license '${pkg.license}' which is prohibited under the active software supply-chain policy.`,
            category: 'LICENSE_VIOLATION',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            evidence: {
              location: { filePath: pkg.manifestPath, startLine: 1 },
              snippet: `Package: ${pkg.name}@${pkg.version}, License: ${pkg.license}`
            },
            affectedComponent: `${pkg.name}@${pkg.version}`,
            references: {
              urls: [`https://spdx.org/licenses/${pkg.license}.html`]
            },
            exploitPreconditions: 'Application distributed with strong copyleft dependencies.',
            impact: 'Legal liability or forced source-code disclosure under reciprocal licensing terms.',
            remediation: `Replace ${pkg.name} with a permissively licensed alternative (e.g., MIT, Apache-2.0, BSD-3-Clause).`,
            engineId: this.id,
            engineName: this.name,
            ruleId: 'SENTINEL-LIC-POLICY',
            verificationStatus: 'CONFIRMED',
            reachability: 'UNKNOWN',
            firstDetectedAt: new Date().toISOString(),
            lastDetectedAt: new Date().toISOString()
          });
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
