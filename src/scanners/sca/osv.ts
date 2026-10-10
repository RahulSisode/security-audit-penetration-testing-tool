import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { ManifestParser } from './manifest-parser';
import { KNOWN_OFFLINE_ADVISORIES, SCAReachabilityAnalyzer } from './advisories';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';
import { WorkspaceScanner } from '../../utils/workspace';

export class OSVScanner extends BaseScanner {
  public readonly id = 'sentinel-osv-sca';
  public readonly name = 'Sentinel Software Supply Chain & Dependency Analyzer (OSV)';

  public async isAvailable(): Promise<boolean> {
    return true; // Zero-API built-in + CLI hybrid
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (tools.osvScanner) {
      const res = await executeSafeProcess(tools.osvScanner, ['--version'], { timeoutMs: 3000 });
      return `OSV-Scanner CLI (${res.stdout.trim() || 'v1.7.0'}) + Built-in Database`;
    }
    return '1.0.0 (Offline CVE Advisory Engine)';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];
    const workspaceRoot = options.targetDirectory;

    try {
      // 1. Discover all packages in workspace
      const packages = ManifestParser.parseAll(workspaceRoot);
      const discovery = WorkspaceScanner.discoverFiles(workspaceRoot);

      // Check external CLI first if available
      const tools = await ToolDiscovery.discover(workspaceRoot);
      if (tools.osvScanner) {
        const cliRes = await executeSafeProcess(tools.osvScanner, ['--json', '-r', workspaceRoot], {
          cwd: workspaceRoot,
          timeoutMs: options.timeoutMs || 60000
        });

        if (cliRes.exitCode === 0 || (cliRes.exitCode === 1 && cliRes.stdout)) {
          try {
            const parsed = JSON.parse(cliRes.stdout);
            const results = parsed.results || [];
            for (const r of results) {
              const relPath = path.relative(workspaceRoot, r.source?.path || 'manifest').replace(/\\/g, '/');
              for (const pkg of r.packages || []) {
                for (const vuln of pkg.vulnerabilities || []) {
                  const pkgName = pkg.package?.name || 'unknown';
                  const pkgVer = pkg.package?.version || 'unknown';
                  const reachability = SCAReachabilityAnalyzer.isPackageReachable(pkgName, workspaceRoot, discovery.scannableFiles);

                  const fingerprint = generateFingerprint('DEPENDENCY_VULNERABILITY', vuln.id, relPath, 1, `${pkgName}@${pkgVer}`);

                  findings.push({
                    fingerprint,
                    title: `Vulnerable Dependency: ${pkgName}@${pkgVer} (${vuln.id})`,
                    description: vuln.summary || vuln.details || 'Known vulnerability in dependency.',
                    category: 'DEPENDENCY_VULNERABILITY',
                    severity: vuln.database_specific?.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
                    confidence: 'CONFIRMED',
                    evidence: {
                      location: { filePath: relPath, startLine: 1 },
                      snippet: `Dependency "${pkgName}": "${pkgVer}" in ${relPath}`
                    },
                    affectedComponent: `${pkgName}@${pkgVer}`,
                    references: {
                      cve: vuln.aliases || [vuln.id],
                      urls: vuln.references?.map((ref: any) => ref.url) || []
                    },
                    exploitPreconditions: `Application utilizes vulnerable package ${pkgName}@${pkgVer}.`,
                    impact: vuln.details || 'Vulnerability in third-party library.',
                    remediation: `Upgrade ${pkgName} to a patched release.`,
                    engineId: this.id,
                    engineName: this.name,
                    ruleId: vuln.id,
                    verificationStatus: 'CONFIRMED',
                    reachability: reachability.reachable,
                    reachabilityEvidence: reachability.evidence,
                    firstDetectedAt: new Date().toISOString(),
                    lastDetectedAt: new Date().toISOString()
                  });
                }
              }
            }
          } catch {}
        }
      }

      // 2. Scan using built-in offline advisory database (provides guaranteed baseline even without CLI or network)
      for (const pkg of packages) {
        for (const adv of KNOWN_OFFLINE_ADVISORIES) {
          if (adv.packageName.toLowerCase() === pkg.name.toLowerCase()) {
            if (SCAReachabilityAnalyzer.compareSemver(pkg.version, adv.vulnerableVersionRange)) {
              const reachability = SCAReachabilityAnalyzer.isPackageReachable(pkg.name, workspaceRoot, discovery.scannableFiles);
              const fingerprint = generateFingerprint('DEPENDENCY_VULNERABILITY', adv.id, pkg.manifestPath, 1, `${pkg.name}@${pkg.version}`);

              // Deduplicate if CLI already reported it
              if (!findings.some(f => f.fingerprint === fingerprint)) {
                findings.push({
                  fingerprint,
                  title: `Vulnerable Dependency: ${pkg.name}@${pkg.version} (${adv.cve})`,
                  description: adv.description,
                  category: 'DEPENDENCY_VULNERABILITY',
                  severity: adv.severity,
                  confidence: 'CONFIRMED',
                  evidence: {
                    location: { filePath: pkg.manifestPath, startLine: 1 },
                    snippet: `"${pkg.name}": "${pkg.version}" (${pkg.isDirect ? 'Direct' : 'Transitive'})`
                  },
                  affectedComponent: `${pkg.name}@${pkg.version}`,
                  references: {
                    cve: [adv.cve],
                    cwe: adv.cwe,
                    cvss: adv.cvss,
                    urls: [`https://nvd.nist.gov/vuln/detail/${adv.cve}`]
                  },
                  exploitPreconditions: `Installed version ${pkg.version} matches vulnerable range ${adv.vulnerableVersionRange}.`,
                  impact: `Exploitation of ${adv.cve}: ${adv.title}`,
                  remediation: `Upgrade ${pkg.name} to version ${adv.fixedVersion} or higher in ${pkg.manifestPath}.`,
                  proposedFix: {
                    description: `Upgrade ${pkg.name} to ${adv.fixedVersion}`,
                    replacementCode: `"${pkg.name}": "^${adv.fixedVersion}"`,
                    patchDiff: `- "${pkg.name}": "${pkg.version}"\n+ "${pkg.name}": "^${adv.fixedVersion}"`,
                    targetFile: pkg.manifestPath,
                    startLine: 1,
                    endLine: 1,
                    isDeterministic: true,
                    requiresManualReview: true,
                    explanation: `Upgrades vulnerable dependency ${pkg.name} from ${pkg.version} to patched version ${adv.fixedVersion}.`
                  },
                  engineId: this.id,
                  engineName: this.name,
                  ruleId: adv.id,
                  verificationStatus: 'CONFIRMED',
                  reachability: reachability.reachable,
                  reachabilityEvidence: reachability.evidence,
                  firstDetectedAt: new Date().toISOString(),
                  lastDetectedAt: new Date().toISOString()
                });
              }
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
          version: await this.getVersion(),
          status: 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: err?.message || String(err)
        }
      };
    }
  }
}
