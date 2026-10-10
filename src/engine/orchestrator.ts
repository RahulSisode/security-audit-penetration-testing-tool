import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  ScanOptions,
  ScanResult,
  SecurityFinding,
  ScannerExecutionResult,
  VulnerabilityCategory,
  ScanSummary
} from '../core/types';
import { IScanner } from '../scanners/base';
import { BuiltinSASTScanner } from '../scanners/sast/builtin-sast';
import { SemgrepScanner } from '../scanners/sast/semgrep';
import { TaintAnalysisScanner } from '../scanners/taint/engine';
import { OSVScanner } from '../scanners/sca/osv';
import { TrivySCAScanner } from '../scanners/sca/trivy';
import { BuiltinSecretsScanner } from '../scanners/secrets/builtin-secrets';
import { GitleaksScanner } from '../scanners/secrets/gitleaks';
import { BuiltinIaCScanner } from '../scanners/iac/builtin-iac';
import { CheckovScanner } from '../scanners/iac/checkov';
import { APISecurityScanner } from '../scanners/api/api-security';
import { SafeDASTScanner } from '../scanners/dast/safe-dast';
import { ZAPScanner } from '../scanners/dast/zap';
import { MemorySafetyScanner } from '../scanners/specialized/memory-safety';
import { CryptoMisuseScanner } from '../scanners/specialized/crypto-misuse';
import { LicenseComplianceScanner } from '../scanners/specialized/licenses';
import { deduplicateFindings } from '../core/deduplication';
import { SuppressionManager } from '../core/suppression';
import { computeScanCoverage } from '../core/coverage';
import { WorkspaceScanner } from '../utils/workspace';
import { logger } from '../utils/logger';

export class ScanOrchestrator {
  private scanners: IScanner[] = [];
  private suppressionManager: SuppressionManager;

  constructor(workspaceRoot?: string) {
    this.suppressionManager = new SuppressionManager(workspaceRoot);
    this.registerDefaultScanners();
  }

  private registerDefaultScanners(): void {
    this.scanners = [
      // Layer A: SAST
      new BuiltinSASTScanner(),
      new SemgrepScanner(),
      // Layer B: Taint & Data Flow
      new TaintAnalysisScanner(),
      // Layer C: SCA
      new OSVScanner(),
      new TrivySCAScanner(),
      // Layer D: Secrets
      new BuiltinSecretsScanner(),
      new GitleaksScanner(),
      // Layer E: IaC
      new BuiltinIaCScanner(),
      new CheckovScanner(),
      // Layer F: API Security
      new APISecurityScanner(),
      // Layer G: DAST
      new SafeDASTScanner(),
      new ZAPScanner(),
      // Layer H: Specialized
      new MemorySafetyScanner(),
      new CryptoMisuseScanner(),
      new LicenseComplianceScanner()
    ];
  }

  public async runScan(options: ScanOptions): Promise<ScanResult> {
    const scanId = crypto.randomUUID();
    const startTime = Date.now();
    const startedAt = new Date().toISOString();

    logger.info(`Starting Sentinel Security Scan [${scanId}] on ${options.targetDirectory}`);

    // 1. Workspace Discovery
    const discovery = WorkspaceScanner.discoverFiles(
      options.targetDirectory,
      options.maxFileSizeMb,
      options.customIgnorePatterns
    );

    const allFindings: SecurityFinding[] = [];
    const executionResults: ScannerExecutionResult[] = [];
    const checkedCategories = new Set<VulnerabilityCategory>();

    // 2. Execute Scanners Concurrently
    const scanPromises = this.scanners.map(async (scanner) => {
      try {
        const isAvailable = await scanner.isAvailable();
        if (!isAvailable) {
          executionResults.push({
            scannerId: scanner.id,
            scannerName: scanner.name,
            version: await scanner.getVersion(),
            status: 'UNAVAILABLE',
            executionTimeMs: 0,
            findingsCount: 0,
            errorMessage: `${scanner.name} is not installed or available on this platform.`
          });
          return;
        }

        const res = await scanner.scan(options);
        executionResults.push(res.executionResult);

        if (res.findings && res.findings.length > 0) {
          for (const f of res.findings) {
            allFindings.push(f);
            checkedCategories.add(f.category);
          }
        }
      } catch (err: any) {
        executionResults.push({
          scannerId: scanner.id,
          scannerName: scanner.name,
          version: 'Unknown',
          status: 'FAILED',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: err?.message || String(err)
        });
      }
    });

    await Promise.all(scanPromises);

    // 3. Finding Deduplication across multiple engines
    const deduplicated = deduplicateFindings(allFindings);

    // 4. File Map for Inline Suppression Checking
    const fileContentsMap = new Map<string, string>();
    for (const filePath of discovery.scannableFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const rel = path.relative(options.targetDirectory, filePath).replace(/\\/g, '/');
        fileContentsMap.set(filePath, content);
        fileContentsMap.set(rel, content);
      } catch {}
    }

    // 5. Apply Suppressions
    const suppressedFindings = this.suppressionManager.applySuppressions(deduplicated, fileContentsMap);

    // 6. Compute Counts & Summary
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;
    let suppressedCount = 0;

    for (const f of suppressedFindings) {
      if (f.suppression?.isSuppressed) {
        suppressedCount++;
      } else {
        switch (f.severity) {
          case 'CRITICAL': criticalCount++; break;
          case 'HIGH': highCount++; break;
          case 'MEDIUM': mediumCount++; break;
          case 'LOW': lowCount++; break;
          case 'INFO': infoCount++; break;
        }
      }
    }

    // Add standard checked categories from active built-in engines
    checkedCategories.add('INJECTION');
    checkedCategories.add('XSS');
    checkedCategories.add('PATH_TRAVERSAL');
    checkedCategories.add('SSRF');
    checkedCategories.add('DESERIALIZATION');
    checkedCategories.add('SECRETS');
    checkedCategories.add('DEPENDENCY_VULNERABILITY');
    checkedCategories.add('IAC_MISCONFIGURATION');
    checkedCategories.add('API_SECURITY');
    checkedCategories.add('CRYPTOGRAPHY');
    checkedCategories.add('MEMORY_SAFETY');
    checkedCategories.add('TAINT_FLOW');

    const durationMs = Date.now() - startTime;
    const completedAt = new Date().toISOString();

    const summary: ScanSummary = {
      totalFindings: suppressedFindings.filter(f => !f.suppression?.isSuppressed).length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      suppressedCount,
      fixedCount: 0,
      durationMs,
      startedAt,
      completedAt
    };

    const dastStatus = options.dastOptions?.enabled ? 'EXECUTED' : 'DISABLED';

    const coverage = computeScanCoverage(
      discovery.allFiles.length,
      discovery.scannableFiles.length,
      discovery.skippedFiles.length,
      discovery.totalLinesOfCode,
      discovery.languages,
      discovery.frameworks,
      executionResults,
      Array.from(checkedCategories),
      suppressedFindings,
      dastStatus
    );

    logger.info(`Sentinel Scan [${scanId}] completed in ${durationMs}ms. Found ${summary.totalFindings} active findings.`);

    return {
      scanId,
      targetDirectory: options.targetDirectory,
      summary,
      coverage,
      findings: suppressedFindings
    };
  }
}
