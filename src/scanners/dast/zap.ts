import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity } from '../../core/types';
import { ToolDiscovery } from '../discovery';
import { executeSafeProcess } from '../../utils/process';
import { generateFingerprint } from '../../core/fingerprint';

export class ZAPScanner extends BaseScanner {
  public readonly id = 'owasp-zap';
  public readonly name = 'OWASP ZAP Dynamic Scanner';

  public async isAvailable(): Promise<boolean> {
    const tools = await ToolDiscovery.discover();
    return !!tools.zap;
  }

  public async getVersion(): Promise<string> {
    const tools = await ToolDiscovery.discover();
    if (!tools.zap) return 'Not installed';
    return 'OWASP ZAP Dynamic Engine';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const tools = await ToolDiscovery.discover(options.targetDirectory);

    if (!options.dastOptions?.enabled || !options.dastOptions.targetUrl) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'SKIPPED',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'DAST is optional and was not explicitly authorized/enabled.'
        }
      };
    }

    if (!tools.zap) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          status: 'UNAVAILABLE',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'OWASP ZAP CLI is not installed in system PATH.'
        }
      };
    }

    try {
      const zapArgs = ['-cmd', '-quickurl', options.dastOptions.targetUrl, '-quickout', 'zap_report.json'];
      const res = await executeSafeProcess(tools.zap, zapArgs, {
        timeoutMs: (options.dastOptions.timeoutSeconds || 120) * 1000
      });

      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: res.exitCode === 0 ? 'EXECUTED' : 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0
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
