import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { WorkspaceScanner } from '../../utils/workspace';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence } from '../../core/redaction';

interface MemorySafetyRule {
  id: string;
  name: string;
  pattern: RegExp;
  description: string;
  cwe: string[];
  remediation: string;
}

const MEMORY_RULES: MemorySafetyRule[] = [
  {
    id: 'SENTINEL-MEM-DOUBLE-FREE',
    name: 'Potential Double-Free Vulnerability',
    pattern: /free\s*\(\s*([a-zA-Z0-9_]+)\s*\);[\s\S]*?free\s*\(\s*\1\s*\);/g,
    description: 'Freeing the same pointer twice without setting it to NULL leads to heap corruption and code execution.',
    cwe: ['CWE-415'],
    remediation: 'Set pointer to NULL immediately after freeing (ptr = NULL;) or use modern smart pointers (std::unique_ptr).'
  },
  {
    id: 'SENTINEL-MEM-UNCHECKED-MALLOC',
    name: 'Unchecked malloc / calloc Return Value',
    pattern: /([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_*]+\)\s*)?malloc\s*\([^)]+\);(?!\s*if\s*\(\s*\1\s*(?:==|!=)\s*NULL)/g,
    description: 'malloc return value used without checking for NULL allocation failure.',
    cwe: ['CWE-476'],
    remediation: 'Always verify if (ptr == NULL) before dereferencing memory.'
  },
  {
    id: 'SENTINEL-MEM-USE-AFTER-FREE',
    name: 'Use-After-Free Pattern',
    pattern: /free\s*\(\s*([a-zA-Z0-9_]+)\s*\);[\s\S]{1,100}?\1\s*->/g,
    description: 'Dereferencing pointer member after it has been deallocated with free().',
    cwe: ['CWE-416'],
    remediation: 'Avoid accessing heap memory after releasing it; reset pointer to NULL.'
  }
];

export class MemorySafetyScanner extends BaseScanner {
  public readonly id = 'sentinel-memory-safety';
  public readonly name = 'Sentinel Native Memory Safety Analyzer';

  public async isAvailable(): Promise<boolean> {
    return true; // Built-in C/C++ memory safety engine
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (C/C++ Memory Defect & Pointer Engine)';
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

      const nativeFiles = discovery.scannableFiles.filter(f => {
        const ext = path.extname(f).toLowerCase();
        return ['.c', '.cpp', '.cc', '.h', '.hpp'].includes(ext);
      });

      for (const filePath of nativeFiles) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        const relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');

        for (const rule of MEMORY_RULES) {
          const globalRegex = new RegExp(rule.pattern.source, 'g');
          let match: RegExpExecArray | null;

          while ((match = globalRegex.exec(content)) !== null) {
            const startLine = content.substring(0, match.index).split('\n').length;
            const lineText = lines[startLine - 1] || '';
            const fingerprint = generateFingerprint('MEMORY_SAFETY', rule.id, relPath, startLine, match[0]);

            const evidence = sanitizeFindingEvidence({
              location: { filePath: relPath, startLine },
              snippet: lineText.trim(),
              rawMatch: match[0]
            });

            findings.push({
              fingerprint,
              title: rule.name,
              description: rule.description,
              category: 'MEMORY_SAFETY',
              severity: 'HIGH',
              confidence: 'HIGH',
              evidence: evidence as any,
              affectedComponent: relPath,
              references: {
                cwe: rule.cwe,
                owasp: ['A04:2021-Insecure Design']
              },
              exploitPreconditions: 'Native binary execution under memory pressure or crafted heap conditions.',
              impact: 'Application crash, heap corruption, potential arbitrary code execution.',
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
