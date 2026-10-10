import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions } from '../../core/types';
import { SAST_RULES, SASTRule } from './rules';
import { generateFingerprint } from '../../core/fingerprint';
import { WorkspaceScanner } from '../../utils/workspace';
import { sanitizeFindingEvidence } from '../../core/redaction';

export class BuiltinSASTScanner extends BaseScanner {
  public readonly id = 'sentinel-builtin-sast';
  public readonly name = 'Sentinel Static Code Analyzer';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in zero-dependency engine
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (Built-in Multi-Language Engine)';
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
        const ext = path.extname(filePath).toLowerCase();

        for (const rule of SAST_RULES) {
          this.evaluateRuleOnFile(rule, filePath, content, lines, workspaceRoot, findings);
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

  private evaluateRuleOnFile(
    rule: SASTRule,
    filePath: string,
    content: string,
    lines: string[],
    workspaceRoot: string,
    findings: SecurityFinding[]
  ): void {
    // Check if anti-patterns are present in content (false positive filter)
    if (rule.antiPatterns) {
      for (const anti of rule.antiPatterns) {
        if (anti.test(content)) {
          // Rule suppressed due to safe anti-pattern detected
          return;
        }
      }
    }

    for (const pattern of rule.patterns) {
      const globalRegex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      let match: RegExpExecArray | null;

      while ((match = globalRegex.exec(content)) !== null) {
        // Calculate line number
        const matchIndex = match.index;
        const lineOffset = content.substring(0, matchIndex).split('\n').length;
        const startLine = lineOffset;
        const currentLineText = lines[startLine - 1] || '';
        const startColumn = currentLineText.indexOf(match[0].trim()) + 1 || 1;

        // Context lines
        const contextBefore = lines.slice(Math.max(0, startLine - 3), startLine - 1);
        const contextAfter = lines.slice(startLine, Math.min(lines.length, startLine + 3));

        const relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');
        const fingerprint = generateFingerprint(rule.category, rule.id, relPath, startLine, match[0]);

        const evidence = sanitizeFindingEvidence({
          location: {
            filePath: relPath,
            startLine,
            startColumn,
            endLine: startLine + match[0].split('\n').length - 1,
            endColumn: startColumn + match[0].length
          },
          snippet: currentLineText.trim(),
          rawMatch: match[0],
          contextLinesBefore: contextBefore,
          contextLinesAfter: contextAfter
        });

        let proposedFix;
        if (rule.generateFix) {
          try {
            const fixResult = rule.generateFix(currentLineText, match);
            proposedFix = {
              description: `Fix: ${rule.name}`,
              replacementCode: fixResult.replacement,
              patchDiff: `- ${currentLineText}\n+ ${fixResult.replacement}`,
              targetFile: relPath,
              startLine,
              endLine: startLine,
              isDeterministic: true,
              requiresManualReview: true,
              explanation: fixResult.explanation
            };
          } catch {}
        }

        findings.push({
          fingerprint,
          title: rule.name,
          description: rule.description,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          evidence: evidence as any,
          affectedComponent: relPath,
          references: {
            cwe: rule.cwe,
            owasp: rule.owasp,
            cvss: rule.cvss,
            urls: rule.cwe.map(c => `https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html`)
          },
          exploitPreconditions: rule.exploitPreconditions,
          impact: rule.impact,
          remediation: rule.remediation,
          proposedFix,
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
