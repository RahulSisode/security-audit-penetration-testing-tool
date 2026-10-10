import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding, FindingSuppression } from './types';

export interface SuppressionRule {
  fingerprint?: string;
  ruleId?: string;
  filePath?: string;
  category?: string;
  justification: string;
  suppressedBy: string;
  expiresAt?: string;
}

export class SuppressionManager {
  private suppressions: SuppressionRule[] = [];

  constructor(workspaceDir?: string) {
    if (workspaceDir) {
      this.loadSuppressions(workspaceDir);
    }
  }

  public loadSuppressions(workspaceDir: string): void {
    const configPath = path.join(workspaceDir, '.sentinel-suppressions.json');
    if (fs.existsSync(configPath)) {
      try {
        const data = fs.readFileSync(configPath, 'utf8');
        this.suppressions = JSON.parse(data);
      } catch (e) {
        console.error('Failed to parse .sentinel-suppressions.json:', e);
      }
    }
  }

  public applySuppressions(findings: SecurityFinding[], fileContentsMap?: Map<string, string>): SecurityFinding[] {
    const now = new Date();

    for (const finding of findings) {
      // 1. Check file-level inline ignore comments
      if (fileContentsMap && fileContentsMap.has(finding.evidence.location.filePath)) {
        const content = fileContentsMap.get(finding.evidence.location.filePath)!;
        const lines = content.split('\n');
        const targetLineIdx = finding.evidence.location.startLine - 1;

        // Check line itself or line above
        const checkLines = [lines[targetLineIdx], targetLineIdx > 0 ? lines[targetLineIdx - 1] : ''];
        for (const line of checkLines) {
          if (line && (line.includes('sentinel-ignore') || line.includes('sentinel-disable'))) {
            if (
              line.includes(finding.ruleId) ||
              line.includes(finding.category) ||
              line.includes('all')
            ) {
              finding.suppression = {
                isSuppressed: true,
                justification: 'Suppressed via inline comment in code',
                suppressedBy: 'inline-comment',
                suppressedAt: now.toISOString()
              };
              break;
            }
          }
        }
      }

      // 2. Check JSON config suppressions
      if (!finding.suppression?.isSuppressed) {
        for (const sup of this.suppressions) {
          if (sup.expiresAt && new Date(sup.expiresAt) < now) {
            continue; // expired
          }

          if (
            (sup.fingerprint && sup.fingerprint === finding.fingerprint) ||
            (sup.ruleId && sup.ruleId === finding.ruleId && (!sup.filePath || finding.evidence.location.filePath.includes(sup.filePath))) ||
            (sup.category && sup.category === finding.category && (!sup.filePath || finding.evidence.location.filePath.includes(sup.filePath)))
          ) {
            finding.suppression = {
              isSuppressed: true,
              justification: sup.justification,
              suppressedBy: sup.suppressedBy,
              suppressedAt: now.toISOString()
            };
            break;
          }
        }
      }
    }

    return findings;
  }
}
