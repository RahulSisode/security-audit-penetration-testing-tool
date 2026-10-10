import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding } from './types';

export interface BaselineComparison {
  newFindings: SecurityFinding[];
  fixedFindings: SecurityFinding[];
  existingFindings: SecurityFinding[];
}

export class BaselineManager {
  public static saveBaseline(workspaceDir: string, findings: SecurityFinding[]): string {
    const baselinePath = path.join(workspaceDir, '.sentinel-baseline.json');
    const data = JSON.stringify({
      timestamp: new Date().toISOString(),
      findings
    }, null, 2);
    fs.writeFileSync(baselinePath, data, 'utf8');
    return baselinePath;
  }

  public static loadBaseline(workspaceDir: string): SecurityFinding[] | null {
    const baselinePath = path.join(workspaceDir, '.sentinel-baseline.json');
    if (fs.existsSync(baselinePath)) {
      try {
        const raw = fs.readFileSync(baselinePath, 'utf8');
        const parsed = JSON.parse(raw);
        return parsed.findings || [];
      } catch {
        return null;
      }
    }
    return null;
  }

  public static compare(currentFindings: SecurityFinding[], baselineFindings: SecurityFinding[]): BaselineComparison {
    const currentMap = new Map(currentFindings.map(f => [f.fingerprint, f]));
    const baselineMap = new Map(baselineFindings.map(f => [f.fingerprint, f]));

    const newFindings: SecurityFinding[] = [];
    const existingFindings: SecurityFinding[] = [];
    const fixedFindings: SecurityFinding[] = [];

    for (const current of currentFindings) {
      if (baselineMap.has(current.fingerprint)) {
        existingFindings.push(current);
      } else {
        newFindings.push(current);
      }
    }

    for (const baseline of baselineFindings) {
      if (!currentMap.has(baseline.fingerprint)) {
        fixedFindings.push(baseline);
      }
    }

    return {
      newFindings,
      fixedFindings,
      existingFindings
    };
  }
}
