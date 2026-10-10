import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityFinding, Severity } from '../core/types';

export class SentinelDiagnosticsManager {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel-security');
  }

  public updateDiagnostics(findings: SecurityFinding[], workspaceRoot: string): void {
    this.diagnosticCollection.clear();
    const map = new Map<string, vscode.Diagnostic[]>();

    for (const f of findings) {
      if (f.suppression?.isSuppressed) continue;

      const fullPath = path.isAbsolute(f.evidence.location.filePath)
        ? f.evidence.location.filePath
        : path.join(workspaceRoot, f.evidence.location.filePath);

      const startLine = Math.max(0, (f.evidence.location.startLine || 1) - 1);
      const startCol = Math.max(0, (f.evidence.location.startColumn || 1) - 1);
      const endLine = Math.max(0, (f.evidence.location.endLine || f.evidence.location.startLine || 1) - 1);
      const endCol = Math.max(0, (f.evidence.location.endColumn || 80) - 1);

      const range = new vscode.Range(startLine, startCol, endLine, endCol);
      const severity = this.mapToVsCodeSeverity(f.severity);

      const diag = new vscode.Diagnostic(
        range,
        `[Sentinel: ${f.severity}] ${f.title}\n${f.description}\nRule: ${f.ruleId} (${f.engineName})`,
        severity
      );

      diag.code = f.ruleId;
      diag.source = 'Sentinel Security';

      if (!map.has(fullPath)) {
        map.set(fullPath, []);
      }
      map.get(fullPath)!.push(diag);
    }

    for (const [filePath, diags] of map.entries()) {
      const uri = vscode.Uri.file(filePath);
      this.diagnosticCollection.set(uri, diags);
    }
  }

  public clear(): void {
    this.diagnosticCollection.clear();
  }

  public dispose(): void {
    this.diagnosticCollection.dispose();
  }

  private mapToVsCodeSeverity(sev: Severity): vscode.DiagnosticSeverity {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return vscode.DiagnosticSeverity.Error;
      case 'MEDIUM':
        return vscode.DiagnosticSeverity.Warning;
      case 'LOW':
        return vscode.DiagnosticSeverity.Information;
      case 'INFO':
        return vscode.DiagnosticSeverity.Hint;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }
}
