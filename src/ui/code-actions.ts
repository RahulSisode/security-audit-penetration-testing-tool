import * as vscode from 'vscode';
import { SecurityFinding } from '../core/types';

export class SentinelCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  private findings: SecurityFinding[] = [];

  public updateFindings(findings: SecurityFinding[]): void {
    this.findings = findings;
  }

  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const relPath = vscode.workspace.asRelativePath(document.uri).replace(/\\/g, '/');

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'Sentinel Security') continue;

      const matchingFinding = this.findings.find(
        f => f.evidence.location.filePath === relPath &&
             Math.abs((f.evidence.location.startLine || 1) - 1 - diagnostic.range.start.line) <= 1
      );

      if (matchingFinding) {
        // 1. Quick Fix Action (if proposedFix exists)
        if (matchingFinding.proposedFix && matchingFinding.proposedFix.replacementCode) {
          const fixAction = new vscode.CodeAction(
            `🛡️ Sentinel Fix: ${matchingFinding.proposedFix.description}`,
            vscode.CodeActionKind.QuickFix
          );
          fixAction.edit = new vscode.WorkspaceEdit();
          const targetRange = new vscode.Range(
            matchingFinding.proposedFix.startLine - 1,
            0,
            matchingFinding.proposedFix.endLine - 1,
            document.lineAt(matchingFinding.proposedFix.endLine - 1).text.length
          );
          fixAction.edit.replace(document.uri, targetRange, matchingFinding.proposedFix.replacementCode);
          fixAction.diagnostics = [diagnostic];
          fixAction.isPreferred = true;
          actions.push(fixAction);
        }

        // 2. Show Remediation Guidance Action
        const guideAction = new vscode.CodeAction(
          `📖 Sentinel: View Remediation Guidance (${matchingFinding.ruleId})`,
          vscode.CodeActionKind.Empty
        );
        guideAction.command = {
          command: 'sentinel.showFindingGuidance',
          title: 'Show Guidance',
          arguments: [matchingFinding]
        };
        actions.push(guideAction);

        // 3. Inline Suppression Action
        const suppressAction = new vscode.CodeAction(
          `🔒 Sentinel: Suppress Finding (Add inline ignore comment)`,
          vscode.CodeActionKind.QuickFix
        );
        suppressAction.edit = new vscode.WorkspaceEdit();
        const lineNum = Math.max(0, (matchingFinding.evidence.location.startLine || 1) - 1);
        const comment = `// sentinel-ignore-rule ${matchingFinding.ruleId} Suppressed via editor action\n`;
        suppressAction.edit.insert(document.uri, new vscode.Position(lineNum, 0), comment);
        actions.push(suppressAction);
      }
    }

    return actions;
  }
}
