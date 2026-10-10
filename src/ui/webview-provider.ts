import * as vscode from 'vscode';
import * as path from 'path';
import { ScanResult, SecurityFinding } from '../core/types';
import { HTMLExporter } from '../exporters/html';
import { SARIFExporter } from '../exporters/sarif';
import { JSONExporter } from '../exporters/json';
import { MarkdownExporter } from '../exporters/markdown';
import { OllamaClient } from '../ai/ollama';

export class SentinelDashboardPanel {
  public static currentPanel: SentinelDashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private result: ScanResult | null = null;
  private ollama: OllamaClient;

  public static createOrShow(extensionUri: vscode.Uri, result?: ScanResult): SentinelDashboardPanel {
    const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;

    if (SentinelDashboardPanel.currentPanel) {
      SentinelDashboardPanel.currentPanel.panel.reveal(column);
      if (result) {
        SentinelDashboardPanel.currentPanel.update(result);
      }
      return SentinelDashboardPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'sentinelDashboard',
      'Sentinel Security Dashboard',
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true
      }
    );

    SentinelDashboardPanel.currentPanel = new SentinelDashboardPanel(panel, extensionUri, result);
    return SentinelDashboardPanel.currentPanel;
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, result?: ScanResult) {
    this.panel = panel;
    this.result = result || null;
    this.ollama = new OllamaClient();

    this.updateWebviewContent();

    this.panel.onDidDispose(() => {
      SentinelDashboardPanel.currentPanel = undefined;
    });

    this.panel.webview.onDidReceiveMessage(async (message) => {
      switch (message.command) {
        case 'triggerFullScan':
          vscode.commands.executeCommand('sentinel.fullScan');
          break;
        case 'exportSARIF':
          vscode.commands.executeCommand('sentinel.exportSARIF');
          break;
        case 'exportHTML':
          vscode.commands.executeCommand('sentinel.exportHTML');
          break;
        case 'openFile':
          this.openFindingFile(message.filePath, message.line);
          break;
        case 'applyFix':
          if (this.result) {
            const finding = this.result.findings.find(f => f.fingerprint === message.fingerprint);
            if (finding) {
              vscode.commands.executeCommand('sentinel.applyAndVerifyFix', finding);
            }
          }
          break;
        case 'showGuidance':
          if (this.result) {
            const finding = this.result.findings.find(f => f.fingerprint === message.fingerprint);
            if (finding) {
              vscode.commands.executeCommand('sentinel.showFindingGuidance', finding);
            }
          }
          break;
        case 'askOllama':
          if (this.result) {
            const finding = this.result.findings.find(f => f.fingerprint === message.fingerprint);
            if (finding) {
              const explanation = await this.ollama.explainAndSuggestFix(finding);
              this.panel.webview.postMessage({
                command: 'ollamaResponse',
                fingerprint: message.fingerprint,
                data: explanation
              });
            }
          }
          break;
      }
    });
  }

  private openFindingFile(filePath: string, line: number) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) return;
    const fullPath = path.isAbsolute(filePath)
      ? filePath
      : path.join(workspaceFolders[0].uri.fsPath, filePath);

    const uri = vscode.Uri.file(fullPath);
    vscode.workspace.openTextDocument(uri).then(doc => {
      vscode.window.showTextDocument(doc).then(editor => {
        const lineIdx = Math.max(0, line - 1);
        const range = new vscode.Range(lineIdx, 0, lineIdx, 0);
        editor.selection = new vscode.Selection(lineIdx, 0, lineIdx, 0);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
      });
    });
  }

  public update(result: ScanResult): void {
    this.result = result;
    this.updateWebviewContent();
  }

  private updateWebviewContent(): void {
    if (!this.result) {
      this.panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b0e14; color: #e6edf3; padding: 60px 20px; text-align: center; }
            .card { max-width: 480px; margin: 0 auto; background: #151b23; border: 1px solid #30363d; border-radius: 12px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
            .btn { padding: 12px 24px; background: #2f81f7; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; margin-top: 16px; }
            .btn:hover { background: #388bfd; }
          </style>
        </head>
        <body>
          <div class="card">
            <div style="font-size: 48px; margin-bottom: 12px;">🛡️</div>
            <h2 style="margin: 0 0 8px 0; color: #ffffff;">Sentinel Security Dashboard</h2>
            <p style="color: #8b949e; font-size: 14px; margin: 0;">Ready to scan your workspace with zero API keys required.</p>
            <button class="btn" onclick="triggerScan()">⚡ Run Full Security Scan</button>
          </div>
          <script>
            const vscode = acquireVsCodeApi();
            function triggerScan() { vscode.postMessage({ command: 'triggerFullScan' }); }
          </script>
        </body>
        </html>
      `;
      return;
    }

    this.panel.webview.html = HTMLExporter.export(this.result);
  }
}
