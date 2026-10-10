import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityFinding, ScanResult, Severity } from '../core/types';

export class SentinelTreeDataProvider implements vscode.TreeDataProvider<SentinelTreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<SentinelTreeItem | undefined | void> = new vscode.EventEmitter<SentinelTreeItem | undefined | void>();
  readonly onDidChangeTreeData: vscode.Event<SentinelTreeItem | undefined | void> = this._onDidChangeTreeData.event;

  private currentResult: ScanResult | null = null;

  public refresh(result?: ScanResult): void {
    if (result) {
      this.currentResult = result;
    }
    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: SentinelTreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: SentinelTreeItem): Thenable<SentinelTreeItem[]> {
    if (!this.currentResult) {
      const scanBtn = new SentinelTreeItem(
        '▶ Run Full Security Scan',
        vscode.TreeItemCollapsibleState.None
      );
      scanBtn.iconPath = new vscode.ThemeIcon('play', new vscode.ThemeColor('charts.green'));
      scanBtn.command = {
        command: 'sentinel.fullScan',
        title: 'Run Full Scan'
      };
      scanBtn.tooltip = 'Click to scan workspace for SAST, Taint, Secrets, SCA, and IaC vulnerabilities';

      const dashBtn = new SentinelTreeItem(
        '📊 Open Security Dashboard',
        vscode.TreeItemCollapsibleState.None
      );
      dashBtn.iconPath = new vscode.ThemeIcon('graph');
      dashBtn.command = {
        command: 'sentinel.openDashboard',
        title: 'Open Dashboard'
      };

      const dastBtn = new SentinelTreeItem(
        '🌐 Run Authorized DAST Probe',
        vscode.TreeItemCollapsibleState.None
      );
      dastBtn.iconPath = new vscode.ThemeIcon('pulse');
      dastBtn.command = {
        command: 'sentinel.scanDAST',
        title: 'Run DAST'
      };

      return Promise.resolve([scanBtn, dashBtn, dastBtn]);
    }

    if (this.currentResult.findings.length === 0) {
      const cleanItem = new SentinelTreeItem(
        '✅ No active findings in completed checks',
        vscode.TreeItemCollapsibleState.None
      );
      cleanItem.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.green'));
      cleanItem.tooltip = 'All checked security rules passed cleanly.';

      const rescanBtn = new SentinelTreeItem(
        '🔄 Run Scan Again',
        vscode.TreeItemCollapsibleState.None
      );
      rescanBtn.iconPath = new vscode.ThemeIcon('refresh');
      rescanBtn.command = {
        command: 'sentinel.fullScan',
        title: 'Run Scan Again'
      };

      return Promise.resolve([cleanItem, rescanBtn]);
    }

    if (!element) {
      // Top Level Summary & Action Items
      const items: SentinelTreeItem[] = [];

      // Summary Header
      const s = this.currentResult.summary;
      const summaryItem = new SentinelTreeItem(
        `Overview: ${s.totalFindings} Findings (${s.criticalCount} Critical, ${s.highCount} High)`,
        vscode.TreeItemCollapsibleState.None
      );
      summaryItem.iconPath = new vscode.ThemeIcon('shield');
      summaryItem.command = {
        command: 'sentinel.openDashboard',
        title: 'Open Dashboard'
      };
      items.push(summaryItem);

      // Re-scan button
      const rescanBtn = new SentinelTreeItem(
        '🔄 Run Full Scan Again',
        vscode.TreeItemCollapsibleState.None
      );
      rescanBtn.iconPath = new vscode.ThemeIcon('refresh');
      rescanBtn.command = {
        command: 'sentinel.fullScan',
        title: 'Run Full Scan'
      };
      items.push(rescanBtn);

      // Open Dashboard GUI
      const dashBtn = new SentinelTreeItem(
        '📊 Open Visual Dashboard',
        vscode.TreeItemCollapsibleState.None
      );
      dashBtn.iconPath = new vscode.ThemeIcon('graph');
      dashBtn.command = {
        command: 'sentinel.openDashboard',
        title: 'Open Dashboard'
      };
      items.push(dashBtn);

      // Export Reports Button
      const exportBtn = new SentinelTreeItem(
        '📄 Export HTML Report',
        vscode.TreeItemCollapsibleState.None
      );
      exportBtn.iconPath = new vscode.ThemeIcon('file-code');
      exportBtn.command = {
        command: 'sentinel.exportHTML',
        title: 'Export HTML'
      };
      items.push(exportBtn);

      // Severity Groups
      const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      for (const sev of severities) {
        const matching = this.currentResult.findings.filter(f => f.severity === sev && !f.suppression?.isSuppressed);
        if (matching.length > 0) {
          const groupItem = new SentinelTreeItem(
            `${sev} (${matching.length})`,
            vscode.TreeItemCollapsibleState.Expanded,
            'group',
            undefined,
            sev
          );
          groupItem.iconPath = this.getSeverityIcon(sev);
          items.push(groupItem);
        }
      }

      return Promise.resolve(items);
    } else if (element.contextValue === 'group' && element.severityGroup) {
      // Return findings in this severity group
      const matching = this.currentResult.findings.filter(
        f => f.severity === element.severityGroup && !f.suppression?.isSuppressed
      );

      return Promise.resolve(
        matching.map(f => {
          const item = new SentinelTreeItem(
            f.title,
            vscode.TreeItemCollapsibleState.None,
            'finding',
            f
          );
          item.description = `${f.evidence.location.filePath}:${f.evidence.location.startLine}`;
          item.tooltip = `${f.title}\n${f.description}\nCategory: ${f.category}\nEngine: ${f.engineName}\nClick to jump to line in editor`;
          item.iconPath = this.getSeverityIcon(f.severity);

          // Clicking opens the affected file and navigates to line
          const workspaceRoot = this.currentResult?.targetDirectory || '';
          const fullPath = path.isAbsolute(f.evidence.location.filePath)
            ? f.evidence.location.filePath
            : path.join(workspaceRoot, f.evidence.location.filePath);

          item.command = {
            command: 'vscode.open',
            title: 'Open File',
            arguments: [
              vscode.Uri.file(fullPath),
              {
                selection: new vscode.Range(
                  Math.max(0, (f.evidence.location.startLine || 1) - 1),
                  0,
                  Math.max(0, (f.evidence.location.startLine || 1) - 1),
                  0
                )
              }
            ]
          };

          return item;
        })
      );
    }

    return Promise.resolve([]);
  }

  private getSeverityIcon(sev: Severity): vscode.ThemeIcon {
    switch (sev) {
      case 'CRITICAL': return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      case 'HIGH': return new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
      case 'MEDIUM': return new vscode.ThemeIcon('info', new vscode.ThemeColor('charts.yellow'));
      case 'LOW': return new vscode.ThemeIcon('info', new vscode.ThemeColor('charts.blue'));
      default: return new vscode.ThemeIcon('circle-outline');
    }
  }
}

export class SentinelTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue?: string,
    public readonly finding?: SecurityFinding,
    public readonly severityGroup?: Severity
  ) {
    super(label, collapsibleState);
  }
}
