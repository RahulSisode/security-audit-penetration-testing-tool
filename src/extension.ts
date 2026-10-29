import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { ScanOrchestrator } from './engine/orchestrator';
import { SentinelDiagnosticsManager } from './ui/diagnostics';
import { SentinelCodeActionProvider } from './ui/code-actions';
import { SentinelTreeDataProvider } from './ui/sidebar-provider';
import { SentinelDashboardPanel } from './ui/webview-provider';
import { SARIFExporter } from './exporters/sarif';
import { HTMLExporter } from './exporters/html';
import { JSONExporter } from './exporters/json';
import { RuleBasedRemediationEngine } from './ai/rule-remediation';
import { FixVerificationEngine } from './fixes/engine';
import { ScanResult, SecurityFinding } from './core/types';
import { SentinelSidebarWebviewProvider } from './ui/sidebar-webview-provider';
import { SentinelSecurityAgent } from './ai/agent/security-agent';
import { logger } from './utils/logger';

let lastScanResult: ScanResult | null = null;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  logger.info('Activating Sentinel Security Extension...');

  const diagnosticsManager = new SentinelDiagnosticsManager();
  const codeActionProvider = new SentinelCodeActionProvider();
  const treeDataProvider = new SentinelTreeDataProvider();
  const sidebarWebviewProvider = new SentinelSidebarWebviewProvider(context.extensionUri);

  // Status Bar Indicator
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
  statusBarItem.command = 'sentinel.openDashboard';
  statusBarItem.text = '$(shield) Sentinel: Ready';
  statusBarItem.tooltip = 'Click to open Sentinel Security Dashboard';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Register Sidebar Webview GUI View
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      SentinelSidebarWebviewProvider.viewType,
      sidebarWebviewProvider
    )
  );

  // Register Sidebar Tree View
  vscode.window.registerTreeDataProvider('sentinelFindingsView', treeDataProvider);

  // Register Code Actions Provider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      codeActionProvider,
      { providedCodeActionKinds: SentinelCodeActionProvider.providedCodeActionKinds }
    )
  );

  // Command: Run Full Security Scan
  const fullScanCommand = vscode.commands.registerCommand('sentinel.fullScan', async () => {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      vscode.window.showWarningMessage('Sentinel Security: Please open a project workspace folder to scan.');
      return;
    }

    const workspaceRoot = workspaceFolders[0].uri.fsPath;
    sidebarWebviewProvider.setScanningState(true);
    statusBarItem.text = '$(sync~spin) Sentinel: Scanning...';

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Sentinel Security: Running Full Multi-Layer Security Scan...',
        cancellable: false
      },
      async (progress) => {
        progress.report({ increment: 10, message: 'Discovering workspace files...' });

        const orchestrator = new ScanOrchestrator(workspaceRoot);
        const result = await orchestrator.runScan({ targetDirectory: workspaceRoot });
        lastScanResult = result;

        progress.report({ increment: 50, message: 'Normalizing findings and checking coverage...' });

        // Update UI components
        diagnosticsManager.updateDiagnostics(result.findings, workspaceRoot);
        codeActionProvider.updateFindings(result.findings);
        treeDataProvider.refresh(result);
        sidebarWebviewProvider.updateScanResult(result);

        if (SentinelDashboardPanel.currentPanel) {
          SentinelDashboardPanel.currentPanel.update(result);
        }

        const s = result.summary;
        if (s.totalFindings === 0) {
          statusBarItem.text = '$(shield) Sentinel: Secured';
          statusBarItem.backgroundColor = undefined;
          vscode.window.showInformationMessage(
            `🛡️ Sentinel Security: ${result.coverage.summaryMessage}`
          );
        } else {
          statusBarItem.text = `$(shield) Sentinel: ${s.totalFindings} Issues (${s.criticalCount} Crit)`;
          statusBarItem.backgroundColor = s.criticalCount > 0 
            ? new vscode.ThemeColor('statusBarItem.errorBackground') 
            : new vscode.ThemeColor('statusBarItem.warningBackground');

          const action = await vscode.window.showWarningMessage(
            `🛡️ Sentinel Security: Detected ${s.totalFindings} active findings (${s.criticalCount} Critical, ${s.highCount} High).`,
            'Open Dashboard',
            'Export Report'
          );

          if (action === 'Open Dashboard') {
            SentinelDashboardPanel.createOrShow(context.extensionUri, result);
          } else if (action === 'Export Report') {
            vscode.commands.executeCommand('sentinel.exportHTML');
          }
        }
      }
    );
  });

  // Command: Open Dashboard
  const openDashboardCommand = vscode.commands.registerCommand('sentinel.openDashboard', () => {
    SentinelDashboardPanel.createOrShow(context.extensionUri, lastScanResult || undefined);
  });

  // Command: Export SARIF
  const exportSARIFCommand = vscode.commands.registerCommand('sentinel.exportSARIF', async () => {
    if (!lastScanResult) {
      vscode.window.showWarningMessage('Sentinel Security: No scan results to export. Run a scan first.');
      return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    const defaultUri = workspaceFolders
      ? vscode.Uri.file(path.join(workspaceFolders[0].uri.fsPath, 'sentinel-report.sarif'))
      : undefined;

    const saveUri = await vscode.window.showSaveDialog({
      defaultUri,
      filters: { 'SARIF Files': ['sarif', 'json'] }
    });

    if (saveUri) {
      const sarifData = SARIFExporter.export(lastScanResult);
      fs.writeFileSync(saveUri.fsPath, sarifData, 'utf8');
      vscode.window.showInformationMessage(`🛡️ Sentinel: Successfully exported SARIF report to ${saveUri.fsPath}`);
    }
  });

  // Command: Export HTML Report
  const exportHTMLCommand = vscode.commands.registerCommand('sentinel.exportHTML', async () => {
    if (!lastScanResult) {
      vscode.window.showWarningMessage('Sentinel Security: No scan results to export. Run a scan first.');
      return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    const defaultUri = workspaceFolders
      ? vscode.Uri.file(path.join(workspaceFolders[0].uri.fsPath, 'sentinel-report.html'))
      : undefined;

    const saveUri = await vscode.window.showSaveDialog({
      defaultUri,
      filters: { 'HTML Files': ['html'] }
    });

    if (saveUri) {
      const htmlData = HTMLExporter.export(lastScanResult);
      fs.writeFileSync(saveUri.fsPath, htmlData, 'utf8');
      vscode.window.showInformationMessage(`🛡️ Sentinel: Successfully exported HTML report to ${saveUri.fsPath}`);
    }
  });

  // Command: Show Remediation Guidance
  const showGuidanceCommand = vscode.commands.registerCommand('sentinel.showFindingGuidance', (finding: SecurityFinding) => {
    if (!finding) return;
    const guide = RuleBasedRemediationEngine.getGuidance(finding);
    vscode.window.showInformationMessage(
      `🛡️ [${finding.ruleId}] ${guide.title}\n\n${guide.summary}\n\nRemediation Steps:\n${guide.remediationSteps.join('\n')}`,
      { modal: true }
    );
  });

  // Command: Apply and Verify Fix
  const applyFixCommand = vscode.commands.registerCommand('sentinel.applyAndVerifyFix', async (finding: SecurityFinding) => {
    if (!finding) return;
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) return;
    const workspaceRoot = workspaceFolders[0].uri.fsPath;

    const confirm = await vscode.window.showWarningMessage(
      `Apply automated fix for '${finding.title}' in ${finding.evidence.location.filePath}?`,
      { modal: true },
      'Apply and Verify Fix'
    );

    if (confirm === 'Apply and Verify Fix') {
      const verification = await FixVerificationEngine.applyAndVerifyFix(finding, workspaceRoot, true);
      if (verification.issueResolved) {
        vscode.window.showInformationMessage(`🛡️ Sentinel: ${verification.message}`);
        // Trigger rescan
        vscode.commands.executeCommand('sentinel.fullScan');
      } else {
        vscode.window.showErrorMessage(`🛡️ Sentinel: ${verification.message}`);
      }
    }
  });

  // Command: Run Authorized DAST Probe
  const dastCommand = vscode.commands.registerCommand('sentinel.scanDAST', async () => {
    const targetUrl = await vscode.window.showInputBox({
      prompt: 'Enter the authorized target URL to test dynamically (e.g. http://localhost:3000)',
      placeHolder: 'http://127.0.0.1:3000',
      validateInput: (val) => {
        try {
          new URL(val);
          return null;
        } catch {
          return 'Please enter a valid HTTP/HTTPS URL';
        }
      }
    });

    if (!targetUrl) return;

    const consent = await vscode.window.showWarningMessage(
      `CONFIRM AUTHORIZATION: Do you own or have explicit authorization to perform security testing against ${targetUrl}?`,
      { modal: true },
      'Yes, I am authorized'
    );

    if (consent !== 'Yes, I am authorized') {
      vscode.window.showInformationMessage('DAST scan cancelled.');
      return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    const workspaceRoot = workspaceFolders ? workspaceFolders[0].uri.fsPath : process.cwd();

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Sentinel Security: Running safe DAST probes on ${targetUrl}...`,
        cancellable: false
      },
      async () => {
        const orchestrator = new ScanOrchestrator(workspaceRoot);
        const result = await orchestrator.runScan({
          targetDirectory: workspaceRoot,
          dastOptions: {
            enabled: true,
            targetUrl,
            authorizedScope: [targetUrl],
            safeModeOnly: true
          }
        });
        lastScanResult = result;
        diagnosticsManager.updateDiagnostics(result.findings, workspaceRoot);
        treeDataProvider.refresh(result);
        SentinelDashboardPanel.createOrShow(context.extensionUri, result);
      }
    );
  });

  // Command: Consult AI Security Agent
  const consultAgentCommand = vscode.commands.registerCommand('sentinel.consultAgent', async () => {
    const config = vscode.workspace.getConfiguration('sentinel');
    const endpoint = config.get<string>('ollama.endpoint') || 'http://127.0.0.1:11434';
    const model = config.get<string>('ollama.model') || 'llama3';
    const agent = new SentinelSecurityAgent({ ollamaEndpoint: endpoint, ollamaModel: model });

    const query = await vscode.window.showInputBox({
      prompt: 'Ask the Sentinel AI Security Agent (e.g. "How should I sanitize DOM XSS in React?")',
      placeHolder: 'Enter question about security posture, exploit vectors, or mitigations...'
    });
    if (!query) return;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Sentinel AI Agent: Analyzing security context...',
        cancellable: false
      },
      async () => {
        const response = await agent.consultAgent(query);
        const doc = await vscode.workspace.openTextDocument({
          content: response,
          language: 'markdown'
        });
        await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
      }
    );
  });

  // Command: Run AI Agent Investigation on Finding
  const investigateAgentCommand = vscode.commands.registerCommand('sentinel.investigateWithAgent', async (finding?: SecurityFinding) => {
    let targetFinding = finding;
    if (!targetFinding && lastScanResult && lastScanResult.findings.length > 0) {
      const items = lastScanResult.findings.map(f => ({
        label: `[${f.severity}] ${f.title}`,
        description: `${f.evidence.location.filePath}:${f.evidence.location.startLine}`,
        finding: f
      }));
      const picked = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select a finding to investigate with the AI Security Agent'
      });
      if (picked) targetFinding = picked.finding;
    }

    if (!targetFinding) {
      vscode.window.showWarningMessage('Sentinel Security: No finding selected to investigate.');
      return;
    }

    const config = vscode.workspace.getConfiguration('sentinel');
    const endpoint = config.get<string>('ollama.endpoint') || 'http://127.0.0.1:11434';
    const model = config.get<string>('ollama.model') || 'llama3';
    const agent = new SentinelSecurityAgent({ ollamaEndpoint: endpoint, ollamaModel: model });

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Sentinel AI Agent: Investigating [${targetFinding.ruleId}] ${targetFinding.title}...`,
        cancellable: false
      },
      async () => {
        const report = await agent.investigateFinding(targetFinding!);
        const mdReport = `# 🛡️ Sentinel AI Agent Investigation Report
**Investigation ID:** \`${report.investigationId}\`  
**Timestamp:** ${report.timestamp}  
**Engine:** ${report.executionModel}  
**Target:** \`${targetFinding!.evidence.location.filePath}:${targetFinding!.evidence.location.startLine}\`  
**Severity:** **${targetFinding!.severity}** | **Rule:** \`${targetFinding!.ruleId}\`

---

## 🎯 1. Attack Vector Hypothesis
- **Vulnerability:** ${report.hypothesis.vulnerabilityType}
- **Confidence:** \`${report.hypothesis.confidence}\`
- **Threat Actor:** ${report.hypothesis.threatActorModel}
- **Attack Vector:** ${report.hypothesis.attackVector}
- **Exploit Preconditions:**
${report.hypothesis.exploitPreconditions.map(p => `  - ${p}`).join('\n')}
- **Expected Impact:** ${report.hypothesis.expectedImpact}

---

## 🔍 2. Non-Destructive Verification Steps
${report.verificationSteps.map(s => `### Step ${s.stepNumber}: ${s.action}
- **Tool:** \`${s.toolName}\` | **Status:** \`${s.status}\`
- **Observation:** ${s.observation}`).join('\n\n')}

---

## ⚖️ 3. Agent Triage Verdict
- **Verdict:** **\`${report.verdict.verdict}\`**
- **Explanation:** ${report.verdict.explanation}
- **Mitigating Controls Found:** ${report.verdict.mitigatingControlsFound.length > 0 ? report.verdict.mitigatingControlsFound.join(', ') : 'None'}
- **Audit Notes:** ${report.verdict.auditNotes}

---

## 🛠️ 4. Remediation Plan & Regression Test
**Summary:** ${report.remediation.remediationSummary}

### Proposed Patch:
\`\`\`diff
${report.remediation.patchDiff}
\`\`\`

### Generated Regression Unit Test:
\`\`\`typescript
${report.remediation.regressionTestCode}
\`\`\`
`;
        const doc = await vscode.workspace.openTextDocument({
          content: mdReport,
          language: 'markdown'
        });
        await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
      }
    );
  });

  // Command: Generate Regression Test
  const generateTestCommand = vscode.commands.registerCommand('sentinel.generateRegressionTest', async (finding?: SecurityFinding) => {
    let targetFinding = finding;
    if (!targetFinding && lastScanResult && lastScanResult.findings.length > 0) {
      const items = lastScanResult.findings.map(f => ({
        label: `[${f.severity}] ${f.title}`,
        description: `${f.evidence.location.filePath}:${f.evidence.location.startLine}`,
        finding: f
      }));
      const picked = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select finding to generate regression test'
      });
      if (picked) targetFinding = picked.finding;
    }

    if (!targetFinding) return;
    const agent = new SentinelSecurityAgent();
    const testCode = agent.generateRegressionTest(targetFinding);
    const doc = await vscode.workspace.openTextDocument({
      content: testCode,
      language: 'typescript'
    });
    await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
  });

  context.subscriptions.push(
    fullScanCommand,
    openDashboardCommand,
    exportSARIFCommand,
    exportHTMLCommand,
    showGuidanceCommand,
    applyFixCommand,
    dastCommand,
    consultAgentCommand,
    investigateAgentCommand,
    generateTestCommand,
    diagnosticsManager
  );

  logger.info('Sentinel Security Extension activated successfully.');
}

export function deactivate() {
  logger.info('Deactivating Sentinel Security Extension...');
}
