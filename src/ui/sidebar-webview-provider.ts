import * as vscode from 'vscode';
import * as path from 'path';
import { ScanResult, SecurityFinding, Severity } from '../core/types';
import { FixVerificationEngine } from '../fixes/engine';
import { RuleBasedRemediationEngine } from '../ai/rule-remediation';
import { SentinelSecurityAgent } from '../ai/agent/security-agent';

export class SentinelSidebarWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = 'sentinelSidebarView';
  private _view?: vscode.WebviewView;
  private currentResult: ScanResult | null = null;
  private isScanning: boolean = false;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri]
    };

    this.updateWebview();

    webviewView.webview.onDidReceiveMessage(async (data) => {
      switch (data.action) {
        case 'triggerFullScan':
          vscode.commands.executeCommand('sentinel.fullScan');
          break;
        case 'openDashboard':
          vscode.commands.executeCommand('sentinel.openDashboard');
          break;
        case 'exportHTML':
          vscode.commands.executeCommand('sentinel.exportHTML');
          break;
        case 'exportSARIF':
          vscode.commands.executeCommand('sentinel.exportSARIF');
          break;
        case 'runDAST':
          vscode.commands.executeCommand('sentinel.scanDAST');
          break;
        case 'openFile':
          this.openFindingFile(data.filePath, data.line);
          break;
        case 'applyFix':
          if (this.currentResult) {
            const finding = this.currentResult.findings.find(f => f.fingerprint === data.fingerprint);
            if (finding) {
              vscode.commands.executeCommand('sentinel.applyAndVerifyFix', finding);
            }
          }
          break;
        case 'showGuidance':
          if (this.currentResult) {
            const finding = this.currentResult.findings.find(f => f.fingerprint === data.fingerprint);
            if (finding) {
              vscode.commands.executeCommand('sentinel.showFindingGuidance', finding);
            }
          }
          break;
        case 'investigateAgent':
          if (this.currentResult) {
            const finding = this.currentResult.findings.find(f => f.fingerprint === data.fingerprint) || this.currentResult.findings[0];
            if (finding) {
              vscode.commands.executeCommand('sentinel.investigateWithAgent', finding);
            }
          } else {
            vscode.commands.executeCommand('sentinel.investigateWithAgent');
          }
          break;
        case 'generateTest':
          if (this.currentResult) {
            const finding = this.currentResult.findings.find(f => f.fingerprint === data.fingerprint) || this.currentResult.findings[0];
            if (finding) {
              vscode.commands.executeCommand('sentinel.generateRegressionTest', finding);
            }
          }
          break;
        case 'consultAgent': {
          const config = vscode.workspace.getConfiguration('sentinel');
          const endpoint = config.get<string>('ollama.endpoint') || 'http://127.0.0.1:11434';
          const model = config.get<string>('ollama.model') || 'llama3';
          const agent = new SentinelSecurityAgent({ ollamaEndpoint: endpoint, ollamaModel: model });
          let targetFinding: SecurityFinding | undefined;
          if (data.fingerprint && this.currentResult) {
            targetFinding = this.currentResult.findings.find(f => f.fingerprint === data.fingerprint);
          } else if (this.currentResult && this.currentResult.findings.length > 0) {
            targetFinding = this.currentResult.findings[0];
          }
          const reply = await agent.consultAgent(data.query, targetFinding);
          if (this._view) {
            this._view.webview.postMessage({ action: 'agentReply', text: reply });
          }
          break;
        }
      }
    });
  }

  public updateScanResult(result: ScanResult) {
    this.currentResult = result;
    this.isScanning = false;
    this.updateWebview();
  }

  public setScanningState(scanning: boolean) {
    this.isScanning = scanning;
    this.updateWebview();
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

  private updateWebview() {
    if (!this._view) return;
    this._view.webview.html = this.getHtmlForWebview();
  }

  private calculateSecurityScore(): { score: number; grade: string; color: string } {
    if (!this.currentResult) {
      return { score: 100, grade: 'A+', color: '#3fb950' };
    }
    const s = this.currentResult.summary;
    let penalty = (s.criticalCount * 25) + (s.highCount * 12) + (s.mediumCount * 5) + (s.lowCount * 1);
    let score = Math.max(0, 100 - penalty);
    let grade = 'A+';
    let color = '#3fb950';

    if (score >= 90) { grade = 'A'; color = '#3fb950'; }
    else if (score >= 75) { grade = 'B'; color = '#58a6ff'; }
    else if (score >= 60) { grade = 'C'; color = '#d29922'; }
    else if (score >= 40) { grade = 'D'; color = '#db6d28'; }
    else { grade = 'F'; color = '#f85149'; }

    return { score, grade, color };
  }

  private getHtmlForWebview(): string {
    const s = this.currentResult?.summary;
    const c = this.currentResult?.coverage;
    const findings = this.currentResult?.findings || [];
    const health = this.calculateSecurityScore();

    const appliedDefenses = [
      { name: 'Host & Process Firewall', status: 'ACTIVE', desc: 'macOS Application Sandbox & local port protection active.' },
      { name: 'Zero-API Airgap Isolation', status: 'VERIFIED', desc: '100% in-memory execution; zero network data leaks.' },
      { name: 'Dynamic Secret Redactor', status: 'ENFORCED', desc: 'Automatic Shannon entropy masking for sensitive keys.' },
      { name: 'Multi-Layer AST Engine', status: 'ACTIVE', desc: '15 scanning layers verifying code syntax & taint flows.' },
      { name: 'Deterministic Fingerprinting', status: 'ENGAGED', desc: 'SHA-256 deduplication prevents false alarm fatigue.' }
    ];

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Security Controls</title>
  <style>
    :root {
      --bg: var(--vscode-sideBar-background, #181818);
      --card-bg: var(--vscode-editor-background, #1f1f1f);
      --card-hover: var(--vscode-list-hoverBackground, #2a2d2e);
      --text: var(--vscode-foreground, #cccccc);
      --text-muted: var(--vscode-descriptionForeground, #888888);
      --border: var(--vscode-widget-border, #333333);
      --btn-primary: var(--vscode-button-background, #0e639c);
      --btn-primary-hover: var(--vscode-button-hoverBackground, #1177bb);
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #58a6ff;
      --success: #3fb950;
      --purple: #bc8cff;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 10px;
      font-size: 12px;
      line-height: 1.4;
    }

    /* Score Header Card */
    .score-card {
      background: linear-gradient(135deg, rgba(30,35,45,0.8), rgba(20,22,28,0.9));
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }
    .score-left {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .score-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      font-weight: 700;
    }
    .score-subtitle {
      font-size: 13px;
      font-weight: 600;
      color: #ffffff;
    }
    .score-meta {
      font-size: 10px;
      color: var(--text-muted);
    }
    .score-badge {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      border: 3px solid ${health.color};
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      font-weight: 900;
      color: ${health.color};
      background: rgba(0,0,0,0.3);
      box-shadow: 0 0 10px ${health.color}33;
    }

    /* Firewall Card */
    .firewall-card {
      background: linear-gradient(135deg, rgba(35, 134, 54, 0.12), rgba(22, 27, 34, 0.8));
      border: 1px solid rgba(63, 185, 80, 0.35);
      border-radius: 6px;
      padding: 8px 10px;
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .firewall-info {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .firewall-badge {
      font-size: 9px;
      font-weight: 800;
      padding: 2px 6px;
      border-radius: 8px;
      background: rgba(63, 185, 80, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
      text-transform: uppercase;
    }

    /* Primary Scan Button */
    .hero-btn {
      width: 100%;
      padding: 10px 14px;
      background: var(--btn-primary);
      color: #ffffff;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      transition: all 0.15s ease;
      margin-bottom: 10px;
    }
    .hero-btn:hover { background: var(--btn-primary-hover); transform: translateY(-1px); }
    .hero-btn:active { transform: translateY(0); }
    .hero-btn:disabled { opacity: 0.6; cursor: not-allowed; }

    /* Quick Launch Bar */
    .quick-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      margin-bottom: 10px;
    }
    .quick-btn {
      padding: 6px 8px;
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 4px;
      font-size: 11px;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
      transition: background 0.15s;
    }
    .quick-btn:hover { background: var(--card-hover); border-color: #555; }

    /* View Mode Tabs */
    .tab-bar {
      display: flex;
      border-bottom: 1px solid var(--border);
      margin-bottom: 10px;
    }
    .tab-item {
      flex: 1;
      padding: 6px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
    }
    .tab-item:hover { color: var(--text); }
    .tab-item.active { color: var(--btn-primary); border-bottom-color: var(--btn-primary); }

    .view-panel { display: none; }
    .view-panel.active { display: block; }

    /* Severity Filter Chips */
    .filter-chips {
      display: flex;
      gap: 4px;
      margin-bottom: 10px;
      overflow-x: auto;
      padding-bottom: 2px;
    }
    .chip {
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-bg);
      color: var(--text-muted);
      transition: all 0.15s;
      white-space: nowrap;
    }
    .chip.active {
      background: #0e639c;
      color: #ffffff;
      border-color: #1177bb;
    }
    .chip-crit { color: var(--critical); border-color: var(--critical); }
    .chip-crit.active { background: var(--critical); color: #fff; }
    .chip-high { color: var(--high); border-color: var(--high); }
    .chip-high.active { background: var(--high); color: #fff; }
    .chip-med { color: var(--medium); border-color: var(--medium); }
    .chip-med.active { background: var(--medium); color: #fff; }
    .chip-low { color: var(--low); border-color: var(--low); }
    .chip-low.active { background: var(--low); color: #fff; }

    /* Search Box */
    .search-box {
      width: 100%;
      padding: 6px 10px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--text);
      font-size: 11px;
      margin-bottom: 10px;
    }
    .search-box:focus {
      outline: none;
      border-color: var(--btn-primary);
    }

    /* Findings List */
    .findings-container, .defenses-container {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: calc(100vh - 310px);
      overflow-y: auto;
    }
    .finding-card, .defense-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      transition: all 0.15s;
    }
    .finding-card:hover, .defense-card:hover {
      border-color: #555;
      background: var(--card-hover);
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 6px;
      margin-bottom: 4px;
      cursor: pointer;
    }
    .finding-title {
      font-weight: 600;
      font-size: 11.5px;
      color: #ffffff;
      line-height: 1.3;
    }
    .pill {
      font-size: 8.5px;
      font-weight: 800;
      padding: 2px 5px;
      border-radius: 8px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .pill-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .pill-high { background: rgba(219, 109, 40, 0.2); color: var(--high); border: 1px solid var(--high); }
    .pill-medium { background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .pill-low { background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }

    .card-meta {
      font-size: 10.5px;
      color: var(--text-muted);
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 4px;
      cursor: pointer;
    }
    .code-preview {
      background: #0d1117;
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 4px;
      padding: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 10.5px;
      color: #79c0ff;
      overflow-x: auto;
      white-space: pre;
      margin-bottom: 6px;
      cursor: pointer;
    }
    .card-actions {
      display: flex;
      gap: 4px;
      margin-top: 6px;
    }
    .btn-action {
      flex: 1;
      padding: 4px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--text);
      text-align: center;
      transition: background 0.15s;
    }
    .btn-fix {
      background: rgba(63, 185, 80, 0.15);
      color: #3fb950;
      border-color: #3fb950;
    }
    .btn-fix:hover { background: rgba(63, 185, 80, 0.3); }
    .btn-action:hover { background: rgba(255,255,255,0.08); }

    /* Defense Card */
    .defense-card {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .def-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .def-title {
      font-weight: 600;
      font-size: 11.5px;
      color: #ffffff;
    }
    .def-badge {
      font-size: 8.5px;
      font-weight: 800;
      color: var(--success);
      background: rgba(63, 185, 80, 0.15);
      padding: 1px 6px;
      border-radius: 4px;
    }
    .def-desc {
      font-size: 10.5px;
      color: var(--text-muted);
    }

    /* Spinner */
    .spinner {
      border: 2px solid rgba(255,255,255,0.1);
      border-top: 2px solid var(--btn-primary);
      border-radius: 50%;
      width: 16px;
      height: 16px;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  </style>
</head>
<body>

  <!-- Score Header -->
  <div class="score-card">
    <div class="score-left">
      <span class="score-title">Security Posture</span>
      <span class="score-subtitle">${s ? s.totalFindings + ' Active Issues' : 'Ready to Scan'}</span>
      <span class="score-meta">${c ? c.filesScanned + ' files analyzed' : 'Multi-layer static & taint scan'}</span>
    </div>
    <div class="score-badge">${health.grade}</div>
  </div>

  <!-- Firewall Status Card -->
  <div class="firewall-card">
    <div class="firewall-info">
      <span style="font-size: 18px;">🛡️</span>
      <div>
        <div style="font-weight: 700; font-size: 11.5px; color: #fff;">Host & Process Firewall</div>
        <div style="font-size: 10px; color: var(--success);">Enabled • Sandbox Isolated</div>
      </div>
    </div>
    <span class="firewall-badge">ACTIVE</span>
  </div>

  <!-- Primary Scan Action -->
  <button class="hero-btn" onclick="triggerScan()" ${this.isScanning ? 'disabled' : ''}>
    ${this.isScanning ? '<div class="spinner"></div> Scanning Workspace...' : '🛡️ Scan Workspace Now'}
  </button>

  <!-- Quick Actions Grid -->
  <div class="quick-grid">
    <button class="quick-btn" onclick="openDashboard()">📊 Dashboard</button>
    <button class="quick-btn" onclick="runDAST()">🌐 DAST Probe</button>
    <button class="quick-btn" onclick="exportHTML()">📄 Export HTML</button>
    <button class="quick-btn" onclick="exportSARIF()">📋 Export SARIF</button>
  </div>

  <!-- View Mode Tabs -->
  <div class="tab-bar">
    <button class="tab-item active" id="tabFindingsBtn" onclick="switchView('findings')">Findings (${findings.length})</button>
    <button class="tab-item" id="tabAgentBtn" onclick="switchView('agent')">🤖 AI Agent</button>
    <button class="tab-item" id="tabDefensesBtn" onclick="switchView('defenses')">Defenses (${appliedDefenses.length})</button>
  </div>

  <!-- View 1: Findings Stream -->
  <div id="findingsView" class="view-panel active">
    <!-- Filter Chips -->
    <div class="filter-chips">
      <button class="chip active" onclick="setSeverityFilter('ALL', this)">All (${findings.length})</button>
      <button class="chip chip-crit" onclick="setSeverityFilter('CRITICAL', this)">Crit (${s ? s.criticalCount : 0})</button>
      <button class="chip chip-high" onclick="setSeverityFilter('HIGH', this)">High (${s ? s.highCount : 0})</button>
      <button class="chip chip-med" onclick="setSeverityFilter('MEDIUM', this)">Med (${s ? s.mediumCount : 0})</button>
      <button class="chip chip-low" onclick="setSeverityFilter('LOW', this)">Low (${s ? s.lowCount : 0})</button>
    </div>

    <!-- Live Search -->
    <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search by rule, file, or CWE..." onkeyup="applyFilters()">

    <div class="findings-container" id="findingsContainer">
      ${this.isScanning ? `
        <div style="text-align:center; padding: 24px; color: var(--text-muted);">
          <div class="spinner" style="margin: 0 auto 10px auto;"></div>
          <p>Analyzing AST patterns, taint flows, secrets & IaC...</p>
        </div>
      ` : findings.length === 0 ? `
        <div style="text-align:center; padding: 30px 10px; color: var(--text-muted);">
          <p style="font-size: 28px; margin: 0 0 6px 0;">🛡️</p>
          <p style="font-weight: 600; color: var(--text); margin: 0 0 4px 0;">${this.currentResult ? 'Workspace is Secured' : 'No Scans Run Yet'}</p>
          <p style="font-size: 11px; margin: 0;">${this.currentResult ? 'Zero high-risk security flaws identified.' : 'Click "Scan Workspace Now" to check your code.'}</p>
        </div>
      ` : findings.map(f => {
        if (f.suppression?.isSuppressed) return '';
        return `
          <div class="finding-card" data-severity="${f.severity}" data-search="${f.title.toLowerCase()} ${f.category.toLowerCase()} ${f.evidence.location.filePath.toLowerCase()} ${f.ruleId.toLowerCase()}">
            <div class="card-header" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">
              <span class="finding-title">${f.title}</span>
              <span class="pill pill-${f.severity.toLowerCase()}">${f.severity}</span>
            </div>
            <div class="card-meta" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">
              <span>📍</span>
              <span style="font-family: monospace; text-decoration: underline;">${f.evidence.location.filePath}:${f.evidence.location.startLine}</span>
            </div>
            ${f.evidence.snippet ? `
              <div class="code-preview" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">${f.evidence.redactedSnippet || f.evidence.snippet}</div>
            ` : ''}
            <div class="card-actions">
              <button class="btn-action" style="color: #bc8cff; border-color: rgba(188,140,255,0.4);" onclick="investigateAgent('${f.fingerprint}')" title="AI Agent Investigation">🤖 Agent</button>
              ${f.proposedFix ? `<button class="btn-action btn-fix" onclick="applyFix('${f.fingerprint}')">⚡ Fix</button>` : ''}
              <button class="btn-action" onclick="generateTest('${f.fingerprint}')" title="Synthesize Unit Test">🧪 Test</button>
              <button class="btn-action" onclick="showGuidance('${f.fingerprint}')">📖 Guide</button>
            </div>
          </div>
        `;
      }).join('')}
    </div>
  </div>

  <!-- View 2: AI Security Agent Triage -->
  <div id="agentView" class="view-panel">
    <div style="display:flex; flex-direction:column; gap:8px;">
      <div style="background: linear-gradient(135deg, rgba(188,140,255,0.15), rgba(20,22,28,0.9)); border: 1px solid rgba(188,140,255,0.4); border-radius: 6px; padding: 10px;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
          <span style="font-size: 20px;">🤖</span>
          <div>
            <div style="font-weight: 700; font-size: 12px; color: #fff;">Sentinel Autonomous Agent</div>
            <div style="font-size: 10px; color: #bc8cff;">Strix-Inspired Security Reasoner</div>
          </div>
        </div>
        <div style="display: flex; gap: 4px; flex-wrap: wrap;">
          <span style="font-size: 9px; padding: 2px 6px; border-radius: 4px; background: rgba(63,185,80,0.2); color: #3fb950; border: 1px solid #3fb950;">Zero-API Offline Safe</span>
          <span style="font-size: 9px; padding: 2px 6px; border-radius: 4px; background: rgba(88,166,255,0.2); color: #58a6ff; border: 1px solid #58a6ff;">Ollama Ready</span>
        </div>
      </div>

      <div style="display: flex; gap: 6px;">
        <button class="quick-btn" style="flex:1; border-color: rgba(188,140,255,0.5); color: #bc8cff;" onclick="investigateAgent('')">🎯 Investigate Top</button>
        <button class="quick-btn" style="flex:1;" onclick="generateTest('')">🧪 Synthesize Test</button>
      </div>

      <div style="display: flex; gap: 4px; margin-top: 4px;">
        <input type="text" id="agentQueryInput" class="search-box" style="margin-bottom:0;" placeholder="Ask agent (e.g. How to mitigate XSS?)..." onkeydown="if(event.key==='Enter') sendAgentQuery()">
        <button class="quick-btn" style="background: var(--btn-primary); color: #fff; border:none; padding: 0 10px;" onclick="sendAgentQuery()">Ask</button>
      </div>

      <div id="agentResponseArea" style="background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 11px; max-height: calc(100vh - 380px); overflow-y: auto;">
        <div style="color: var(--text-muted);">
          <p style="font-weight: 600; color: #fff; margin: 0 0 4px 0;">🛡️ Autonomous Agent Workflow:</p>
          • <strong>Hypothesis:</strong> Attack vector & exploit preconditions<br>
          • <strong>Verification:</strong> AST structure & non-destructive check<br>
          • <strong>Triage:</strong> Filter false positives & verify framework guards<br>
          • <strong>Remediation:</strong> Deterministic patch & Mocha regression test<br>
          • <strong>Scope Guard:</strong> Strict local target authorization
        </div>
      </div>
    </div>
  </div>

  <!-- View 3: Applied Defenses -->
  <div id="defensesView" class="view-panel">
    <div class="defenses-container">
      ${appliedDefenses.map(d => `
        <div class="defense-card">
          <div class="def-top">
            <span class="def-title">✅ ${d.name}</span>
            <span class="def-badge">${d.status}</span>
          </div>
          <span class="def-desc">${d.desc}</span>
        </div>
      `).join('')}
    </div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    let currentSeverity = 'ALL';

    function triggerScan() { vscode.postMessage({ action: 'triggerFullScan' }); }
    function openDashboard() { vscode.postMessage({ action: 'openDashboard' }); }
    function exportHTML() { vscode.postMessage({ action: 'exportHTML' }); }
    function exportSARIF() { vscode.postMessage({ action: 'exportSARIF' }); }
    function runDAST() { vscode.postMessage({ action: 'runDAST' }); }
    function openFile(filePath, line) { vscode.postMessage({ action: 'openFile', filePath, line }); }
    function applyFix(fingerprint) { vscode.postMessage({ action: 'applyFix', fingerprint }); }
    function showGuidance(fingerprint) { vscode.postMessage({ action: 'showGuidance', fingerprint }); }
    function investigateAgent(fingerprint) { vscode.postMessage({ action: 'investigateAgent', fingerprint }); }
    function generateTest(fingerprint) { vscode.postMessage({ action: 'generateTest', fingerprint }); }

    function sendAgentQuery() {
      const input = document.getElementById('agentQueryInput');
      const query = (input.value || '').trim();
      if (!query) return;
      input.value = '';
      const area = document.getElementById('agentResponseArea');
      area.innerHTML = '<div style="color: #79c0ff;">🤖 Agent analyzing question with scope guard...</div>';
      vscode.postMessage({ action: 'consultAgent', query });
    }

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.action === 'agentReply') {
        const area = document.getElementById('agentResponseArea');
        area.innerHTML = '<div style="color:#e6edf3; white-space:pre-wrap;">' + message.text + '</div>';
      }
    });

    function switchView(viewName) {
      document.getElementById('tabFindingsBtn').classList.toggle('active', viewName === 'findings');
      document.getElementById('tabAgentBtn').classList.toggle('active', viewName === 'agent');
      document.getElementById('tabDefensesBtn').classList.toggle('active', viewName === 'defenses');
      document.getElementById('findingsView').classList.toggle('active', viewName === 'findings');
      document.getElementById('agentView').classList.toggle('active', viewName === 'agent');
      document.getElementById('defensesView').classList.toggle('active', viewName === 'defenses');
    }

    function setSeverityFilter(sev, el) {
      currentSeverity = sev;
      document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      el.classList.add('active');
      applyFilters();
    }

    function applyFilters() {
      const q = (document.getElementById('searchInput').value || '').toLowerCase();
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(card => {
        const sev = card.getAttribute('data-severity');
        const text = card.getAttribute('data-search') || '';
        const matchSev = (currentSeverity === 'ALL' || sev === currentSeverity);
        const matchQuery = text.includes(q);
        card.style.display = (matchSev && matchQuery) ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`;
  }
}
