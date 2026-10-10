import { ScanResult, SecurityFinding, Severity } from '../core/types';

export class HTMLExporter {
  public static export(result: ScanResult): string {
    const s = result.summary;
    const c = result.coverage;
    const findings = result.findings || [];

    // Security Score Calculation
    let penalty = (s.criticalCount * 25) + (s.highCount * 12) + (s.mediumCount * 5) + (s.lowCount * 1);
    let score = Math.max(0, 100 - penalty);
    let grade = 'A+';
    let gradeColor = '#3fb950';

    if (score >= 90) { grade = 'A'; gradeColor = '#3fb950'; }
    else if (score >= 75) { grade = 'B'; gradeColor = '#58a6ff'; }
    else if (score >= 60) { grade = 'C'; gradeColor = '#d29922'; }
    else if (score >= 40) { grade = 'D'; gradeColor = '#db6d28'; }
    else { grade = 'F'; gradeColor = '#f85149'; }

    // Category groups
    const sastFindings = findings.filter(f => ['INJECTION', 'XSS', 'PATH_TRAVERSAL', 'SSRF', 'DESERIALIZATION', 'UNSAFE_REFLECTION', 'CRYPTOGRAPHY', 'INSECURE_RNG'].includes(f.category));
    const taintFindings = findings.filter(f => (f.evidence.taintTrace && f.evidence.taintTrace.length > 0) || f.category === 'TAINT_FLOW' || f.category === 'INJECTION' || f.engineName.includes('Taint'));
    const secretFindings = findings.filter(f => f.category === 'SECRETS');
    const iacFindings = findings.filter(f => f.category === 'IAC_MISCONFIGURATION');
    const scaFindings = findings.filter(f => f.category === 'DEPENDENCY_VULNERABILITY' || f.category === 'LICENSE_VIOLATION' || f.category === 'SUPPLY_CHAIN_RISK');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Security Dashboard</title>
  <style>
    :root {
      --bg: #0b0e14;
      --card-bg: #151b23;
      --card-hover: #1c2430;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --primary: #2f81f7;
      --primary-hover: #388bfd;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #58a6ff;
      --success: #3fb950;
      --purple: #bc8cff;
      --font-mono: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 0;
      line-height: 1.5;
    }

    /* Top Navigation Header */
    .navbar {
      background: #0d1117;
      border-bottom: 1px solid var(--border);
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      font-size: 24px;
    }
    .brand-text h1 {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
      color: #ffffff;
      letter-spacing: -0.3px;
    }
    .brand-text p {
      font-size: 11px;
      color: var(--text-muted);
      margin: 0;
      font-family: var(--font-mono);
    }
    .nav-actions {
      display: flex;
      gap: 8px;
    }
    .btn {
      padding: 7px 14px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-bg);
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s;
    }
    .btn:hover { background: var(--card-hover); border-color: #555; }
    .btn-primary { background: var(--primary); color: #ffffff; border-color: var(--primary); }
    .btn-primary:hover { background: var(--primary-hover); }

    /* Main Container */
    .container {
      max-width: 1300px;
      margin: 0 auto;
      padding: 24px;
    }

    /* Hero Metrics Section */
    .hero-grid {
      display: grid;
      grid-template-columns: 240px 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }
    .posture-card {
      background: linear-gradient(145deg, #151b23, #0f141c);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    .grade-circle {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      border: 4px solid ${gradeColor};
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      font-weight: 900;
      color: ${gradeColor};
      margin-bottom: 10px;
      box-shadow: 0 0 16px ${gradeColor}33;
    }
    .posture-title { font-size: 13px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); }
    .posture-desc { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .stat-top { display: flex; justify-content: space-between; align-items: center; }
    .stat-title { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); }
    .stat-val { font-size: 32px; font-weight: 800; margin: 6px 0; }
    .stat-meta { font-size: 11px; color: var(--text-muted); }
    .c-crit { color: var(--critical); }
    .c-high { color: var(--high); }
    .c-med { color: var(--medium); }
    .c-low { color: var(--low); }

    /* Tabs Navigation */
    .tabs-bar {
      display: flex;
      border-bottom: 1px solid var(--border);
      gap: 8px;
      margin-bottom: 20px;
    }
    .tab-btn {
      padding: 10px 18px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.15s;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
    .tab-count {
      background: rgba(255,255,255,0.1);
      padding: 2px 7px;
      border-radius: 10px;
      font-size: 11px;
    }

    /* Tab Content Areas */
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }

    /* Search & Filter Bar */
    .toolbar {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }
    .search-input {
      flex: 1;
      padding: 9px 14px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 13px;
    }
    .search-input:focus { outline: none; border-color: var(--primary); }

    /* Finding Items */
    .findings-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      transition: border-color 0.15s;
    }
    .finding-card:hover { border-color: #555; }
    .finding-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
    }
    .finding-title-text {
      font-size: 15px;
      font-weight: 700;
      color: #ffffff;
    }
    .pill {
      font-size: 10px;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .pill-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .pill-high { background: rgba(219, 109, 40, 0.2); color: var(--high); border: 1px solid var(--high); }
    .pill-medium { background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .pill-low { background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }

    .finding-meta {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 10px;
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
    }
    .meta-tag { display: inline-flex; align-items: center; gap: 4px; }
    .meta-file { font-family: var(--font-mono); color: #79c0ff; text-decoration: underline; cursor: pointer; }

    .code-block {
      background: #090d13;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #79c0ff;
      overflow-x: auto;
      margin: 10px 0;
    }

    .diff-block {
      background: #090d13;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      font-family: var(--font-mono);
      font-size: 12px;
      margin: 10px 0;
      overflow-x: auto;
    }
    .diff-del { color: #f85149; }
    .diff-add { color: #3fb950; font-weight: 600; }

    .remediation-box {
      background: rgba(47, 129, 247, 0.08);
      border-left: 3px solid var(--primary);
      padding: 10px 14px;
      border-radius: 0 6px 6px 0;
      font-size: 12px;
      margin: 10px 0;
    }

    .actions-bar {
      display: flex;
      gap: 8px;
      margin-top: 12px;
    }
    .btn-sm {
      padding: 5px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-bg);
      color: var(--text);
    }
    .btn-fix {
      background: rgba(63, 185, 80, 0.15);
      color: var(--success);
      border-color: var(--success);
    }
    .btn-fix:hover { background: rgba(63, 185, 80, 0.3); }

    /* Trace Timeline */
    .trace-container {
      background: #090d13;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      margin: 10px 0;
    }
    .trace-step {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
      position: relative;
    }
    .trace-dot {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: var(--primary);
      color: #fff;
      font-size: 10px;
      font-weight: bold;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .trace-dot.sink { background: var(--critical); }
    .trace-content { flex: 1; }
    .trace-title { font-size: 12px; font-weight: 600; color: #fff; }
    .trace-code { font-family: var(--font-mono); font-size: 11px; color: #79c0ff; }

    /* Coverage Table */
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      font-size: 12.5px;
    }
    th, td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }
    th { background: #0e131b; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
    tr:last-child td { border-bottom: none; }
  </style>
</head>
<body>

  <!-- Top Navigation -->
  <div class="navbar">
    <div class="nav-brand">
      <span class="brand-icon">🛡️</span>
      <div class="brand-text">
        <h1>Sentinel Security Dashboard</h1>
        <p>${result.targetDirectory} • Completed in ${s.durationMs}ms</p>
      </div>
    </div>
    <div class="nav-actions">
      <button class="btn btn-primary" onclick="triggerScan()">⚡ Run Full Scan</button>
      <button class="btn" onclick="exportHTML()">📄 Export HTML</button>
      <button class="btn" onclick="exportSARIF()">📋 Export SARIF</button>
    </div>
  </div>

  <div class="container">

    <!-- Hero Metrics Section -->
    <div class="hero-grid">
      <div class="posture-card">
        <div class="grade-circle">${grade}</div>
        <div class="posture-title">Security Grade</div>
        <div class="posture-desc">${s.totalFindings === 0 ? 'Fully Secure' : s.totalFindings + ' Active Risks'}</div>
      </div>
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-top">
            <span class="stat-title">Critical Flaws</span>
            <span class="pill pill-critical">P0</span>
          </div>
          <div class="stat-val c-crit">${s.criticalCount}</div>
          <div class="stat-meta">Immediate RCE / Exploitation</div>
        </div>
        <div class="stat-card">
          <div class="stat-top">
            <span class="stat-title">High Risk</span>
            <span class="pill pill-high">P1</span>
          </div>
          <div class="stat-val c-high">${s.highCount}</div>
          <div class="stat-meta">Injection / XSS / Traversal</div>
        </div>
        <div class="stat-card">
          <div class="stat-top">
            <span class="stat-title">Medium Risk</span>
            <span class="pill pill-medium">P2</span>
          </div>
          <div class="stat-val c-med">${s.mediumCount}</div>
          <div class="stat-meta">Crypto / Auth / Config</div>
        </div>
        <div class="stat-card">
          <div class="stat-top">
            <span class="stat-title">Low & Info</span>
            <span class="pill pill-low">P3</span>
          </div>
          <div class="stat-val c-low">${s.lowCount}</div>
          <div class="stat-meta">Hardening / Best Practices</div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-bar">
      <button class="tab-btn active" onclick="switchTab('all', this)">
        🛡️ All Findings <span class="tab-count">${findings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('sast', this)">
        🔍 SAST & Code Flaws <span class="tab-count">${sastFindings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('taint', this)">
        ⚡ Data-Flow / Taint <span class="tab-count">${taintFindings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('secrets', this)">
        🔑 Secrets & Leaks <span class="tab-count">${secretFindings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('iac', this)">
        ☁️ Cloud & IaC <span class="tab-count">${iacFindings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('coverage', this)">
        ⚙️ Engine Status <span class="tab-count">${c.scanners.length}</span>
      </button>
    </div>

    <!-- Tab 1: All Findings -->
    <div id="tab-all" class="tab-pane active">
      <div class="toolbar">
        <input type="text" id="filterAll" class="search-input" placeholder="🔍 Search findings by rule, CWE, message, or file..." onkeyup="filterCards('tab-all', this.value)">
      </div>
      <div class="findings-list">
        ${renderFindingCards(findings)}
      </div>
    </div>

    <!-- Tab 2: SAST -->
    <div id="tab-sast" class="tab-pane">
      <div class="toolbar">
        <input type="text" id="filterSast" class="search-input" placeholder="🔍 Search SAST findings..." onkeyup="filterCards('tab-sast', this.value)">
      </div>
      <div class="findings-list">
        ${renderFindingCards(sastFindings)}
      </div>
    </div>

    <!-- Tab 3: Taint Analysis -->
    <div id="tab-taint" class="tab-pane">
      <div class="toolbar">
        <input type="text" id="filterTaint" class="search-input" placeholder="🔍 Search Taint flows..." onkeyup="filterCards('tab-taint', this.value)">
      </div>
      <div class="findings-list">
        ${renderFindingCards(taintFindings)}
      </div>
    </div>

    <!-- Tab 4: Secrets -->
    <div id="tab-secrets" class="tab-pane">
      <div class="toolbar">
        <input type="text" id="filterSecrets" class="search-input" placeholder="🔍 Search Secrets..." onkeyup="filterCards('tab-secrets', this.value)">
      </div>
      <div class="findings-list">
        ${renderFindingCards(secretFindings)}
      </div>
    </div>

    <!-- Tab 5: IaC -->
    <div id="tab-iac" class="tab-pane">
      <div class="toolbar">
        <input type="text" id="filterIac" class="search-input" placeholder="🔍 Search IaC & Docker rules..." onkeyup="filterCards('tab-iac', this.value)">
      </div>
      <div class="findings-list">
        ${renderFindingCards(iacFindings)}
      </div>
    </div>

    <!-- Tab 6: Engine Coverage Status -->
    <div id="tab-coverage" class="tab-pane">
      <div style="background:var(--card-bg); border:1px solid var(--border); border-radius:8px; padding:18px; margin-bottom:16px;">
        <h3 style="margin-top:0;">Coverage & Audit Metadata</h3>
        <p style="color:var(--text-muted);">${c.summaryMessage}</p>
        <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; margin-top:14px;">
          <div style="background:#090d13; padding:12px; border-radius:6px; border:1px solid var(--border);">
            <div style="font-size:11px; color:var(--text-muted);">Files Scanned</div>
            <div style="font-size:20px; font-weight:bold;">${c.filesScanned} / ${c.filesDiscovered}</div>
          </div>
          <div style="background:#090d13; padding:12px; border-radius:6px; border:1px solid var(--border);">
            <div style="font-size:11px; color:var(--text-muted);">Lines of Code</div>
            <div style="font-size:20px; font-weight:bold;">~${c.linesOfCodeScanned}</div>
          </div>
          <div style="background:#090d13; padding:12px; border-radius:6px; border:1px solid var(--border);">
            <div style="font-size:11px; color:var(--text-muted);">Languages</div>
            <div style="font-size:13px; font-weight:bold; margin-top:4px;">${c.languagesIdentified.join(', ') || 'N/A'}</div>
          </div>
          <div style="background:#090d13; padding:12px; border-radius:6px; border:1px solid var(--border);">
            <div style="font-size:11px; color:var(--text-muted);">Frameworks</div>
            <div style="font-size:13px; font-weight:bold; margin-top:4px;">${c.frameworksIdentified.join(', ') || 'None'}</div>
          </div>
        </div>
      </div>

      <h3>Active Detection Engines Matrix</h3>
      <table>
        <thead>
          <tr>
            <th>Engine Name</th>
            <th>Engine Version</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Findings Generated</th>
          </tr>
        </thead>
        <tbody>
          ${c.scanners.map(sc => `
            <tr>
              <td><strong>${sc.scannerName}</strong></td>
              <td><code>${sc.version || '1.0.0'}</code></td>
              <td>
                <span class="pill ${sc.status === 'EXECUTED' ? 'pill-low' : sc.status === 'UNAVAILABLE' ? 'pill-critical' : 'pill-medium'}">
                  ${sc.status}
                </span>
              </td>
              <td>${sc.executionTimeMs}ms</td>
              <td><strong>${sc.findingsCount}</strong></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

  </div>

  <script>
    let vscode;
    try { vscode = acquireVsCodeApi(); } catch(e) {}

    function triggerScan() { if (vscode) vscode.postMessage({ command: 'triggerFullScan' }); }
    function exportHTML() { if (vscode) vscode.postMessage({ command: 'exportHTML' }); }
    function exportSARIF() { if (vscode) vscode.postMessage({ command: 'exportSARIF' }); }
    function openFile(filePath, line) { if (vscode) vscode.postMessage({ command: 'openFile', filePath, line }); }
    function applyFix(fingerprint) { if (vscode) vscode.postMessage({ command: 'applyFix', fingerprint }); }
    function showGuidance(fingerprint) { if (vscode) vscode.postMessage({ command: 'showGuidance', fingerprint }); }

    function switchTab(tabId, el) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      el.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
    }

    function filterCards(paneId, query) {
      const q = (query || '').toLowerCase();
      const pane = document.getElementById(paneId);
      const cards = pane.querySelectorAll('.finding-card');
      cards.forEach(card => {
        const text = (card.getAttribute('data-search') || '').toLowerCase();
        card.style.display = text.includes(q) ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`;
  }
}

function renderFindingCards(findings: SecurityFinding[]): string {
  if (findings.length === 0) {
    return `
      <div style="text-align:center; padding: 40px; color: var(--text-muted); background: var(--card-bg); border-radius:8px; border:1px solid var(--border);">
        <p style="font-size:32px; margin:0 0 8px 0;">🛡️</p>
        <p style="font-size:14px; font-weight:600; color:var(--text); margin:0;">No matching security findings</p>
      </div>
    `;
  }

  return findings.map(f => {
    return `
      <div class="finding-card" data-search="${f.title} ${f.category} ${f.severity} ${f.ruleId} ${f.evidence.location.filePath} ${f.references.cwe?.join(' ')}">
        <div class="finding-head">
          <span class="finding-title-text">${f.title}</span>
          <span class="pill pill-${f.severity.toLowerCase()}">${f.severity}</span>
        </div>
        <div class="finding-meta">
          <span class="meta-tag">🏷️ <strong>Category:</strong> ${f.category}</span>
          <span class="meta-tag">⚡ <strong>Rule:</strong> <code>${f.ruleId}</code></span>
          <span class="meta-tag">📍 <strong>File:</strong> <span class="meta-file" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">${f.evidence.location.filePath}:${f.evidence.location.startLine}</span></span>
          <span class="meta-tag">⚙️ <strong>Engine:</strong> ${f.engineName}</span>
        </div>

        <p style="font-size:13px; color:var(--text); margin: 6px 0;">${f.description}</p>

        ${f.evidence.snippet ? `
          <div class="code-block" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">${f.evidence.redactedSnippet || f.evidence.snippet}</div>
        ` : ''}

        ${(f.evidence.taintTrace && f.evidence.taintTrace.length > 0) ? `
          <div class="trace-container">
            <div style="font-size:11px; font-weight:bold; text-transform:uppercase; color:var(--text-muted); margin-bottom:8px;">Data-Flow Trace Graph (${f.evidence.taintTrace.length} Steps)</div>
            ${f.evidence.taintTrace.map((step, sIdx) => `
              <div class="trace-step">
                <div class="trace-dot ${step.type === 'SINK' ? 'sink' : ''}">${step.step || (sIdx + 1)}</div>
                <div class="trace-content">
                  <div class="trace-title">${step.type}: ${step.variableName || ''} - ${step.description}</div>
                  <div class="trace-code">${step.location.filePath}:${step.location.startLine}</div>
                  ${step.codeSnippet ? `<div class="code-block" style="margin:4px 0; padding:6px; font-size:11px;">${step.codeSnippet}</div>` : ''}
                </div>
              </div>
            `).join('')}
          </div>
        ` : ''}

        ${f.remediation ? `
          <div class="remediation-box">
            <strong>💡 Remediation:</strong> ${f.remediation}
          </div>
        ` : ''}

        ${f.proposedFix?.patchDiff ? `
          <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--text-muted); margin-top:8px;">Automated Code Patch</div>
          <div class="diff-block">${f.proposedFix.patchDiff.split('\n').map(l => l.startsWith('+') ? `<span class="diff-add">${l}</span>` : l.startsWith('-') ? `<span class="diff-del">${l}</span>` : `<span>${l}</span>`).join('\n')}</div>
        ` : ''}

        <div class="actions-bar">
          ${f.proposedFix ? `<button class="btn-sm btn-fix" onclick="applyFix('${f.fingerprint}')">⚡ Apply & Verify Fix</button>` : ''}
          <button class="btn-sm" onclick="showGuidance('${f.fingerprint}')">📖 Full Guidance</button>
          <button class="btn-sm" onclick="openFile('${f.evidence.location.filePath}', ${f.evidence.location.startLine})">🔍 Open in Editor</button>
        </div>
      </div>
    `;
  }).join('');
}
