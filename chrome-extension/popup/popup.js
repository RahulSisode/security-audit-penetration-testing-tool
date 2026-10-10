import { auditWebEnvironment, detectAppliedDefenses, generateBugBountyReport } from '../engine/scanner.js';

document.addEventListener('DOMContentLoaded', async () => {
  const scanBtn = document.getElementById('scanBtn');
  const scanBtnText = document.getElementById('scanBtnText');
  const sidePanelBtn = document.getElementById('sidePanelBtn');
  const exportBtn = document.getElementById('exportBtn');
  const targetUrlEl = document.getElementById('targetUrl');
  const gradeBadgeEl = document.getElementById('gradeBadge');
  const firewallStatusEl = document.getElementById('firewallStatus');
  const firewallBadgeEl = document.getElementById('firewallBadge');
  const critEl = document.getElementById('critCount');
  const highEl = document.getElementById('highCount');
  const medEl = document.getElementById('medCount');
  const lowEl = document.getElementById('lowCount');
  const vulnCountEl = document.getElementById('vulnCount');
  const defenseCountEl = document.getElementById('defenseCount');
  const findingsListEl = document.getElementById('findingsList');
  const defensesListEl = document.getElementById('defensesList');

  const tabVulnsBtn = document.getElementById('tabVulnsBtn');
  const tabDefensesBtn = document.getElementById('tabDefensesBtn');
  const tabEndpointsBtn = document.getElementById('tabEndpointsBtn');
  const vulnView = document.getElementById('vulnView');
  const defensesView = document.getElementById('defensesView');
  const endpointsView = document.getElementById('endpointsView');
  const endpointsListEl = document.getElementById('endpointsList');
  const endpointCountEl = document.getElementById('endpointCount');

  let currentResult = null;

  // Tab switching
  tabVulnsBtn.addEventListener('click', () => {
    tabVulnsBtn.classList.add('active');
    tabDefensesBtn.classList.remove('active');
    if (tabEndpointsBtn) tabEndpointsBtn.classList.remove('active');
    vulnView.classList.add('active');
    defensesView.classList.remove('active');
    if (endpointsView) endpointsView.classList.remove('active');
  });

  tabDefensesBtn.addEventListener('click', () => {
    tabDefensesBtn.classList.add('active');
    tabVulnsBtn.classList.remove('active');
    if (tabEndpointsBtn) tabEndpointsBtn.classList.remove('active');
    defensesView.classList.add('active');
    vulnView.classList.remove('active');
    if (endpointsView) endpointsView.classList.remove('active');
  });

  if (tabEndpointsBtn) {
    tabEndpointsBtn.addEventListener('click', () => {
      tabEndpointsBtn.classList.add('active');
      tabVulnsBtn.classList.remove('active');
      tabDefensesBtn.classList.remove('active');
      if (endpointsView) endpointsView.classList.add('active');
      vulnView.classList.remove('active');
      defensesView.classList.remove('active');
    });
  }

  // 1. Initial Load from storage & pre-render defenses
  try {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (activeTab && activeTab.url) {
      targetUrlEl.textContent = activeTab.url;
      const initialReport = detectAppliedDefenses({ url: activeTab.url });
      if (initialReport) {
        defenseCountEl.textContent = initialReport.defenses.length;
        firewallStatusEl.textContent = `Enabled • ${initialReport.firewall.type}`;
        firewallBadgeEl.textContent = initialReport.firewall.status;
        renderDefensesList(initialReport.defenses);
      }
    }

    const data = await chrome.storage.local.get('lastAuditResult');
    if (data.lastAuditResult) {
      renderResults(data.lastAuditResult);
    }
  } catch (e) {
    console.warn('Initial storage load:', e);
  }

  // 2. Open Chrome Side Panel
  if (sidePanelBtn) {
    sidePanelBtn.addEventListener('click', async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.windowId && chrome.sidePanel) {
          await chrome.sidePanel.open({ windowId: tab.windowId });
          window.close();
        }
      } catch (err) {
        console.error('Failed to open side panel:', err);
      }
    });
  }

  // 3. Lightning-Fast Security & Firewall Scan
  scanBtn.addEventListener('click', async () => {
    scanBtn.disabled = true;
    scanBtnText.textContent = 'Auditing Defenses & Headers...';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id || !tab.url) {
        throw new Error('No accessible active web tab found.');
      }

      targetUrlEl.textContent = tab.url;

      // Request full enterprise audit from service worker (including headers, cookies, scripts, defenses)
      const scanResult = await chrome.runtime.sendMessage({ action: 'scanCurrentTab' });

      if (!scanResult || !scanResult.success) {
        throw new Error(scanResult?.error || 'Audit failed to complete.');
      }

      // Auto switch to vulnerabilities view
      tabVulnsBtn.classList.add('active');
      tabDefensesBtn.classList.remove('active');
      vulnView.classList.add('active');
      defensesView.classList.remove('active');

      renderResults(scanResult);
    } catch (err) {
      console.error('Scan error:', err);
      targetUrlEl.textContent = 'Error: ' + err.message;
    } finally {
      scanBtn.disabled = false;
      scanBtnText.textContent = 'Scan Active Page / Repo';
    }
  });

  // 4. Export SARIF
  exportBtn.addEventListener('click', () => {
    if (!currentResult || !currentResult.findings || currentResult.findings.length === 0) {
      alert('No findings to export.');
      return;
    }

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Sentinel Security (Chrome Extension)',
            version: '1.0.0',
            informationUri: 'https://github.com/sentinel-security/sentinel'
          }
        },
        results: currentResult.findings.map(f => ({
          ruleId: f.ruleId,
          message: { text: f.title },
          level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : f.severity === 'MEDIUM' ? 'warning' : 'note',
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line }
            }
          }]
        }))
      }]
    };

    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-audit-${Date.now()}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
  });

  function renderResults(result) {
    currentResult = result;
    const s = result.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0, grade: 'A' };
    const findings = result.findings || [];
    const defenses = result.defenses || [];
    const firewall = result.firewall || { type: 'Standard Security Sandbox', status: 'ACTIVE' };

    targetUrlEl.textContent = result.url || 'Active Page';
    critEl.textContent = s.critical;
    highEl.textContent = s.high;
    medEl.textContent = s.medium;
    lowEl.textContent = s.low;
    vulnCountEl.textContent = s.total;
    defenseCountEl.textContent = defenses.length;

    // Firewall status card
    firewallStatusEl.textContent = `Enabled • ${firewall.type}`;
    firewallBadgeEl.textContent = firewall.status;
    firewallBadgeEl.className = firewall.status === 'ACTIVE' || firewall.status === 'ENABLED' ? 'pill-firewall' : 'pill-firewall';

    // Grade badge
    gradeBadgeEl.textContent = s.grade || 'A';
    gradeBadgeEl.className = `grade-badge grade-${(s.grade || 'A').toLowerCase()}`;

    // Render Vulnerabilities directly in popup
    if (findings.length === 0) {
      findingsListEl.innerHTML = `
        <div class="empty-state">
          <p>🛡️</p>
          <p style="font-weight:600; color:#fff;">Zero Vulnerabilities Found</p>
          <p style="font-size:10px;">Scanned in ${result.durationMs || 10}ms. Code and DOM passed all checked rules.</p>
        </div>
      `;
    } else {
      findingsListEl.innerHTML = findings.map(f => `
        <div class="finding-card">
          <div class="card-top">
            <span class="finding-name">${escapeHtml(f.title)}</span>
            <div style="display:flex; gap:4px; align-items:center;">
              ${f.cvss ? `<span style="font-size:9px; background:#f8514922; color:#f85149; border:1px solid #f8514944; border-radius:4px; padding:1px 4px; font-weight:600;">CVSS ${f.cvss.score}</span>` : ''}
              <span class="pill pill-${f.severity.toLowerCase()}">${f.severity}</span>
            </div>
          </div>
          <div style="font-size:10px; color:#8b949e; margin-bottom:4px;">
            <span>⚡ <strong>${escapeHtml(f.ruleId)}</strong></span> • <span>Line ${f.line}</span>
            ${f.owasp ? ` • <span style="color:#58a6ff;">OWASP ${f.owasp.id}</span>` : ''}
          </div>
          ${f.snippet ? `<div class="code-box">${escapeHtml(f.redactedSnippet || f.snippet)}</div>` : ''}
          <div class="remed-text">💡 <strong>Remediation:</strong> ${escapeHtml(f.remediation || 'Remediation guidance available')}</div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:6px;">
            <span style="font-size:9px; color:#8b949e;">${f.cwe || 'CWE-693'}</span>
            <button class="btn-copy-report" data-finding-id="${f.id}" style="font-size:9px; padding:2px 6px; background:#21262d; border:1px solid #30363d; border-radius:4px; color:#58a6ff; cursor:pointer;">
              📋 Copy Report
            </button>
          </div>
        </div>
      `).join('');
    }

    // Attach copy report click handler
    findingsListEl.querySelectorAll('.btn-copy-report').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const fId = btn.getAttribute('data-finding-id');
        const finding = (currentResult?.findings || []).find(f => f.id === fId);
        if (finding) {
          const report = generateBugBountyReport(finding, currentResult.url);
          navigator.clipboard.writeText(report).then(() => {
            btn.textContent = '✅ Copied!';
            setTimeout(() => { btn.textContent = '📋 Copy Report'; }, 2000);
          });
        }
      });
    });

    const totalSurface = (result.endpoints || []).length + (result.subdomains || []).length + (result.disallowedPaths || []).length;
    if (endpointCountEl) {
      endpointCountEl.textContent = totalSurface;
    }

    // Render Applied Defenses
    renderDefensesList(defenses);

    // Render Endpoints
    renderEndpointsList(result.endpoints || [], result.techStack || [], result.subdomains || [], result.disallowedPaths || []);
  }

  function renderEndpointsList(endpoints = [], techStack = [], subdomains = [], disallowedPaths = []) {
    if (!endpointsListEl) return;
    let html = '';

    if (techStack.length > 0) {
      html += `
        <div style="margin-bottom:10px; padding:8px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:10px; font-weight:600; color:#58a6ff; margin-bottom:4px;">🌐 Fingerprinted Stack</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${techStack.map(t => `<span style="font-size:9px; background:#21262d; border:1px solid #30363d; border-radius:10px; padding:1px 6px; color:#c9d1d9;">${escapeHtml(t.name)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (subdomains.length > 0) {
      html += `
        <div style="margin-bottom:10px; padding:8px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:10px; font-weight:600; color:#3fb950; margin-bottom:4px;">🛰️ Passive Subdomains (${subdomains.length})</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px; max-height:80px; overflow-y:auto;">
            ${subdomains.map(s => `<span style="font-family:monospace; font-size:9px; background:#0d1117; border:1px solid #238636; border-radius:3px; padding:1px 4px; color:#7ee787;">${escapeHtml(s)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (disallowedPaths.length > 0) {
      html += `
        <div style="margin-bottom:10px; padding:8px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:10px; font-weight:600; color:#d29922; margin-bottom:4px;">🤖 Robots.txt Disallowed Paths (${disallowedPaths.length})</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${disallowedPaths.map(p => `<span style="font-family:monospace; font-size:9px; background:#0d1117; border:1px solid #9e6a03; border-radius:3px; padding:1px 4px; color:#e3b341;">${escapeHtml(p)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (endpoints.length === 0 && subdomains.length === 0 && disallowedPaths.length === 0) {
      html += `
        <div class="empty-state">
          <p>🔍</p>
          <p style="font-weight:600; color:#fff;">No Explicit API Routes Harvested</p>
          <p style="font-size:10px;">Scanned scripts and routes for API patterns.</p>
        </div>
      `;
    } else if (endpoints.length > 0) {
      html += `
        <div style="font-size:10px; font-weight:600; color:#58a6ff; margin-bottom:4px;">⚡ Harvested API Routes (${endpoints.length})</div>
      `;
      html += endpoints.map(ep => `
        <div class="finding-card" style="padding:6px 8px; margin-bottom:4px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-family:monospace; font-size:9px; color:#79c0ff; word-break:break-all;">${escapeHtml(ep)}</span>
            <span style="font-size:8px; background:#1f6feb22; color:#58a6ff; border:1px solid #1f6feb44; border-radius:3px; padding:1px 4px;">ROUTE</span>
          </div>
        </div>
      `).join('');
    }

    endpointsListEl.innerHTML = html;
  }

  function renderDefensesList(defenses) {
    if (!defensesListEl) return;
    defensesListEl.innerHTML = (defenses || []).map(d => `
      <div class="defense-item">
        <span class="defense-icon">${d.icon}</span>
        <div class="defense-body">
          <div class="defense-header">
            <span class="defense-name">${escapeHtml(d.name)}</span>
            <span class="defense-badge">${escapeHtml(d.status)}</span>
          </div>
          <div class="defense-desc">${escapeHtml(d.description)}</div>
        </div>
      </div>
    `).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
});
