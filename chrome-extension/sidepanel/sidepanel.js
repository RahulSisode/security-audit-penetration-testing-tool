import { auditWebEnvironment, detectAppliedDefenses, generateBugBountyReport } from '../engine/scanner.js';

document.addEventListener('DOMContentLoaded', async () => {
  const sideScanBtn = document.getElementById('sideScanBtn');
  const exportHtmlBtn = document.getElementById('exportHtmlBtn');
  const panelTargetEl = document.getElementById('panelTarget');
  const sideGradeBadgeEl = document.getElementById('sideGradeBadge');
  const sideFirewallStatusEl = document.getElementById('sideFirewallStatus');
  const sideFirewallBadgeEl = document.getElementById('sideFirewallBadge');
  const sideCritEl = document.getElementById('sideCrit');
  const sideHighEl = document.getElementById('sideHigh');
  const sideMedEl = document.getElementById('sideMed');
  const sideLowEl = document.getElementById('sideLow');
  const countAllEl = document.getElementById('countAll');
  const sideDefenseCountEl = document.getElementById('sideDefenseCount');
  const sideSearchEl = document.getElementById('sideSearch');
  const sideFindingsListEl = document.getElementById('sideFindingsList');
  const sideDefensesListEl = document.getElementById('sideDefensesList');
  const filterChips = document.querySelectorAll('.chip');

  const sideTabVulns = document.getElementById('sideTabVulns');
  const sideTabDefenses = document.getElementById('sideTabDefenses');
  const sideTabEndpoints = document.getElementById('sideTabEndpoints');
  const sideFindingsView = document.getElementById('sideFindingsView');
  const sideDefensesView = document.getElementById('sideDefensesView');
  const sideEndpointsView = document.getElementById('sideEndpointsView');
  const sideEndpointsListEl = document.getElementById('sideEndpointsList');
  const sideEndpointCountEl = document.getElementById('sideEndpointCount');

  let currentResult = null;
  let activeFilter = 'ALL';

  // Tab switching
  sideTabVulns.addEventListener('click', () => {
    sideTabVulns.classList.add('active');
    sideTabDefenses.classList.remove('active');
    if (sideTabEndpoints) sideTabEndpoints.classList.remove('active');
    sideFindingsView.classList.add('active');
    sideDefensesView.classList.remove('active');
    if (sideEndpointsView) sideEndpointsView.classList.remove('active');
  });

  sideTabDefenses.addEventListener('click', () => {
    sideTabDefenses.classList.add('active');
    sideTabVulns.classList.remove('active');
    if (sideTabEndpoints) sideTabEndpoints.classList.remove('active');
    sideDefensesView.classList.add('active');
    sideFindingsView.classList.remove('active');
    if (sideEndpointsView) sideEndpointsView.classList.remove('active');
  });

  if (sideTabEndpoints) {
    sideTabEndpoints.addEventListener('click', () => {
      sideTabEndpoints.classList.add('active');
      sideTabVulns.classList.remove('active');
      sideTabDefenses.classList.remove('active');
      if (sideEndpointsView) sideEndpointsView.classList.add('active');
      sideFindingsView.classList.remove('active');
      sideDefensesView.classList.remove('active');
    });
  }

  // 1. Initial Load & pre-render defenses
  try {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (activeTab && activeTab.url) {
      panelTargetEl.textContent = activeTab.url;
      const initialReport = detectAppliedDefenses({ url: activeTab.url });
      if (initialReport) {
        sideDefenseCountEl.textContent = initialReport.defenses.length;
        sideFirewallStatusEl.textContent = `Active • ${initialReport.firewall.type}`;
        sideFirewallBadgeEl.textContent = initialReport.firewall.status;
        renderSideDefensesList(initialReport.defenses);
      }
    }

    const data = await chrome.storage.local.get('lastAuditResult');
    if (data.lastAuditResult) {
      renderSideResults(data.lastAuditResult);
    }
  } catch (e) {
    console.warn('Sidepanel initial load:', e);
  }

  // 2. Direct Scan
  sideScanBtn.addEventListener('click', async () => {
    sideScanBtn.disabled = true;
    sideScanBtn.innerHTML = '<span>Auditing Defenses & Headers...</span>';

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id || !tab.url) {
        throw new Error('No active web tab found.');
      }

      panelTargetEl.textContent = tab.url;

      // Request full enterprise audit from service worker (including headers, cookies, scripts, defenses)
      const scanResult = await chrome.runtime.sendMessage({ action: 'scanCurrentTab' });

      if (!scanResult || !scanResult.success) {
        throw new Error(scanResult?.error || 'Audit failed to complete.');
      }

      renderSideResults(scanResult);
    } catch (err) {
      console.error('Sidepanel scan error:', err);
      panelTargetEl.textContent = 'Error: ' + err.message;
    } finally {
      sideScanBtn.disabled = false;
      sideScanBtn.innerHTML = '<span>⚡ Scan Current Tab</span>';
    }
  });

  // 3. Export HTML
  exportHtmlBtn.addEventListener('click', () => {
    if (!currentResult) {
      alert('No scan data to export.');
      return;
    }

    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <title>Sentinel Security Audit Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b0e14; color: #e6edf3; padding: 24px; max-width: 900px; margin: 0 auto; }
    .card { background: #151b23; border: 1px solid #30363d; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
    .crit { color: #f85149; } .high { color: #db6d28; } .med { color: #d29922; } .low { color: #58a6ff; }
    pre { background: #090d13; padding: 10px; border-radius: 4px; overflow-x: auto; color: #79c0ff; font-family: monospace; font-size: 12px; }
  </style>
</head>
<body>
  <h1>🛡️ Sentinel Security Audit Report</h1>
  <p><strong>Target URL:</strong> ${currentResult.url} | <strong>Date:</strong> ${currentResult.timestamp}</p>
  <div class="card">
    <h3>🛡️ Perimeter & Firewall Status</h3>
    <p><strong>Status:</strong> ${currentResult.firewall?.status || 'ACTIVE'} (${currentResult.firewall?.type || 'Standard WAF'})</p>
  </div>
  <h2>Applied Defenses (${currentResult.defenses?.length || 0})</h2>
  ${(currentResult.defenses || []).map(d => `
    <div class="card">
      <h4>${d.icon} ${d.name} (${d.status})</h4>
      <p>${d.description}</p>
    </div>
  `).join('')}
  <h2>Security Vulnerabilities (${currentResult.findings.length})</h2>
  ${currentResult.findings.map(f => `
    <div class="card">
      <h3 class="${f.severity === 'CRITICAL' ? 'crit' : f.severity === 'HIGH' ? 'high' : 'med'}">[${f.severity}] ${f.title}</h3>
      <p><strong>Rule ID:</strong> <code>${f.ruleId}</code> | <strong>Line:</strong> ${f.line}</p>
      ${f.snippet ? `<pre><code>${f.redactedSnippet || f.snippet}</code></pre>` : ''}
      <p>💡 <strong>Remediation:</strong> ${f.remediation}</p>
    </div>
  `).join('')}
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Filter chips click
  filterChips.forEach(chip => {
    chip.addEventListener('click', () => {
      filterChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      activeFilter = chip.getAttribute('data-filter');
      applyFiltering();
    });
  });

  // Search input
  sideSearchEl.addEventListener('keyup', applyFiltering);

  function applyFiltering() {
    const query = (sideSearchEl.value || '').toLowerCase();
    const cards = sideFindingsListEl.querySelectorAll('.finding-card');

    cards.forEach(card => {
      const sev = card.getAttribute('data-severity');
      const text = (card.getAttribute('data-search') || '').toLowerCase();
      const matchSev = (activeFilter === 'ALL' || sev === activeFilter);
      const matchQuery = text.includes(query);
      card.style.display = (matchSev && matchQuery) ? 'block' : 'none';
    });
  }

  function renderSideResults(result) {
    currentResult = result;
    const s = result.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0, grade: 'A' };
    const findings = result.findings || [];
    const defenses = result.defenses || [];
    const firewall = result.firewall || { type: 'Host Perimeter Firewall', status: 'ACTIVE' };

    panelTargetEl.textContent = result.url || 'Active Tab';
    sideCritEl.textContent = s.critical;
    sideHighEl.textContent = s.high;
    sideMedEl.textContent = s.medium;
    sideLowEl.textContent = s.low;
    countAllEl.textContent = s.total;
    sideDefenseCountEl.textContent = defenses.length;

    // Firewall status card
    sideFirewallStatusEl.textContent = `Active • ${firewall.type}`;
    sideFirewallBadgeEl.textContent = firewall.status;

    sideGradeBadgeEl.textContent = s.grade || 'A';
    sideGradeBadgeEl.className = `grade-badge grade-${(s.grade || 'A').toLowerCase()}`;

    // Render Findings
    if (findings.length === 0) {
      sideFindingsListEl.innerHTML = `
        <div class="empty-state">
          <p>🛡️</p>
          <p style="font-weight:600; color:#fff;">Zero Vulnerabilities Found</p>
          <p style="font-size:11px;">Scanned in ${result.durationMs || 10}ms. Target passed all local AST and secret rules.</p>
        </div>
      `;
    } else {
      sideFindingsListEl.innerHTML = findings.map(f => `
        <div class="finding-card" data-severity="${f.severity}" data-search="${escapeHtml(f.title)} ${escapeHtml(f.ruleId)} ${escapeHtml(f.snippet || '')}">
          <div class="card-header">
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <div style="display:flex; gap:4px; align-items:center;">
              ${f.cvss ? `<span style="font-size:9px; background:#f8514922; color:#f85149; border:1px solid #f8514944; border-radius:4px; padding:2px 5px; font-weight:600;">CVSS ${f.cvss.score}</span>` : ''}
              <span class="pill pill-${f.severity.toLowerCase()}">${f.severity}</span>
            </div>
          </div>
          <div class="finding-meta">
            <span>⚡ <strong>${f.ruleId}</strong></span> • <span>Line ${f.line}</span>
            ${f.owasp ? ` • <span style="color:#58a6ff;">OWASP ${f.owasp.id} (${f.owasp.name})</span>` : ''}
          </div>
          ${f.snippet ? `<div class="code-preview">${escapeHtml(f.redactedSnippet || f.snippet)}</div>` : ''}
          <div class="remediation-box">
            <strong>💡 Remediation:</strong> ${escapeHtml(f.remediation || 'Remediate flaw before deployment.')}
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
            <span style="font-size:10px; color:#8b949e;">${f.cwe || 'CWE-693'}</span>
            <button class="btn-copy-report" data-finding-id="${f.id}" style="font-size:10px; padding:3px 8px; background:#21262d; border:1px solid #30363d; border-radius:4px; color:#58a6ff; cursor:pointer;">
              📋 Copy Bug Bounty Report
            </button>
          </div>
        </div>
      `).join('');
    }

    // Attach copy report click handler
    sideFindingsListEl.querySelectorAll('.btn-copy-report').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const fId = btn.getAttribute('data-finding-id');
        const finding = (currentResult?.findings || []).find(f => f.id === fId);
        if (finding) {
          const report = generateBugBountyReport(finding, currentResult.url);
          navigator.clipboard.writeText(report).then(() => {
            btn.textContent = '✅ Copied!';
            setTimeout(() => { btn.textContent = '📋 Copy Bug Bounty Report'; }, 2000);
          });
        }
      });
    });

    const totalSurfaceCount = (result.endpoints || []).length + (result.subdomains || []).length + (result.disallowedPaths || []).length;
    if (sideEndpointCountEl) {
      sideEndpointCountEl.textContent = totalSurfaceCount;
    }

    // Render Defenses
    renderSideDefensesList(defenses);

    // Render Endpoints & Tech Stack
    renderSideEndpointsList(result.endpoints || [], result.techStack || [], result.subdomains || [], result.disallowedPaths || []);

    applyFiltering();
  }

  function renderSideEndpointsList(endpoints = [], techStack = [], subdomains = [], disallowedPaths = []) {
    if (!sideEndpointsListEl) return;
    let html = '';

    if (techStack.length > 0) {
      html += `
        <div style="margin-bottom:12px; padding:10px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:11px; font-weight:600; color:#58a6ff; margin-bottom:6px;">🌐 Detected Tech Stack & Footprinting</div>
          <div style="display:flex; flex-wrap:wrap; gap:6px;">
            ${techStack.map(t => `<span style="font-size:10px; background:#21262d; border:1px solid #30363d; border-radius:12px; padding:2px 8px; color:#c9d1d9;">${escapeHtml(t.name)} • ${escapeHtml(t.category)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (subdomains.length > 0) {
      html += `
        <div style="margin-bottom:12px; padding:10px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:11px; font-weight:600; color:#3fb950; margin-bottom:6px;">🛰️ Passive Subdomains Discovered (${subdomains.length})</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px; max-height:120px; overflow-y:auto;">
            ${subdomains.map(s => `<span style="font-family:monospace; font-size:10px; background:#0d1117; border:1px solid #238636; border-radius:4px; padding:2px 6px; color:#7ee787;">${escapeHtml(s)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (disallowedPaths.length > 0) {
      html += `
        <div style="margin-bottom:12px; padding:10px; background:#161b22; border:1px solid #30363d; border-radius:6px;">
          <div style="font-size:11px; font-weight:600; color:#d29922; margin-bottom:6px;">🤖 Robots.txt Disallowed Hidden Paths (${disallowedPaths.length})</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${disallowedPaths.map(p => `<span style="font-family:monospace; font-size:10px; background:#0d1117; border:1px solid #9e6a03; border-radius:4px; padding:2px 6px; color:#e3b341;">${escapeHtml(p)}</span>`).join('')}
          </div>
        </div>
      `;
    }

    if (endpoints.length === 0 && subdomains.length === 0 && disallowedPaths.length === 0) {
      html += `
        <div class="empty-state">
          <p>🔍</p>
          <p style="font-weight:600; color:#fff;">No Explicit API Endpoints Harvested</p>
          <p style="font-size:11px;">Scanned scripts and DOM routes for API patterns.</p>
        </div>
      `;
    } else if (endpoints.length > 0) {
      html += `
        <div style="font-size:11px; font-weight:600; color:#58a6ff; margin-bottom:6px;">⚡ Harvested API Routes (${endpoints.length})</div>
      `;
      html += endpoints.map((ep, idx) => `
        <div class="finding-card" style="padding:8px 12px; margin-bottom:6px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-family:monospace; font-size:11px; color:#79c0ff; word-break:break-all;">${escapeHtml(ep)}</span>
            <span style="font-size:9px; background:#1f6feb22; color:#58a6ff; border:1px solid #1f6feb44; border-radius:4px; padding:1px 6px;">ROUTE #${idx + 1}</span>
          </div>
        </div>
      `).join('');
    }

    sideEndpointsListEl.innerHTML = html;
  }

  function renderSideDefensesList(defenses) {
    if (!sideDefensesListEl) return;
    sideDefensesListEl.innerHTML = (defenses || []).map(d => `
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
