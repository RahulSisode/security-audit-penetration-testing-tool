import { auditWebEnvironment, discoverPassiveSubdomains } from './engine/scanner.js';
import { ChromeSentinelAgent } from './engine/agent.js';

const sentinelAgent = new ChromeSentinelAgent();

/**
 * Validates target URL against SSRF and private network metadata exposure
 */
function isValidHost(urlString) {
  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    // Block cloud metadata services and localhost loopback
    if (
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host === 'metadata.internal' ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host.endsWith('.local')
    ) {
      return false;
    }
    // Block private RFC 1918 / RFC 6598 ranges
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)/.test(host)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Scope and Redirect Safe Fetch Wrapper
 * Prevents SSRF, re-validates redirects against authorized origin, and blocks scope escape.
 */
async function safeFetchWithScopeAndRedirect(url, options = {}, authorizedOrigin = null) {
  if (!isValidHost(url)) {
    throw new Error('Blocked: Target host is invalid, cloud metadata, or restricted.');
  }

  if (authorizedOrigin) {
    try {
      const targetHost = new URL(url).hostname.toLowerCase();
      const authHost = new URL(authorizedOrigin).hostname.toLowerCase();
      if (targetHost !== authHost) {
        throw new Error(`Scope violation: Target ${targetHost} escaped authorized origin ${authHost}`);
      }
    } catch (e) {
      throw new Error('Scope evaluation error: ' + e.message);
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 4000);

  try {
    const resp = await fetch(url, {
      ...options,
      redirect: 'manual',
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    // Handle redirects with strict scope re-validation
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('location');
      if (loc) {
        const resolvedLoc = new URL(loc, url).href;
        if (!isValidHost(resolvedLoc)) {
          throw new Error('Blocked redirect to unapproved or metadata destination: ' + resolvedLoc);
        }
        if (authorizedOrigin) {
          const destHost = new URL(resolvedLoc).hostname.toLowerCase();
          const authHost = new URL(authorizedOrigin).hostname.toLowerCase();
          if (destHost !== authHost) {
            throw new Error(`Scope violation: Redirect to ${destHost} escaped approved scope`);
          }
        }
        return safeFetchWithScopeAndRedirect(resolvedLoc, options, authorizedOrigin);
      }
    }
    return resp;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

/**
 * Fetch HTTP response headers for target URL
 */
async function fetchHttpHeaders(targetUrl) {
  if (!isValidHost(targetUrl)) {
    return {};
  }
  const headers = {};
  const origin = new URL(targetUrl).origin;

  try {
    const resp = await safeFetchWithScopeAndRedirect(targetUrl, {
      method: 'HEAD',
      cache: 'no-cache',
      credentials: 'omit'
    }, origin);
    resp.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });
  } catch (err) {
    // If HEAD is blocked or disallowed by server, fallback to quick GET with scope enforcement
    try {
      const resp = await safeFetchWithScopeAndRedirect(targetUrl, {
        method: 'GET',
        cache: 'no-cache',
        credentials: 'omit'
      }, origin);
      resp.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
    } catch (fallbackErr) {
      console.warn('Could not fetch headers with scope guard for:', targetUrl, fallbackErr.message);
    }
  }
  return headers;
}

/**
 * Audit active tab environment with full browser telemetry
 */
export async function performFullAudit(tab) {
  const startTime = performance.now();
  if (!tab || !tab.id || !tab.url) {
    throw new Error('No active web page available.');
  }

  // Internal Chrome/Edge URLs
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://') || tab.url.startsWith('about:') || tab.url.startsWith('chrome-extension://')) {
    return {
      success: true,
      url: tab.url,
      title: tab.title || 'Internal Browser Page',
      findings: [],
      defenses: [],
      firewall: { type: 'Browser Internal Sandbox', status: 'ISOLATED', isActive: true },
      techStack: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, score: 100, grade: 'A' },
      durationMs: 1,
      timestamp: new Date().toISOString()
    };
  }

  // 1. In-page DOM and script inspection
  let pageData = {
    url: tab.url,
    html: '',
    scripts: [],
    externalScripts: [],
    resources: [],
    metaTags: [],
    hasSRI: false,
    insecureForms: []
  };

  try {
    const injection = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // Collect inline scripts
        const scripts = [];
        document.querySelectorAll('script:not([src])').forEach(s => {
          const code = s.innerText || s.textContent || '';
          if (code.trim().length > 0 && code.length < 500000) {
            scripts.push(code);
          }
        });

        // Collect external script URLs
        const externalScripts = Array.from(document.querySelectorAll('script[src]'))
          .map(s => s.src)
          .filter(Boolean);

        // Collect resource URLs for mixed-content check
        const resources = [];
        document.querySelectorAll('img[src], link[href], iframe[src], audio[src], video[src]').forEach(el => {
          const src = el.src || el.href;
          if (src && (src.startsWith('http://') || src.startsWith('https://'))) {
            resources.push(src);
          }
        });

        // Meta tags
        const metaTags = Array.from(document.querySelectorAll('meta'))
          .map(m => (m.getAttribute('http-equiv') || '') + ' ' + (m.getAttribute('content') || ''));

        // SRI check
        const hasSRI = Array.from(document.querySelectorAll('script[integrity], link[integrity]')).length > 0;

        // Insecure forms
        const insecureForms = Array.from(document.querySelectorAll('form'))
          .map(f => f.action || '')
          .filter(a => a.startsWith('http://') && !a.includes('localhost') && !a.includes('127.0.0.1'));

        const bodyText = document.body ? document.body.innerText.substring(0, 100000) : '';

        // Storage token inspection (JWTs and session keys)
        const storageTokens = [];
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const val = localStorage.getItem(key);
            if (val && (val.includes('.') || val.length > 20)) {
              storageTokens.push({ key: `localStorage.${key}`, value: val });
            }
          }
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const val = sessionStorage.getItem(key);
            if (val && (val.includes('.') || val.length > 20)) {
              storageTokens.push({ key: `sessionStorage.${key}`, value: val });
            }
          }
        } catch (e) {}

        return {
          url: window.location.href,
          html: bodyText,
          scripts,
          externalScripts,
          resources,
          metaTags,
          hasSRI,
          insecureForms,
          storageTokens
        };
      }
    });

    if (injection && injection[0]?.result) {
      pageData = injection[0].result;
    }
  } catch (injErr) {
    console.warn('Script injection restricted on this page:', injErr.message);
  }

  // 2. HTTP response headers
  const headers = await fetchHttpHeaders(tab.url);

  // 3. Cookies audit
  let cookies = [];
  if (chrome.cookies && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
    try {
      cookies = await chrome.cookies.getAll({ url: tab.url });
    } catch (cookieErr) {
      console.warn('Could not read cookies:', cookieErr);
    }
  }

  // 4. Passive Subdomains (crt.sh) + robots.txt & security.txt
  let robotsTxt = '';
  let securityTxt = '';
  let checkedSecurityTxt = false;
  let subdomains = [];

  if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
    try {
      const u = new URL(tab.url);
      const origin = u.origin;
      const [rText, sText, subs] = await Promise.all([
        fetch(`${origin}/robots.txt`, { cache: 'no-cache' }).then(r => r.ok ? r.text() : '').catch(() => ''),
        fetch(`${origin}/.well-known/security.txt`, { cache: 'no-cache' }).then(r => r.ok ? r.text() : '').catch(() => ''),
        discoverPassiveSubdomains(u.hostname).catch(() => [])
      ]);
      robotsTxt = rText || '';
      securityTxt = sText || '';
      checkedSecurityTxt = true;
      subdomains = subs || [];
    } catch (e) {}
  }

  // 5. Run enterprise audit
  const auditRes = auditWebEnvironment({
    ...pageData,
    url: tab.url,
    headers,
    cookies,
    storageTokens: pageData.storageTokens || [],
    robotsTxt,
    securityTxt,
    checkedSecurityTxt,
    subdomains
  });

  const findings = auditRes.findings || [];
  const defenses = auditRes.defenses || [];
  const firewall = auditRes.firewall || { type: 'Host Perimeter Firewall', status: 'ACTIVE', isActive: true };
  const techStack = auditRes.techStack || [];

  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;

  let penalty = (critical * 25) + (high * 12) + (medium * 5) + (low * 1);
  let score = Math.max(0, 100 - penalty);
  let grade = 'A';
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  const durationMs = Math.round(performance.now() - startTime);

  const result = {
    success: true,
    url: tab.url,
    title: tab.title || tab.url,
    findings,
    defenses,
    firewall,
    techStack,
    endpoints: auditRes.endpoints || [],
    disallowedPaths: auditRes.disallowedPaths || [],
    subdomains: auditRes.subdomains || [],
    summary: { critical, high, medium, low, total: findings.length, score, grade },
    durationMs,
    timestamp: new Date().toISOString()
  };

  await chrome.storage.local.set({ lastAuditResult: result });

  // Update extension badge
  try {
    await chrome.action.setBadgeText({ text: findings.length > 0 ? String(findings.length) : '✓' });
    await chrome.action.setBadgeBackgroundColor({
      color: critical > 0 ? '#f85149' : high > 0 ? '#db6d28' : findings.length > 0 ? '#d29922' : '#3fb950'
    });
  } catch (badgeErr) {}

  return result;
}

// Runtime message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'openSidePanel') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.id) {
          await chrome.sidePanel.open({ windowId: tab.windowId });
          sendResponse({ success: true });
        }
      } catch (err) {
        console.error('Failed to open side panel:', err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.action === 'scanCurrentTab') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id || !tab.url) {
          sendResponse({ success: false, error: 'No active web page available.' });
          return;
        }
        const result = await performFullAudit(tab);
        sendResponse(result);
      } catch (err) {
        console.error('Scan error in service worker:', err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.action === 'getLastAuditResult') {
    (async () => {
      const data = await chrome.storage.local.get('lastAuditResult');
      sendResponse(data.lastAuditResult || null);
    })();
    return true;
  }

  if (message.action === 'agentInvestigate') {
    (async () => {
      try {
        const finding = message.finding;
        const hypothesis = sentinelAgent.generateHypothesis(finding);
        const steps = sentinelAgent.planVerificationSteps(finding);
        const triage = sentinelAgent.triageFinding(finding);
        const remediation = sentinelAgent.generateRemediation(finding);
        sendResponse({
          success: true,
          hypothesis,
          steps,
          triage,
          remediation
        });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.action === 'agentConsult') {
    (async () => {
      try {
        const answer = await sentinelAgent.consult(message.query, message.finding);
        sendResponse({ success: true, answer });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
});
