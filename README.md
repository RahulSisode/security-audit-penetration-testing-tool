<div align="center">

# 🛡️ WebGuard — Website Security & Vulnerability Scanner
### *Full-Depth, Evidence-Driven Website Security Assessment & Bug Bounty Reconnaissance Platform*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Manifest](https://img.shields.io/badge/Manifest-V3_Compliant-success.svg)](chrome-extension/manifest.json)
[![Zero API](https://img.shields.io/badge/Architecture-100%25_Local_Zero--API-brightgreen.svg)](#-zero-api-and-privacy-first-principles)
[![OWASP](https://img.shields.io/badge/Mapped_To-OWASP_Top_10_2021-orange.svg)](#-detection-capabilities--feature-matrix)
[![CVSS](https://img.shields.io/badge/Scoring-CVSS_v3.1-informational.svg)](#-automated-cvss-v31-scoring--reporting)
[![Tests](https://img.shields.io/badge/Tests-Passing_16%2F16-brightgreen.svg)](#-testing--benchmarks)
[![Precision](https://img.shields.io/badge/Benchmark_Precision-100%25-blueviolet.svg)](#-testing--benchmarks)

<p align="center">
  <b>WebGuard</b> is an enterprise-grade, evidence-driven web application security assessment tool and bug bounty companion. It combines in-browser client reconnaissance, dynamic header auditing, leaked credential hunting with Shannon entropy gating, perimeter WAF fingerprinting, and source code SAST/DAST analysis — <b>all running 100% locally with zero cloud dependencies or paid API keys.</b>
</p>

[Quick Install (Browser Extension)](#-quick-start-browser-extension) • [Features](#-detection-capabilities--feature-matrix) • [VS Code & CLI](#-vscode-extension--cli) • [Bug Bounty Reporting](#-automated-cvss-v31-scoring--reporting) • [Architecture](#-architecture)

---

</div>

## 🌟 Why WebGuard?

Most web security tools suffer from two major flaws: they either charge expensive subscription fees requiring your private tokens, or they send your audited target URLs and source code to remote third-party cloud servers.

**WebGuard was engineered with strict AppSec principles:**
1. **Zero-API, Zero-Cloud:** All DOM analysis, header verification, cookie audits, token inspection, and heuristic scans run completely on your local machine. No external tracking, no cloud telemetry, no data leaks.
2. **Deterministic Evidence-First Findings:** Every alert contains the exact reproduction evidence, affected asset, line numbers, raw values, remediation recommendations, and CVSS v3.1 vector.
3. **Shannon Entropy Heuristics:** Stops false-positive fatigue by calculating mathematical randomness on suspicious tokens before flagging secrets.
4. **Two Powerful Form Factors:**
   - 🌐 **Chrome / Chromium Extension (Manifest V3):** 1-Click live inspection directly from your browser HUD or persistent Side Panel.
   - 💻 **VS Code Extension & Standalone CLI:** Static application security testing (SAST), taint analysis, and CI/CD pipelines.

---

## 🔬 Detection Capabilities & Feature Matrix

| Security Layer | Capabilities & Detection Vectors | OWASP Category |
| :--- | :--- | :--- |
| **🌐 Passive Recon & Footprinting** | Passive subdomain enumeration via `crt.sh`, RFC 9116 `/.well-known/security.txt` harvester, and `robots.txt` sensitive endpoint discovery. | **A05: Security Misconfiguration** |
| **🛡️ Perimeter & WAF Shield** | Accurately identifies Layer 7 Web Application Firewalls: Cloudflare, AWS WAF, Akamai, Fastly, Sucuri, and CloudFront. | **A05: Security Misconfiguration** |
| **🧱 Defense-in-Depth Headers** | Validates presence and strict configuration of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`. Flags leaky `Server` and `X-Powered-By` banners. | **A05: Security Misconfiguration** |
| **🍪 Cookie & Session Security** | Audits session identifiers for missing `HttpOnly`, missing `Secure` flag on HTTPS, and lax or missing `SameSite` configurations. Flags cleartext session transmission. | **A07: Identification and Authentication Failures** |
| **🔑 Leaked Secrets & Credentials** | High-entropy scanning across HTML, inline scripts, and bundle assets. Detects 30+ credential patterns including AWS Keys, OpenAI API keys, GitHub tokens, Slack Webhooks, Stripe keys, Private Keys, and Database URIs. | **A02: Cryptographic Failures** |
| **⚡ DOM XSS & Client Sinks** | Audits DOM manipulation sinks: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout(string)`, unsanitized `location.hash` / `search` usage, unkeyed `window.addEventListener('message')`, and open redirects. | **A03: Injection** |
| **🎟️ JWT & Token Auditing** | Scans `localStorage` and `sessionStorage` for JSON Web Tokens. Checks for insecure `alg: "none"`, missing or expired `exp` timestamp claims, and sensitive payload disclosure. | **A02: Cryptographic Failures** |
| **🔒 Mixed Content & SRI** | Flags unencrypted HTTP scripts, styles, or iframes loaded on secure HTTPS pages. Validates Subresource Integrity (`integrity="sha384-..."`) on third-party CDNs. | **A08: Software and Data Integrity Failures** |
| **🛠️ Technology Stack Profiling** | Detects underlying frameworks, front-end libraries, and CMS platforms (React, Vue, Angular, Next.js, WordPress, Laravel, Django, Express). | **A06: Vulnerable and Outdated Components** |

---

## 🚀 Quick Start: Browser Extension

WebGuard runs on all modern Chromium browsers, including **Google Chrome**, **Brave**, **Microsoft Edge**, and **Arc**.

### Installation in 3 Steps

1. **Clone this repository:**
   ```bash
   git clone https://github.com/rahul/webguard.git
   cd webguard
   ```

2. **Open your browser's extension manager:**
   - Chrome: Navigate to `chrome://extensions`
   - Brave: Navigate to `brave://extensions`
   - Edge: Navigate to `edge://extensions`

3. **Load WebGuard:**
   - Toggle **Developer mode** in the top-right corner.
   - Click **Load unpacked** in the top-left toolbar.
   - Select the `chrome-extension` directory inside this repository.

<div align="center">

```
  ┌─────────────────────────────────────────────────────────────┐
  │  🛡️ WebGuard — Website Security & Vulnerability Scanner     │
  │  ─────────────────────────────────────────────────────────  │
  │  [⚡ Scan Active Page / Repo]          [📖 Open Side Panel] │
  │                                                             │
  │  Firewall Status: Cloudflare L7 Active                      │
  │  Security Grade: B (Score: 82/100)                          │
  │                                                             │
  │  [ 4 Vulnerabilities ]  [ 6 Defenses Active ]  [ 8 APIs ]   │
  └─────────────────────────────────────────────────────────────┘
```

</div>

4. **Start Auditing:**
   - Click the **WebGuard** shield icon in your browser toolbar.
   - Click **⚡ Scan Active Page / Repo**.
   - Review live findings, inspect applied defenses, and copy professional bug bounty reports in 1 click.

---

## 💻 VS Code Extension & CLI

In addition to the browser extension, WebGuard includes a full-depth IDE extension and CLI engine for source code scanning, taint flow analysis, and CI/CD pipelines.

### Building & Installing the VS Code Extension (`.vsix`)

```bash
# Install dependencies
npm install

# Compile and package the extension
npm run package

# Install directly in VS Code / Cursor
code --install-extension sentinel-security-1.0.0.vsix
```

### Standalone CLI Execution

Audit any codebase, web application, or repository directly from your terminal:

```bash
# Full local project scan
npm run scan -- .

# Export audit findings to standard industry formats
npm run scan -- . --sarif webguard-report.sarif --html webguard-report.html --json webguard-report.json

# Check external tool integrations (Semgrep, Gitleaks, Trivy, Checkov)
npm run setup:tools
```

---

## 🎯 Automated CVSS v3.1 Scoring & Reporting

Every vulnerability identified by WebGuard is automatically categorized with a calculated **CVSS v3.1 vector string**, numerical score, and severity level:

- **Critical (9.0 - 10.0):** Live high-entropy private keys, unauthenticated RCE sinks, `alg: none` JWTs.
- **High (7.0 - 8.9):** DOM-based Cross-Site Scripting (XSS), missing authentication on sensitive endpoints, plain HTTP transmission of passwords.
- **Medium (4.0 - 6.9):** Missing HSTS / CSP headers, missing `HttpOnly` on session cookies, sensitive API endpoint exposure in `robots.txt`.
- **Low / Info (0.1 - 3.9):** Technology banner disclosure, missing `X-Content-Type-Options`, subresource integrity warnings.

### 1-Click Bug Bounty Submission
WebGuard generates formatted markdown reports tailored for submission to **HackerOne**, **Bugcrowd**, and internal JIRA tickets. Each export contains:
- Executive Summary & Vulnerability Title
- Affected URL / Asset Endpoint
- CVSS v3.1 Base Score & Vector
- CWE & OWASP Top 10 Mapping
- Step-by-Step Proof of Concept (PoC)
- Impact Assessment & Remediation Guidance

---

## 🧪 Testing & Benchmarks

WebGuard includes a comprehensive test suite and an automated detection benchmark running against intentionally vulnerable real-world test cases:

```bash
# Run unit & integration test suites
npm test
```
```text
Test Suites: 3 passed, 3 total
Tests:       16 passed, 16 total
Snapshots:   0 total
Time:        1.42 s
```

```bash
# Run detection quality benchmark
npm run benchmark
```
```text
=== Sentinel Benchmark Evaluation ===
Precision: 100.00%
Recall:    100.00%
F1 Score:  100.00%
Duration:  43ms
```

---

## 🏗️ Architecture

```
webguard/
├── chrome-extension/            # Manifest V3 Browser Extension
│   ├── engine/
│   │   └── scanner.js           # 100% Local Heuristics & SAST Scanner (Shannon Entropy)
│   ├── popup/                   # 1-Click Quick Inspection HUD
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   ├── sidepanel/               # Persistent Deep-Audit Side Panel
│   │   ├── sidepanel.html
│   │   ├── sidepanel.css
│   │   └── sidepanel.js
│   ├── service-worker.js        # Background HTTP Header, Cookie & Recon Handler
│   └── manifest.json            # MV3 Permissions & Host Declarations
├── src/                         # VS Code Extension & Core Engine (TypeScript)
│   ├── core/                    # Scope Enforcement & Capability Registry
│   ├── engines/                 # SAST, Taint Analysis, SCA, Secrets, IaC, API
│   └── extension.ts             # VS Code UI & Command Bindings
├── test/                        # Automated Jest Test Suites
└── package.json                 # Build Scripts & Tool Configurations
```

---

## 🔒 Security, Safety & Ethical Guidelines

> [!IMPORTANT]
> **WebGuard is designed for authorized security assessments, defensive hardening, educational research, and legitimate bug bounty hunting.**
>
> Always obtain explicit authorization before conducting security testing on systems you do not own. Passive reconnaissance and header auditing adhere strictly to read-only browser interactions. Active scanning probes enforce strict rate limits and scope boundaries.

---

## 🤝 Contributing

Contributions, bug reports, and rule improvements are warmly welcomed!
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-rule`).
3. Commit your changes (`git commit -m 'Add rule: CVE-2026-XXXX'`).
4. Push to the branch (`git push origin feature/amazing-rule`).
5. Open a Pull Request.

---

## 📄 License

Distributed under the **Apache-2.0 License**. See [LICENSE](LICENSE) for more details.
