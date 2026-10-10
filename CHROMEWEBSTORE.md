# Chrome Web Store Listing Metadata: Sentinel Security

*Last Updated: 2026-10-09*

---

## 1. Store Listing Details

- **Extension Name**: Sentinel Security — Vulnerability & Secret Scanner
- **Summary / Short Description**: Zero-API security analyzer detecting web vulnerabilities, leaked secrets, DOM XSS, insecure headers, and GitHub code risks.
- **Category**: Developer Tools / Productivity
- **Primary Language**: English

---

## 2. Detailed Description

Sentinel Security is a privacy-first, client-side security scanner that helps developers and security engineers detect vulnerabilities and credential leaks directly within their browser without sending any code or data to external servers.

### Key Capabilities
- **Local AST & Pattern Analysis**: Instantly audits page DOM, inline scripts, and GitHub repositories for DOM XSS, dynamic code execution (eval), and unsafe cryptographic operations.
- **Secret & Key Leak Detection**: Scans page source and scripts for leaked API keys (AWS, OpenAI, Slack, database connection strings, JWT tokens) with high-entropy verification and automatic token masking.
- **Security Posture Score**: Computes an instant letter grade (A to F) based on vulnerability severity.
- **Chrome Side Panel View**: Inspect security findings side-by-side with your code or web application.
- **Standardized Exports**: Export findings directly to SARIF v2.1.0 or self-contained HTML reports for compliance and CI/CD triage.

---

## 3. Permissions Justifications

| Permission | Justification |
| :--- | :--- |
| `storage` | Required to save local scan history and user filter preferences across browser sessions without remote servers. |
| `tabs` | Required to identify the URL and title of the active tab being scanned. |
| `activeTab` | Required to grant temporary script execution access to the active webpage when the user clicks the scan button. |
| `scripting` | Required to inspect DOM elements and inline `<script>` tags on the active page during an on-demand audit. |
| `sidePanel` | Required to open and display the Sentinel Security side panel for side-by-side code inspection. |
| `host_permissions: <all_urls>` | Required to permit security analysis across any web page, localhost development server, or code repository requested by the user. |

---

## 4. Privacy & Data Use Disclosure

- **Does this extension collect or transmit user data?** No. All scanning, AST pattern matching, and secret entropy calculations occur strictly inside the browser runtime. Zero external API calls are made.
- **Single Purpose**: Real-time security auditing and secret leak detection for web applications and source code.
