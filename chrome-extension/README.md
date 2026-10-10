# 🛡️ WebGuard — Chrome Extension (Manifest V3)

A **zero-API, 100% local, client-side website security & vulnerability scanner** for Google Chrome, Microsoft Edge, Brave, and Arc browsers.

---

## ⚡ Key Highlights

- **100% Local & Zero-API:** All DOM, header, secret, cookie, and vulnerability checks execute directly in the browser. Zero cloud dependencies, zero external tracking, zero data leakage.
- **Deep Reconnaissance:** Passive crt.sh subdomain discovery, RFC 9116 `security.txt` & `robots.txt` harvester, and technology stack fingerprinting.
- **WAF & Perimeter Shield Detection:** Accurately identifies Layer 7 Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Fastly, Sucuri, Cloudfront).
- **Leaked Secret & High-Entropy Detection:** Scans DOM scripts and inline assets with Shannon entropy calculation for AWS, OpenAI, GitHub, Stripe, Slack, and private keys.
- **Header & Defense Verification:** Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Server banners.
- **Cookie Security Audit:** Audits flags for `HttpOnly`, `Secure`, and `SameSite` on all site cookies.
- **JWT & Token Auditor:** Analyzes LocalStorage & SessionStorage tokens for `alg: "none"`, missing expiration (`exp`), and sensitive payload keys.
- **1-Click Bug Bounty Reports:** Automatically formats complete vulnerability evidence into ready-to-submit HackerOne, Bugcrowd, and markdown reports with CVSS v3.1 scoring.

---

## 📦 How to Install in Chrome, Edge, Brave & Arc

1. Open your browser and navigate to the extensions page:
   - **Chrome:** `chrome://extensions`
   - **Brave:** `brave://extensions`
   - **Edge:** `edge://extensions`
2. Enable **Developer mode** toggle in the top-right corner.
3. Click the **Load unpacked** button in the top-left toolbar.
4. Select this directory:
   ```text
   /path/to/webguard/chrome-extension
   ```
5. Pin **WebGuard** to your browser toolbar.
6. Open any website, click the WebGuard shield icon, and click **⚡ Scan Active Page / Repo**.

---

## 📄 License

Licensed under the Apache-2.0 License.
