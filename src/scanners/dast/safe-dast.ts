import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { URL } from 'url';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Severity } from '../../core/types';
import { generateFingerprint } from '../../core/fingerprint';

export class SafeDASTScanner extends BaseScanner {
  public readonly id = 'sentinel-safe-dast';
  public readonly name = 'Sentinel Authorized DAST Runner';

  public async isAvailable(): Promise<boolean> {
    return true; // Available for authorized target testing
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (Safe Non-Destructive Dynamic Tester)';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    // Guard: Must be explicitly enabled with confirmed authorized target
    if (!options.dastOptions || !options.dastOptions.enabled || !options.dastOptions.targetUrl) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'SKIPPED',
          executionTimeMs: 0,
          findingsCount: 0,
          errorMessage: 'DAST is optional and was not explicitly authorized/enabled.'
        }
      };
    }

    const targetUrlStr = options.dastOptions.targetUrl;
    let targetUrl: URL;
    try {
      targetUrl = new URL(targetUrlStr);
    } catch {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: `Invalid target URL provided for DAST: ${targetUrlStr}`
        }
      };
    }

    try {
      // 1. Probe Baseline Headers & Security Controls (Strictly Safe)
      const baseRes = await this.performHttpRequest(targetUrl, 'GET');

      if (!baseRes.headers) {
        return {
          findings: [],
          executionResult: {
            scannerId: this.id,
            scannerName: this.name,
            version: await this.getVersion(),
            status: 'FAILED',
            executionTimeMs: Date.now() - startTime,
            findingsCount: 0,
            errorMessage: `Target ${targetUrlStr} unreachable or refused connection.`
          }
        };
      }

      // Check Missing Security Headers
      const missingHeaders: string[] = [];
      if (!baseRes.headers['strict-transport-security'] && targetUrl.protocol === 'https:') {
        missingHeaders.push('Strict-Transport-Security (HSTS)');
      }
      if (!baseRes.headers['x-content-type-options']) {
        missingHeaders.push('X-Content-Type-Options: nosniff');
      }
      if (!baseRes.headers['x-frame-options'] && !baseRes.headers['content-security-policy']?.includes('frame-ancestors')) {
        missingHeaders.push('X-Frame-Options (Clickjacking Protection)');
      }
      if (!baseRes.headers['content-security-policy']) {
        missingHeaders.push('Content-Security-Policy');
      }

      if (missingHeaders.length > 0) {
        const fingerprint = generateFingerprint('DAST_DYNAMIC_FINDING', 'DAST-HEADER-001', targetUrl.origin, 1, missingHeaders.join(','));
        findings.push({
          fingerprint,
          title: `Dynamic Check: Missing HTTP Security Headers (${missingHeaders.length} headers missing)`,
          description: `Live server at ${targetUrl.origin} is missing critical defense-in-depth response headers: ${missingHeaders.join(', ')}.`,
          category: 'DAST_DYNAMIC_FINDING',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          evidence: {
            location: { filePath: targetUrl.origin, startLine: 1 },
            snippet: `Missing: ${missingHeaders.join(', ')}`
          },
          affectedComponent: targetUrl.origin,
          references: {
            owasp: ['A05:2021-Security Misconfiguration'],
            cwe: ['CWE-693']
          },
          exploitPreconditions: 'Browser accesses target endpoint.',
          impact: 'Increased vulnerability to clickjacking, MIME-sniffing attacks, and cross-site scripting.',
          remediation: 'Configure reverse proxy or web server (e.g. Helmet, Nginx) to emit HSTS, CSP, and X-Content-Type-Options.',
          engineId: this.id,
          engineName: this.name,
          ruleId: 'DAST-HEADER-001',
          verificationStatus: 'CONFIRMED',
          reachability: 'REACHABLE',
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString()
        });
      }

      // Check Insecure Cookies (Missing HttpOnly / Secure / SameSite)
      const setCookie = baseRes.headers['set-cookie'];
      if (setCookie) {
        const cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const cookie of cookieArray) {
          const cookieName = cookie.split('=')[0];
          const isHttpOnly = /httponly/i.test(cookie);
          const isSecure = /secure/i.test(cookie);
          const hasSameSite = /samesite/i.test(cookie);

          if (!isHttpOnly || !isSecure || !hasSameSite) {
            const fingerprint = generateFingerprint('DAST_DYNAMIC_FINDING', 'DAST-COOKIE-001', targetUrl.origin, 1, cookieName);
            findings.push({
              fingerprint,
              title: `Dynamic Check: Insecure Cookie Configuration for '${cookieName}'`,
              description: `Cookie '${cookieName}' is missing security flags: ${[!isHttpOnly && 'HttpOnly', !isSecure && 'Secure', !hasSameSite && 'SameSite'].filter(Boolean).join(', ')}.`,
              category: 'DAST_DYNAMIC_FINDING',
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              evidence: {
                location: { filePath: targetUrl.origin, startLine: 1 },
                snippet: cookie
              },
              affectedComponent: `Cookie:${cookieName}`,
              references: {
                owasp: ['A07:2021-Identification and Authentication Failures'],
                cwe: ['CWE-614', 'CWE-1004']
              },
              exploitPreconditions: 'Client executes JavaScript or transmits cookie over unencrypted channel.',
              impact: 'Client-side script cookie theft via XSS, or transmission in plaintext.',
              remediation: 'Set HttpOnly: true, Secure: true, and SameSite: "Lax" or "Strict" on all session cookies.',
              engineId: this.id,
              engineName: this.name,
              ruleId: 'DAST-COOKIE-001',
              verificationStatus: 'CONFIRMED',
              reachability: 'REACHABLE',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        }
      }

      // 2. Safe Canary Non-Destructive Probe (e.g. harmless parameter echo)
      const canaryToken = 'sentinel_canary_' + crypto.randomBytes(8).toString('hex');
      const probeUrl = new URL(targetUrlStr);
      probeUrl.searchParams.set('q', `<${canaryToken}>`);

      const probeRes = await this.performHttpRequest(probeUrl, 'GET');
      if (probeRes.body && probeRes.body.includes(`<${canaryToken}>`)) {
        // Reflected canary without HTML escaping detected!
        const fingerprint = generateFingerprint('DAST_DYNAMIC_FINDING', 'DAST-XSS-REFLECTED', targetUrl.origin, 1, probeUrl.pathname);
        findings.push({
          fingerprint,
          title: `Dynamic Check: Reflected Unescaped Input on ${probeUrl.pathname}`,
          description: `Harmless canary token <${canaryToken}> was reflected unencoded in server response.`,
          category: 'DAST_DYNAMIC_FINDING',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          evidence: {
            location: { filePath: targetUrl.origin + probeUrl.pathname, startLine: 1 },
            snippet: `Reflected payload in response body: <${canaryToken}>`
          },
          affectedComponent: probeUrl.pathname,
          references: {
            owasp: ['A03:2021-Injection'],
            cwe: ['CWE-79']
          },
          exploitPreconditions: 'Victim visits crafted URL with injected query parameter.',
          impact: 'Reflected Cross-Site Scripting (XSS).',
          remediation: 'HTML-encode or sanitize all reflected query parameters before rendering into HTML responses.',
          engineId: this.id,
          engineName: this.name,
          ruleId: 'DAST-XSS-REFLECTED',
          verificationStatus: 'CONFIRMED',
          reachability: 'REACHABLE',
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString()
        });
      }

      return {
        findings,
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'EXECUTED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: findings.length
        }
      };
    } catch (err: any) {
      return {
        findings: [],
        executionResult: {
          scannerId: this.id,
          scannerName: this.name,
          version: await this.getVersion(),
          status: 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: err?.message || String(err)
        }
      };
    }
  }

  private performHttpRequest(target: URL, method: string): Promise<{ statusCode?: number; headers?: http.IncomingHttpHeaders; body: string }> {
    return new Promise((resolve) => {
      const isHttps = target.protocol === 'https:';
      const client = isHttps ? https : http;

      const req = client.request(
        target,
        {
          method,
          timeout: 10000,
          headers: {
            'User-Agent': 'Sentinel-Security-DAST/1.0 (Authorized Audit Probe)'
          }
        },
        (res) => {
          let body = '';
          res.on('data', chunk => {
            if (body.length < 500000) body += chunk.toString('utf8');
          });
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, headers: res.headers, body });
          });
        }
      );

      req.on('error', () => {
        resolve({ body: '' });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ body: '' });
      });

      req.end();
    });
  }
}
