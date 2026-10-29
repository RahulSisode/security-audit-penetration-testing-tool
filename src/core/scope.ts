import { ScopeManifest } from './types';
import { URL } from 'url';
import * as http from 'http';
import * as https from 'https';

export interface ScopeValidationResult {
  isAuthorized: boolean;
  normalizedUrl: string;
  matchedHostname?: string;
  reason?: string;
}

export interface ScopeAuditEvent {
  timestamp: string;
  action: 'INITIALIZED' | 'TARGET_CHECKED' | 'REDIRECT_CHECKED' | 'EXCLUDED' | 'UNAUTHORIZED';
  url: string;
  isAuthorized: boolean;
  reason?: string;
}

export interface ScopeHttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  isActiveTest?: boolean;
  maxRedirects?: number;
  allowRealExternalTargets?: boolean;
}

export interface ScopeHttpResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  finalUrl: string;
  redirectsFollowed: number;
}

export class ScopeManager {
  private manifest: ScopeManifest;
  private auditLog: ScopeAuditEvent[] = [];
  private requestCount = 0;

  constructor(manifest: Partial<ScopeManifest> & { targetOrigin: string }) {
    let hostname = '';
    try {
      hostname = new URL(manifest.targetOrigin).hostname;
    } catch {
      hostname = manifest.targetOrigin;
    }

    this.manifest = {
      targetOrigin: manifest.targetOrigin,
      authorizedHostnames: manifest.authorizedHostnames || [hostname],
      excludedPaths: manifest.excludedPaths || ['/logout', '/signout', '/delete', '/deactivate'],
      permitActiveTesting: manifest.permitActiveTesting ?? false,
      maxRequestsPerSecond: manifest.maxRequestsPerSecond || 5,
      maxConcurrency: manifest.maxConcurrency || 2,
      timeoutMs: manifest.timeoutMs || 10000,
      approvedBy: manifest.approvedBy || 'Security Operator',
      approvalTimestamp: manifest.approvalTimestamp || new Date().toISOString()
    };

    this.auditLog.push({
      timestamp: new Date().toISOString(),
      action: 'INITIALIZED',
      url: this.manifest.targetOrigin,
      isAuthorized: true,
      reason: `Scope initialized for hostnames: ${this.manifest.authorizedHostnames.join(', ')}`
    });
  }

  public getManifest(): Readonly<ScopeManifest> {
    return { ...this.manifest };
  }

  public getAuditTrail(): ReadonlyArray<ScopeAuditEvent> {
    return [...this.auditLog];
  }

  public validateUrl(rawUrl: string): ScopeValidationResult {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      const res: ScopeValidationResult = {
        isAuthorized: false,
        normalizedUrl: rawUrl,
        reason: 'Malformed or unparseable URL.'
      };
      this.recordAudit('UNAUTHORIZED', rawUrl, false, res.reason);
      return res;
    }

    const host = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();

    // Block dangerous metadata endpoints (SSRF protection)
    if (this.isMetadataOrDangerousHost(host)) {
      const res: ScopeValidationResult = {
        isAuthorized: false,
        normalizedUrl: parsed.href,
        reason: `Access to metadata or restricted infrastructure hostname "${host}" is strictly forbidden.`
      };
      this.recordAudit('UNAUTHORIZED', parsed.href, false, res.reason);
      return res;
    }

    // Check excluded paths
    for (const excluded of this.manifest.excludedPaths) {
      if (pathname.startsWith(excluded.toLowerCase())) {
        const res: ScopeValidationResult = {
          isAuthorized: false,
          normalizedUrl: parsed.href,
          reason: `Path "${pathname}" is explicitly excluded in scope manifest.`
        };
        this.recordAudit('EXCLUDED', parsed.href, false, res.reason);
        return res;
      }
    }

    // Check authorized hostnames
    let matchedHost: string | undefined;
    for (const authHost of this.manifest.authorizedHostnames) {
      const cleanAuth = authHost.toLowerCase().trim();
      if (cleanAuth.startsWith('*.')) {
        const domainSuffix = cleanAuth.substring(2);
        if (host === domainSuffix || host.endsWith('.' + domainSuffix)) {
          matchedHost = cleanAuth;
          break;
        }
      } else if (host === cleanAuth) {
        matchedHost = cleanAuth;
        break;
      }
    }

    if (!matchedHost) {
      const res: ScopeValidationResult = {
        isAuthorized: false,
        normalizedUrl: parsed.href,
        reason: `Hostname "${host}" is not in the approved authorized list [${this.manifest.authorizedHostnames.join(', ')}].`
      };
      this.recordAudit('UNAUTHORIZED', parsed.href, false, res.reason);
      return res;
    }

    const res: ScopeValidationResult = {
      isAuthorized: true,
      normalizedUrl: parsed.href,
      matchedHostname: matchedHost
    };
    this.recordAudit('TARGET_CHECKED', parsed.href, true);
    return res;
  }

  /**
   * Revalidates HTTP redirects to ensure location targets never escape approved scope.
   */
  public validateRedirect(originalUrl: string, targetRedirectUrl: string): ScopeValidationResult {
    let resolvedUrl: string;
    try {
      resolvedUrl = new URL(targetRedirectUrl, originalUrl).href;
    } catch {
      const res: ScopeValidationResult = {
        isAuthorized: false,
        normalizedUrl: targetRedirectUrl,
        reason: `Unparseable redirect target "${targetRedirectUrl}" from "${originalUrl}".`
      };
      this.recordAudit('UNAUTHORIZED', targetRedirectUrl, false, res.reason);
      return res;
    }

    const result = this.validateUrl(resolvedUrl);
    if (!result.isAuthorized) {
      const auditReason = `Redirect from "${originalUrl}" to "${resolvedUrl}" was blocked: ${result.reason}`;
      this.recordAudit('UNAUTHORIZED', resolvedUrl, false, auditReason);
      return {
        ...result,
        reason: auditReason
      };
    }

    this.recordAudit('REDIRECT_CHECKED', resolvedUrl, true, `Authorized redirect from "${originalUrl}" to "${resolvedUrl}"`);
    return result;
  }

  /**
   * Sanitizes and verifies candidate URLs suggested by website DOM or AI models.
   * Ensures external content or model hallucinations can NEVER expand or mutate the authorized scope.
   */
  public sanitizeCandidateUrl(
    rawCandidate: string,
    source: 'AI_OUTPUT' | 'WEBSITE_CONTENT' | 'USER_INPUT'
  ): ScopeValidationResult {
    const trimmed = (rawCandidate || '').trim();
    if (!trimmed) {
      return {
        isAuthorized: false,
        normalizedUrl: '',
        reason: `Empty candidate URL provided from ${source}.`
      };
    }

    let absoluteCandidate = trimmed;
    if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
      try {
        absoluteCandidate = new URL(trimmed, this.manifest.targetOrigin).href;
      } catch {
        return {
          isAuthorized: false,
          normalizedUrl: trimmed,
          reason: `Could not resolve relative candidate from ${source} against target origin.`
        };
      }
    }

    const validation = this.validateUrl(absoluteCandidate);
    if (!validation.isAuthorized) {
      const reason = `Candidate URL from ${source} [${absoluteCandidate}] is out-of-scope and rejected: ${validation.reason}`;
      this.recordAudit('UNAUTHORIZED', absoluteCandidate, false, reason);
      return {
        isAuthorized: false,
        normalizedUrl: absoluteCandidate,
        reason
      };
    }

    return validation;
  }

  public canExecuteActiveRequest(): { allowed: boolean; reason?: string } {
    if (!this.manifest.permitActiveTesting) {
      return {
        allowed: false,
        reason: 'Active testing has not received explicit operator authorization.'
      };
    }
    return { allowed: true };
  }

  /**
   * Detects whether a URL targets a real external production host on the public internet.
   */
  public isRealExternalTarget(rawUrl: string): boolean {
    try {
      const parsed = new URL(rawUrl);
      const host = parsed.hostname.toLowerCase();
      // Safe test/local hosts
      if (
        host === 'localhost' ||
        host === '127.0.0.1' ||
        host === '::1' ||
        host.endsWith('.test') ||
        host.endsWith('.example') ||
        host.endsWith('.invalid') ||
        host.endsWith('.localhost') ||
        host.endsWith('.local')
      ) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  private isMetadataOrDangerousHost(host: string): boolean {
    return (
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host === 'metadata.internal' ||
      host === '100.100.100.200'
    );
  }

  private recordAudit(
    action: ScopeAuditEvent['action'],
    url: string,
    isAuthorized: boolean,
    reason?: string
  ): void {
    this.auditLog.push({
      timestamp: new Date().toISOString(),
      action,
      url,
      isAuthorized,
      reason
    });
  }
}

/**
 * Scope-Enforced Safe HTTP Client
 * Validates scope and permissions prior to every request, intercepts redirects, and prevents scanning real external targets.
 */
export class ScopeEnforcedHttpClient {
  constructor(private scopeManager: ScopeManager) {}

  public async request(targetUrlStr: string, options: ScopeHttpRequestOptions = {}): Promise<ScopeHttpResponse> {
    const isActive = options.isActiveTest ?? false;

    // 1. Authorization check for active testing
    if (isActive) {
      const activeCheck = this.scopeManager.canExecuteActiveRequest();
      if (!activeCheck.allowed) {
        throw new Error(`[ScopeEnforcedHttpClient] Active request blocked: ${activeCheck.reason}`);
      }
    }

    // 2. Prevent scanning real external targets unless explicitly permitted
    if (!options.allowRealExternalTargets && this.scopeManager.isRealExternalTarget(targetUrlStr)) {
      throw new Error(`[ScopeEnforcedHttpClient] Safety block: Cannot run active security scans against real external target (${targetUrlStr}).`);
    }

    // 3. Pre-flight URL validation
    const scopeCheck = this.scopeManager.validateUrl(targetUrlStr);
    if (!scopeCheck.isAuthorized) {
      throw new Error(`[ScopeEnforcedHttpClient] Out-of-scope target rejected: ${scopeCheck.reason}`);
    }

    return this.executeWithRedirectTracking(targetUrlStr, options, 0);
  }

  private executeWithRedirectTracking(
    currentUrlStr: string,
    options: ScopeHttpRequestOptions,
    redirectsFollowed: number
  ): Promise<ScopeHttpResponse> {
    const maxRedirects = options.maxRedirects ?? 5;
    if (redirectsFollowed > maxRedirects) {
      return Promise.reject(new Error(`[ScopeEnforcedHttpClient] Maximum redirects exceeded (${maxRedirects}).`));
    }

    return new Promise((resolve, reject) => {
      let currentUrl: URL;
      try {
        currentUrl = new URL(currentUrlStr);
      } catch (err: any) {
        return reject(new Error(`[ScopeEnforcedHttpClient] Malformed URL: ${err.message}`));
      }

      const isHttps = currentUrl.protocol === 'https:';
      const client = isHttps ? https : http;
      const method = options.method || 'GET';

      const req = client.request(
        currentUrl,
        {
          method,
          timeout: options.timeoutMs || 10000,
          headers: {
            'User-Agent': 'Sentinel-Security/1.0 (Scope-Enforced-Audit)',
            ...(options.headers || {})
          }
        },
        async (res) => {
          const status = res.statusCode || 0;

          // Handle Redirects: 301, 302, 303, 307, 308
          if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
            const redirectLocation = res.headers.location;
            const redirectValidation = this.scopeManager.validateRedirect(currentUrlStr, redirectLocation);

            if (!redirectValidation.isAuthorized) {
              res.resume(); // drain response
              return reject(new Error(`[ScopeEnforcedHttpClient] Redirect to out-of-scope target blocked: ${redirectValidation.reason}`));
            }

            // Follow redirect to verified target
            try {
              const nextResp = await this.executeWithRedirectTracking(
                redirectValidation.normalizedUrl,
                options,
                redirectsFollowed + 1
              );
              return resolve(nextResp);
            } catch (redirErr) {
              return reject(redirErr);
            }
          }

          let body = '';
          res.on('data', chunk => {
            if (body.length < 1000000) {
              body += chunk.toString('utf8');
            }
          });
          res.on('end', () => {
            resolve({
              statusCode: status,
              headers: res.headers,
              body,
              finalUrl: currentUrlStr,
              redirectsFollowed
            });
          });
        }
      );

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`[ScopeEnforcedHttpClient] Request timed out on ${currentUrlStr}`));
      });

      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }
}

