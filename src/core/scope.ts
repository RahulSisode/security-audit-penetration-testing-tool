import { ScopeManifest } from './types';
import { URL } from 'url';

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

  public canExecuteActiveRequest(): { allowed: boolean; reason?: string } {
    if (!this.manifest.permitActiveTesting) {
      return {
        allowed: false,
        reason: 'Active testing has not received explicit operator authorization.'
      };
    }
    return { allowed: true };
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
