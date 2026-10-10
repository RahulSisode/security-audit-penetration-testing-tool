import * as fs from 'fs';
import * as path from 'path';
import { Severity, ReachabilityStatus } from '../../core/types';
import { DiscoveredPackage } from './manifest-parser';
import { WorkspaceScanner } from '../../utils/workspace';

export interface SecurityAdvisory {
  id: string; // e.g. CVE-2023-45133 or GHSA-...
  cve: string;
  cwe: string[];
  packageName: string;
  ecosystem: string;
  vulnerableVersionRange: string;
  fixedVersion: string;
  title: string;
  description: string;
  severity: Severity;
  cvss: number;
}

export const KNOWN_OFFLINE_ADVISORIES: SecurityAdvisory[] = [
  {
    id: 'GHSA-4w7h-592f-m5fg',
    cve: 'CVE-2023-26159',
    cwe: ['CWE-1333'],
    packageName: 'follow-redirects',
    ecosystem: 'npm',
    vulnerableVersionRange: '< 1.15.4',
    fixedVersion: '1.15.4',
    title: 'follow-redirects Improper Input Validation / ReDoS',
    description: 'follow-redirects prior to 1.15.4 is vulnerable to Regular Expression Denial of Service (ReDoS).',
    severity: 'HIGH',
    cvss: 7.5
  },
  {
    id: 'GHSA-76p3-8jx3-jpfq',
    cve: 'CVE-2023-45133',
    cwe: ['CWE-502'],
    packageName: 'babel/traverse',
    ecosystem: 'npm',
    vulnerableVersionRange: '< 7.23.2',
    fixedVersion: '7.23.2',
    title: 'Babel vulnerable to arbitrary code execution when compiling specific crafted code',
    description: 'Using Babel to compile untrusted code with Babel plugins could lead to code execution.',
    severity: 'HIGH',
    cvss: 8.1
  },
  {
    id: 'GHSA-36p3-wjmg-h94x',
    cve: 'CVE-2022-25883',
    cwe: ['CWE-1333'],
    packageName: 'semver',
    ecosystem: 'npm',
    vulnerableVersionRange: '< 7.5.2',
    fixedVersion: '7.5.2',
    title: 'semver vulnerable to Regular Expression Denial of Service',
    description: 'The semver package is vulnerable to ReDoS when comparing crafted semver strings.',
    severity: 'MEDIUM',
    cvss: 6.5
  },
  {
    id: 'GHSA-vfrx-2q38-x947',
    cve: 'CVE-2023-28155',
    cwe: ['CWE-918'],
    packageName: 'request',
    ecosystem: 'npm',
    vulnerableVersionRange: '<= 2.88.2',
    fixedVersion: 'None (Deprecated, migrate to axios/fetch/undici)',
    title: 'request package SSRF via bypass of tunnel redirection',
    description: 'The request package is unmaintained and vulnerable to SSRF across redirects.',
    severity: 'HIGH',
    cvss: 7.5
  },
  {
    id: 'GHSA-6vfc-2cxq-cd9p',
    cve: 'CVE-2023-32681',
    cwe: ['CWE-200'],
    packageName: 'requests',
    ecosystem: 'pypi',
    vulnerableVersionRange: '< 2.31.0',
    fixedVersion: '2.31.0',
    title: 'Requests library leaks Proxy-Authorization headers on redirect to HTTPS',
    description: 'When requests follows an HTTP-to-HTTPS redirect, the Proxy-Authorization header is unintentionally forwarded.',
    severity: 'MEDIUM',
    cvss: 6.1
  },
  {
    id: 'GHSA-w596-4wvx-j9j6',
    cve: 'CVE-2023-43804',
    cwe: ['CWE-444'],
    packageName: 'urllib3',
    ecosystem: 'pypi',
    vulnerableVersionRange: '< 2.0.7',
    fixedVersion: '2.0.7',
    title: 'urllib3 Cookie Leaking on Redirect',
    description: 'urllib3 does not remove the Cookie request header when following redirects to different hosts.',
    severity: 'HIGH',
    cvss: 8.8
  },
  {
    id: 'GHSA-r556-5269-cf5s',
    cve: 'CVE-2024-21626',
    cwe: ['CWE-200'],
    packageName: 'runc',
    ecosystem: 'golang',
    vulnerableVersionRange: '< 1.1.12',
    fixedVersion: '1.1.12',
    title: 'runc container breakout vulnerability via file descriptor leak',
    description: 'runc in versions before 1.1.12 leaks internal file descriptors allowing container breakout to the host.',
    severity: 'CRITICAL',
    cvss: 9.8
  },
  {
    id: 'GHSA-9px4-7jvh-q2x2',
    cve: 'CVE-2022-24765',
    cwe: ['CWE-1321'],
    packageName: 'lodash',
    ecosystem: 'npm',
    vulnerableVersionRange: '< 4.17.21',
    fixedVersion: '4.17.21',
    title: 'lodash Prototype Pollution via template',
    description: 'Command injection and prototype pollution in lodash template parsing.',
    severity: 'HIGH',
    cvss: 7.4
  }
];

export class SCAReachabilityAnalyzer {
  public static isPackageReachable(
    packageName: string,
    workspaceRoot: string,
    scannableFiles: string[]
  ): { reachable: ReachabilityStatus; evidence?: string } {
    const importPatterns = [
      new RegExp(`require\\s*\\(\\s*['"]${packageName}(?:/[^'"]*)?['"]\\s*\\)`),
      new RegExp(`from\\s+['"]${packageName}(?:/[^'"]*)?['"]`),
      new RegExp(`import\\s+.*?from\\s+['"]${packageName}(?:/[^'"]*)?['"]`),
      new RegExp(`import\\s+${packageName}`),
      new RegExp(`import\\s+['"]${packageName}['"]`)
    ];

    for (const filePath of scannableFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        for (const pattern of importPatterns) {
          if (pattern.test(content)) {
            const rel = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');
            return {
              reachable: 'REACHABLE',
              evidence: `Package '${packageName}' is directly imported in ${rel}`
            };
          }
        }
      } catch {}
    }

    return {
      reachable: 'UNKNOWN',
      evidence: `No direct static import found for '${packageName}' in scanned source files; may be transitive or dynamically loaded.`
    };
  }

  public static compareSemver(version: string, range: string): boolean {
    // Simple robust semver range evaluator for <, <=, ==, >
    const cleanVer = version.replace(/[^0-9.]/g, '');
    const vParts = cleanVer.split('.').map(n => parseInt(n, 10) || 0);

    const rangeMatch = range.match(/(<|<=|==|>|>=)\s*([0-9.]+)/);
    if (!rangeMatch) return false;

    const op = rangeMatch[1];
    const targetParts = rangeMatch[2].split('.').map(n => parseInt(n, 10) || 0);

    const cmp = this.cmpParts(vParts, targetParts);

    if (op === '<') return cmp < 0;
    if (op === '<=') return cmp <= 0;
    if (op === '==') return cmp === 0;
    if (op === '>') return cmp > 0;
    if (op === '>=') return cmp >= 0;
    return false;
  }

  private static cmpParts(a: number[], b: number[]): number {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const numA = a[i] || 0;
      const numB = b[i] || 0;
      if (numA !== numB) {
        return numA < numB ? -1 : 1;
      }
    }
    return 0;
  }
}
