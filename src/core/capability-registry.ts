import { CapabilityRegistryItem, CapabilityStatus } from './types';

export const SENTINEL_CAPABILITY_REGISTRY: CapabilityRegistryItem[] = [
  {
    featureId: 'RECON_TECH_STACK',
    category: 'Reconnaissance',
    description: 'Evidence-based technology, CMS, server, and framework fingerprinting',
    implementationLocation: 'chrome-extension/engine/scanner.js::fingerprintTechStack',
    requiredPermissions: ['tabs', 'scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Heuristics depend on observable DOM signatures, HTTP headers, or asset names']
  },
  {
    featureId: 'RECON_WAF_FINGERPRINT',
    category: 'Perimeter Defense',
    description: 'Layer 7 WAF, CDN, and DDoS reverse proxy detection (Cloudflare, AWS WAF, Akamai, Fastly)',
    implementationLocation: 'chrome-extension/engine/scanner.js::detectFirewall',
    requiredPermissions: ['tabs', '<all_urls>'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Fingerprints observable perimeter behaviors; does not verify deep rate-limit thresholds']
  },
  {
    featureId: 'RECON_PASSIVE_SUBDOMAINS',
    category: 'Reconnaissance',
    description: 'Passive subdomain discovery via Certificate Transparency logs (crt.sh)',
    implementationLocation: 'chrome-extension/engine/scanner.js::discoverPassiveSubdomains',
    requiredPermissions: ['<all_urls>'],
    requiredDependencies: ['https://crt.sh'],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'IMPLEMENTED',
    knownLimitations: ['Only queries public SSL/TLS certificate transparency records; does not perform active DNS brute-forcing']
  },
  {
    featureId: 'HTTP_SECURITY_HEADERS',
    category: 'Configuration',
    description: 'HTTP response header security audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer, Permissions)',
    implementationLocation: 'chrome-extension/engine/scanner.js::analyzeSecurityHeaders',
    requiredPermissions: ['<all_urls>'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Requires accessible HTTP HEAD/GET responses without browser sandboxing interception']
  },
  {
    featureId: 'AUTH_COOKIE_AUDIT',
    category: 'Authentication',
    description: 'Session and authentication cookie security flags audit (HttpOnly, Secure, SameSite)',
    implementationLocation: 'chrome-extension/engine/scanner.js::auditCookies',
    requiredPermissions: ['cookies', '<all_urls>'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Limited to cookies accessible under browser extension host permissions']
  },
  {
    featureId: 'AUTH_CLIENT_JWT',
    category: 'Authentication',
    description: 'Client-side JWT token security inspection (alg: none, expiration, sensitive plaintext claims)',
    implementationLocation: 'chrome-extension/engine/scanner.js::decodeAndAuditJwt',
    requiredPermissions: ['scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Audits unencrypted token claims in storage; cannot verify signature without secret key']
  },
  {
    featureId: 'SAST_DOM_XSS',
    category: 'Client-Side Security',
    description: 'DOM XSS sink and source static analysis (innerHTML, outerHTML, insertAdjacentHTML, dangerouslySetInnerHTML)',
    implementationLocation: 'chrome-extension/engine/scanner.js::SAST_RULES',
    requiredPermissions: ['scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Detects dynamic assignments; complex runtime sanitization libraries may require manual validation']
  },
  {
    featureId: 'SAST_DYNAMIC_CODE_EXEC',
    category: 'Injection',
    description: 'Dangerous dynamic code evaluation detection (eval, new Function, setTimeout strings)',
    implementationLocation: 'chrome-extension/engine/scanner.js::SAST_RULES',
    requiredPermissions: ['scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Flags direct code execution patterns']
  },
  {
    featureId: 'SAST_SECRETS_ENTROPY',
    category: 'Secrets Management',
    description: 'Shannon entropy-gated secret and API key detection (AWS, OpenAI, GitHub PAT, DB connection URIs)',
    implementationLocation: 'chrome-extension/engine/scanner.js::SECRET_RULES',
    requiredPermissions: ['scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/secrets.test.ts',
    status: 'TESTED',
    knownLimitations: ['Entropy gating suppresses low-randomness placeholder keys']
  },
  {
    featureId: 'BUG_HUNT_API_SURFACE',
    category: 'API Security',
    description: 'Automated REST endpoints, routes, and GraphQL endpoint harvesting from loaded scripts and DOM',
    implementationLocation: 'chrome-extension/engine/scanner.js::harvestEndpoints',
    requiredPermissions: ['scripting'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Harvests client-facing routes only; unreferenced internal backend routes require backend crawler']
  },
  {
    featureId: 'BUG_HUNT_QUERY_SINKS',
    category: 'Input Validation',
    description: 'High-risk query parameter vulnerability indicator audit (Open Redirect, SSRF, IDOR, Debug overrides)',
    implementationLocation: 'chrome-extension/engine/scanner.js::auditUrlParameters',
    requiredPermissions: ['tabs'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Flags parameters that represent common target sinks; exploitability requires authorized manual testing']
  },
  {
    featureId: 'POLICY_RFC9116_SECURITY_TXT',
    category: 'Policy & Compliance',
    description: 'RFC 9116 security.txt vulnerability disclosure policy validator and robots.txt path harvester',
    implementationLocation: 'chrome-extension/engine/scanner.js::auditSecurityTxt',
    requiredPermissions: ['<all_urls>'],
    requiredDependencies: [],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Depends on public accessibility of /.well-known/security.txt']
  },
  {
    featureId: 'DAST_SAFE_PROBE',
    category: 'Dynamic Analysis',
    description: 'Non-destructive authorized HTTP response probing and server validation',
    implementationLocation: 'src/scanners/dast/safe-dast.ts::SafeDASTScanner',
    requiredPermissions: ['Authorized Scope Manifest'],
    requiredDependencies: ['Node.js HTTP/HTTPS'],
    testSuite: 'test/unit/scanners.test.ts',
    status: 'TESTED',
    knownLimitations: ['Restricted to read-only non-destructive probes with rate limits and timeout budgets']
  },
  {
    featureId: 'EXPORT_BUG_BOUNTY_REPORT',
    category: 'Reporting',
    description: 'One-click HackerOne and Bugcrowd compliant Markdown/SARIF disclosure report generator with CVSS v3.1',
    implementationLocation: 'chrome-extension/engine/scanner.js::generateBugBountyReport',
    requiredPermissions: [],
    requiredDependencies: [],
    testSuite: 'test/unit/exporters.test.ts',
    status: 'TESTED',
    knownLimitations: ['Formats observed evidence and references; requires operator review before submission']
  }
];

export function getCapabilityRegistrySummary() {
  const total = SENTINEL_CAPABILITY_REGISTRY.length;
  const tested = SENTINEL_CAPABILITY_REGISTRY.filter(c => c.status === 'TESTED').length;
  const implemented = SENTINEL_CAPABILITY_REGISTRY.filter(c => c.status === 'IMPLEMENTED').length;
  const partiallyImplemented = SENTINEL_CAPABILITY_REGISTRY.filter(c => c.status === 'PARTIALLY_IMPLEMENTED').length;
  const unavailable = SENTINEL_CAPABILITY_REGISTRY.filter(c => c.status === 'UNAVAILABLE').length;

  return {
    totalCapabilities: total,
    testedCount: tested,
    implementedCount: implemented,
    partiallyImplementedCount: partiallyImplemented,
    unavailableCount: unavailable,
    coveragePercentage: Math.round(((tested + implemented) / total) * 100),
    items: SENTINEL_CAPABILITY_REGISTRY
  };
}
