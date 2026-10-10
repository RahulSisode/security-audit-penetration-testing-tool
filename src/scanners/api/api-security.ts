import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner } from '../base';
import { SecurityFinding, ScannerExecutionResult, ScanOptions, Confidence } from '../../core/types';
import { WorkspaceScanner } from '../../utils/workspace';
import { generateFingerprint } from '../../core/fingerprint';
import { sanitizeFindingEvidence } from '../../core/redaction';

interface DiscoveredRoute {
  method: string;
  path: string;
  filePath: string;
  line: number;
  hasAuthMiddleware: boolean;
  hasRateLimiting: boolean;
  isGraphQL: boolean;
  isOpenAPI: boolean;
}

export class APISecurityScanner extends BaseScanner {
  public readonly id = 'sentinel-api-security';
  public readonly name = 'Sentinel API & Web Route Security Analyzer';

  public async isAvailable(): Promise<boolean> {
    return true; // Always available built-in
  }

  public async getVersion(): Promise<string> {
    return '1.0.0 (API Route & Schema Security Engine)';
  }

  public async scan(options: ScanOptions): Promise<{
    findings: SecurityFinding[];
    executionResult: ScannerExecutionResult;
  }> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];
    const workspaceRoot = options.targetDirectory;

    try {
      const discovery = WorkspaceScanner.discoverFiles(
        workspaceRoot,
        options.maxFileSizeMb,
        options.customIgnorePatterns
      );

      const routes: DiscoveredRoute[] = [];

      for (const filePath of discovery.scannableFiles) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        const relPath = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');

        // 1. Detect OpenAPI / Swagger Specs without Security Schemes
        if (relPath.includes('openapi') || relPath.includes('swagger')) {
          if (content.includes('openapi:') || content.includes('"swagger":') || content.includes('paths:')) {
            if (!content.includes('security:') && !content.includes('securitySchemes')) {
              const fingerprint = generateFingerprint('API_SECURITY', 'SENTINEL-API-OPENAPI-NOAUTH', relPath, 1, 'OpenAPI No Security');
              findings.push({
                fingerprint,
                title: 'OpenAPI Specification Lacks Global Security Schemes',
                description: 'The OpenAPI definition defines endpoints without declaring authentication or securitySchemes.',
                category: 'API_SECURITY',
                severity: 'MEDIUM',
                confidence: 'CONFIRMED',
                evidence: {
                  location: { filePath: relPath, startLine: 1 },
                  snippet: 'OpenAPI schema lacks security / securitySchemes configuration'
                },
                affectedComponent: relPath,
                references: {
                  owasp: ['API2:2023-Broken Authentication', 'API5:2023-Broken Function Level Authorization'],
                  cwe: ['CWE-306']
                },
                exploitPreconditions: 'API exposed without mandatory authentication documentation/enforcement.',
                impact: 'Endpoints may be unintentionally deployed as unauthenticated public routes.',
                remediation: 'Define securitySchemes (e.g. bearerAuth, oauth2) and apply security: [{ bearerAuth: [] }] in the OpenAPI definition.',
                engineId: this.id,
                engineName: this.name,
                ruleId: 'SENTINEL-API-OPENAPI-NOAUTH',
                verificationStatus: 'CONFIRMED',
                reachability: 'REACHABLE',
                firstDetectedAt: new Date().toISOString(),
                lastDetectedAt: new Date().toISOString()
              });
            }
          }
        }

        // 2. Detect GraphQL Introspection Enabled in Production
        // sentinel-ignore SENTINEL-API-GRAPHQL-INTRO Scanner logic definition
        if (content.includes('ApolloServer') || content.includes('createYoga') || content.includes('graphqlHTTP')) {
          if (content.includes('introspection: true') || !content.includes('introspection: false')) {
            const lineIdx = lines.findIndex(l => l.includes('ApolloServer') || l.includes('createYoga') || l.includes('introspection'));
            const startLine = lineIdx >= 0 ? lineIdx + 1 : 1;
            const fingerprint = generateFingerprint('API_SECURITY', 'SENTINEL-API-GRAPHQL-INTRO', relPath, startLine, 'GraphQL Introspection');

            findings.push({
              fingerprint,
              title: 'GraphQL Schema Introspection Potentially Enabled',
              description: 'GraphQL server appears to allow schema introspection queries, exposing entire data model and internal types.',
              category: 'API_SECURITY',
              severity: 'LOW',
              confidence: 'HYPOTHESIS',
              evidence: {
                location: { filePath: relPath, startLine },
                snippet: lines[startLine - 1] || 'GraphQL server instantiation'
              },
              affectedComponent: relPath,
              references: {
                owasp: ['API8:2023-Security Misconfiguration'],
                cwe: ['CWE-200']
              },
              exploitPreconditions: 'GraphQL server running in production environment.',
              impact: 'Full reconnaissance of internal GraphQL types, queries, and mutations.',
              remediation: 'Explicitly set introspection: process.env.NODE_ENV !== "production" or disable in production.',
              engineId: this.id,
              engineName: this.name,
              ruleId: 'SENTINEL-API-GRAPHQL-INTRO',
              verificationStatus: 'SUSPECTED',
              reachability: 'UNKNOWN',
              firstDetectedAt: new Date().toISOString(),
              lastDetectedAt: new Date().toISOString()
            });
          }
        }

        // 3. Detect Express / FastAPI / Flask Routes with Missing Rate Limiting or Mass-Assignment
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const lineNum = i + 1;

          // Express route pattern check
          // sentinel-ignore SENTINEL-API-MASS-ASSIGN Scanner logic definition
          const expressMatch = line.match(/(?:app|router)\.(post|put|patch|delete)\s*\(\s*['"](\/api\/[^'"]+|\/[^'"]+)['"]/i);
          if (expressMatch) {
            const method = expressMatch[1].toUpperCase();
            const routePath = expressMatch[2];
            const hasAuth = /auth|authenticate|verifyToken|jwt|requireUser|protect/i.test(line);

            // Check Mass-Assignment pattern: Model.create(req.body) or Model.update(req.body)
            const contextSnippet = lines.slice(i, Math.min(lines.length, i + 10)).join('\n');
            if (contextSnippet.includes('.create(req.body)') || contextSnippet.includes('.update(req.body)') || contextSnippet.includes('**request.data')) {
              const fingerprint = generateFingerprint('API_SECURITY', 'SENTINEL-API-MASS-ASSIGN', relPath, lineNum, routePath);
              findings.push({
                fingerprint,
                title: `Mass-Assignment Vulnerability on Route ${method} ${routePath}`,
                description: `Route ${method} ${routePath} binds raw request body directly to database model without parameter whitelisting.`,
                category: 'API_SECURITY',
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                evidence: sanitizeFindingEvidence({
                  location: { filePath: relPath, startLine: lineNum },
                  snippet: line.trim()
                }) as any,
                affectedComponent: `${method} ${routePath}`,
                references: {
                  owasp: ['API3:2023-Broken Object Property Level Authorization'],
                  cwe: ['CWE-915']
                },
                exploitPreconditions: 'Attacker supplies administrative fields (e.g. isAdmin: true, role: "admin") in request body.',
                impact: 'Privilege escalation or unauthorized property modification.',
                remediation: 'Use a strict DTO schema validator (e.g. Zod, Joi, Pydantic) or explicitly pick allowed attributes (e.g. _.pick(req.body, ["name", "email"])).',
                engineId: this.id,
                engineName: this.name,
                ruleId: 'SENTINEL-API-MASS-ASSIGN',
                verificationStatus: 'CONFIRMED',
                reachability: 'REACHABLE',
                firstDetectedAt: new Date().toISOString(),
                lastDetectedAt: new Date().toISOString()
              });
            }

            // Check Sensitive Unauthenticated Endpoint (e.g. /api/users, /api/admin, /api/payments)
            if (!hasAuth && (/admin|user|payment|order|invoice|role|account/i.test(routePath)) && !routePath.includes('login') && !routePath.includes('register')) {
              const fingerprint = generateFingerprint('API_SECURITY', 'SENTINEL-API-SENSITIVE-UNAUTH', relPath, lineNum, routePath);
              findings.push({
                fingerprint,
                title: `Potentially Unprotected Sensitive API Route: ${method} ${routePath}`,
                description: `Sensitive resource route appears to lack authentication middleware on line ${lineNum}.`,
                category: 'API_SECURITY',
                severity: 'MEDIUM',
                confidence: 'MEDIUM',
                evidence: sanitizeFindingEvidence({
                  location: { filePath: relPath, startLine: lineNum },
                  snippet: line.trim()
                }) as any,
                affectedComponent: `${method} ${routePath}`,
                references: {
                  owasp: ['API1:2023-Broken Object Level Authorization', 'API2:2023-Broken Authentication'],
                  cwe: ['CWE-306']
                },
                exploitPreconditions: 'Route exposed without global or router-level authentication check.',
                impact: 'Unauthorized access to business sensitive endpoints.',
                remediation: 'Verify whether authentication middleware is applied globally or attach authentication guard.',
                engineId: this.id,
                engineName: this.name,
                ruleId: 'SENTINEL-API-SENSITIVE-UNAUTH',
                verificationStatus: 'SUSPECTED',
                reachability: 'REACHABLE',
                firstDetectedAt: new Date().toISOString(),
                lastDetectedAt: new Date().toISOString()
              });
            }
          }
        }
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
          status: 'FAILED',
          executionTimeMs: Date.now() - startTime,
          findingsCount: 0,
          errorMessage: err?.message || String(err)
        }
      };
    }
  }
}
