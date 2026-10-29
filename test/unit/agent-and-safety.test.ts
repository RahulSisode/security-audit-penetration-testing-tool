import * as assert from 'assert';
import { ScopeManager, ScopeEnforcedHttpClient } from '../../src/core/scope';
import { SentinelSecurityAgent } from '../../src/ai/agent/security-agent';
import { DeterministicSecurityReasoner } from '../../src/ai/agent/reasoner';
import { SecurityFinding, ScanResult } from '../../src/core/types';

describe('Sentinel AI Agent & Strict Safety Guard Test Suite', () => {
  describe('Scope & Redirect Safety Enforcement', () => {
    it('should permit redirects staying strictly within authorized hostnames', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.local',
        authorizedHostnames: ['app.local', 'api.app.local'],
        permitActiveTesting: true
      });

      // Valid relative redirect
      const res1 = scope.validateRedirect('https://app.local/login', '/dashboard');
      assert.strictEqual(res1.isAuthorized, true);
      assert.strictEqual(res1.normalizedUrl, 'https://app.local/dashboard');

      // Valid subdomain redirect
      const res2 = scope.validateRedirect('https://app.local/v1', 'https://api.app.local/v1/auth');
      assert.strictEqual(res2.isAuthorized, true);

      // Verify audit trail logged REDIRECT_CHECKED
      const audit = scope.getAuditTrail();
      const redirectEvents = audit.filter(a => a.action === 'REDIRECT_CHECKED');
      assert.ok(redirectEvents.length >= 2);
    });

    it('should strictly block redirects attempting to escape authorized scope', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.local',
        authorizedHostnames: ['app.local'],
        permitActiveTesting: true
      });

      // Out of scope external target redirect
      const res = scope.validateRedirect('https://app.local/login', 'https://malicious-external-target.com/callback');
      assert.strictEqual(res.isAuthorized, false);
      assert.ok(res.reason?.includes('not in the approved authorized list'));

      // Check audit log recorded UNAUTHORIZED event
      const audit = scope.getAuditTrail();
      const unauth = audit.filter(a => a.action === 'UNAUTHORIZED');
      assert.ok(unauth.length > 0);
    });

    it('should block redirects targeting excluded paths', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.local',
        authorizedHostnames: ['app.local'],
        excludedPaths: ['/logout', '/admin/destroy']
      });

      const res = scope.validateRedirect('https://app.local/settings', '/logout?confirmed=true');
      assert.strictEqual(res.isAuthorized, false);
      assert.ok(res.reason?.includes('explicitly excluded'));
    });

    it('should never let website content or AI output expand target scope', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.local',
        authorizedHostnames: ['app.local']
      });

      // Website DOM scraped link pointing outside
      const webResult = scope.sanitizeCandidateUrl('https://evil-unauthorized.com/phish', 'WEBSITE_CONTENT');
      assert.strictEqual(webResult.isAuthorized, false);
      assert.ok(webResult.reason?.includes('WEBSITE_CONTENT'));

      // AI Model hallucinates external endpoint
      const aiResult = scope.sanitizeCandidateUrl('https://api.external-cloud.com/keys', 'AI_OUTPUT');
      assert.strictEqual(aiResult.isAuthorized, false);
      assert.ok(aiResult.reason?.includes('AI_OUTPUT'));

      // In-scope relative candidate from website is accepted
      const validWebResult = scope.sanitizeCandidateUrl('/api/v1/user', 'WEBSITE_CONTENT');
      assert.strictEqual(validWebResult.isAuthorized, true);
      assert.strictEqual(validWebResult.normalizedUrl, 'https://app.local/api/v1/user');
    });

    it('should block requests to cloud metadata services (SSRF protection)', () => {
      const scope = new ScopeManager({
        targetOrigin: 'http://169.254.169.254',
        authorizedHostnames: ['169.254.169.254']
      });

      const res = scope.validateUrl('http://169.254.169.254/latest/meta-data/');
      assert.strictEqual(res.isAuthorized, false);
      assert.ok(res.reason?.includes('strictly forbidden'));
    });

    it('should detect real external targets and reject active probes against external domains', async () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://google.com',
        authorizedHostnames: ['google.com'],
        permitActiveTesting: true
      });

      assert.strictEqual(scope.isRealExternalTarget('https://google.com'), true);
      assert.strictEqual(scope.isRealExternalTarget('http://localhost:3000'), false);
      assert.strictEqual(scope.isRealExternalTarget('http://127.0.0.1:8080'), false);
      assert.strictEqual(scope.isRealExternalTarget('http://app.test'), false);

      const client = new ScopeEnforcedHttpClient(scope);
      try {
        await client.request('https://google.com', { isActiveTest: true });
        assert.fail('Should have blocked request against real external target');
      } catch (err: any) {
        assert.ok(err.message.includes('Safety block: Cannot run active security scans against real external target'));
      }
    });

    it('should enforce explicit operator authorization before active testing', async () => {
      const passiveScope = new ScopeManager({
        targetOrigin: 'http://localhost:3000',
        authorizedHostnames: ['localhost'],
        permitActiveTesting: false
      });

      const client = new ScopeEnforcedHttpClient(passiveScope);
      try {
        await client.request('http://localhost:3000/api', { isActiveTest: true });
        assert.fail('Should have failed because active testing is unauthorized');
      } catch (err: any) {
        assert.ok(err.message.includes('Active request blocked'));
      }
    });
  });

  describe('Sentinel AI Security Agent Capabilities (Strix-Inspired)', () => {
    const mockFinding: SecurityFinding = {
      fingerprint: 'test_xss_fingerprint_123',
      title: 'DOM XSS via unescaped innerHTML assignment',
      description: 'Element innerHTML assigned from location.search query param',
      category: 'XSS',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      evidence: {
        location: { filePath: 'src/client/view.js', startLine: 42 },
        snippet: 'document.getElementById("output").innerHTML = userInput;'
      },
      affectedComponent: 'src/client/view.js',
      references: { cwe: ['CWE-79'], owasp: ['A03:2021-Injection'] },
      engineId: 'sentinel-builtin-sast',
      engineName: 'Sentinel Multi-Layer SAST',
      ruleId: 'SAST-DOM-XSS',
      verificationStatus: 'CONFIRMED',
      reachability: 'REACHABLE',
      firstDetectedAt: new Date().toISOString(),
      lastDetectedAt: new Date().toISOString()
    };

    it('should generate an autonomous threat hypothesis with exploit preconditions', () => {
      const hypothesis = DeterministicSecurityReasoner.generateHypothesis(mockFinding);
      assert.ok(hypothesis.id.startsWith('hypo_'));
      assert.strictEqual(hypothesis.vulnerabilityType, 'Cross-Site Scripting (XSS)');
      assert.ok(hypothesis.attackVector.includes('innerHTML') || hypothesis.attackVector.includes('DOM sink'));
      assert.ok(hypothesis.exploitPreconditions.length >= 2);
      assert.ok(hypothesis.expectedImpact.includes('Session hijacking') || hypothesis.expectedImpact.includes('DOM'));
      assert.strictEqual(hypothesis.confidence, 'CONFIRMED');
    });

    it('should formulate structured non-destructive verification steps', () => {
      const steps = DeterministicSecurityReasoner.planVerificationSteps(mockFinding);
      assert.ok(steps.length >= 3);
      assert.strictEqual(steps[0].toolName, 'CODE_AST_INSPECTOR');
      assert.strictEqual(steps[0].status, 'VERIFIED');
      assert.strictEqual(steps[1].toolName, 'TAINT_FLOW_ANALYZER');
      assert.strictEqual(steps[2].toolName, 'FRAMEWORK_FILTER');
      assert.ok(steps.some(s => s.toolName === 'SCOPE_CHECKER'));
    });

    it('should triage false positives when framework mitigations exist', () => {
      // Unsanitized snippet -> True Positive
      const steps1 = DeterministicSecurityReasoner.planVerificationSteps(mockFinding);
      const verdict1 = DeterministicSecurityReasoner.determineTriageVerdict(mockFinding, steps1);
      assert.strictEqual(verdict1.verdict, 'TRUE_POSITIVE_CONFIRMED');

      // Sanitized snippet with DOMPurify -> Mitigated
      const mitigatedFinding = { ...mockFinding };
      const mitigatedCode = 'document.getElementById("output").innerHTML = DOMPurify.sanitize(userInput);';
      const steps2 = DeterministicSecurityReasoner.planVerificationSteps(mitigatedFinding, mitigatedCode);
      const verdict2 = DeterministicSecurityReasoner.determineTriageVerdict(mitigatedFinding, steps2, mitigatedCode);
      assert.strictEqual(verdict2.verdict, 'MITIGATED_BY_FRAMEWORK');
      assert.ok(verdict2.mitigatingControlsFound.some(m => m.includes('DOMPurify')));
    });

    it('should synthesize deterministic code diff patch and regression test', () => {
      const remediation = DeterministicSecurityReasoner.generateRemediation(mockFinding);
      assert.ok(remediation.patchDiff.includes('- element.innerHTML'));
      assert.ok(remediation.patchDiff.includes('+ element.textContent'));
      assert.ok(remediation.regressionTestCode.includes('describe('));
      assert.ok(remediation.regressionTestCode.includes('DOM XSS'));
    });

    it('should run full agent investigation pipeline without real Ollama model', async () => {
      const scope = new ScopeManager({
        targetOrigin: 'http://localhost:3000',
        authorizedHostnames: ['localhost']
      });
      const agent = new SentinelSecurityAgent({ scopeManager: scope });

      const report = await agent.investigateFinding(mockFinding);
      assert.ok(report.investigationId.startsWith('inv_'));
      assert.ok(report.hypothesis.attackVector.length > 0);
      assert.ok(report.verificationSteps.length >= 4);
      assert.strictEqual(report.verdict.verdict, 'TRUE_POSITIVE_CONFIRMED');
      assert.ok(report.remediation.patchDiff.length > 0);
      assert.ok(report.remediation.regressionTestCode.length > 0);
    });

    it('should generate standalone regression unit test code', () => {
      const agent = new SentinelSecurityAgent();
      const testCode = agent.generateRegressionTest(mockFinding);
      assert.ok(testCode.includes('Regression Test'));
      assert.ok(testCode.includes('it('));
    });

    it('should map attack surface and correlate assets with findings', () => {
      const agent = new SentinelSecurityAgent();
      const mockScanResult: ScanResult = {
        scanId: 'scan-1',
        targetDirectory: '/app',
        summary: {
          totalFindings: 1,
          criticalCount: 0,
          highCount: 1,
          mediumCount: 0,
          lowCount: 0,
          infoCount: 0,
          suppressedCount: 0,
          fixedCount: 0,
          durationMs: 12,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString()
        },
        coverage: {} as any,
        findings: [mockFinding]
      };

      const map = agent.mapAttackSurface(mockScanResult);
      assert.ok(map.totalAssets >= 1);
      assert.ok(map.assets.some(a => a.endpoint.includes('view.js')));
    });

    it('should interactively consult agent with safety scope enforcement', async () => {
      const scope = new ScopeManager({
        targetOrigin: 'http://localhost:3000',
        authorizedHostnames: ['localhost']
      });
      const agent = new SentinelSecurityAgent({ scopeManager: scope });

      // Out of scope query should be intercepted by scope guard
      const blockedRes = await agent.consultAgent('Check https://unauthorized-evil-target.com for open redirects');
      assert.ok(blockedRes.includes('[Scope Guard]'));
      assert.ok(blockedRes.includes('outside your authorized scope'));

      // In-scope query produces detailed reasoning
      const answer = await agent.consultAgent('How do I fix this?', mockFinding);
      assert.ok(answer.includes('Sentinel AI Agent Analysis'));
      assert.ok(answer.includes('Remediation'));
    });
  });
});
