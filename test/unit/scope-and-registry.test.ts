import * as assert from 'assert';
import { ScopeManager } from '../../src/core/scope';
import { SENTINEL_CAPABILITY_REGISTRY, getCapabilityRegistrySummary } from '../../src/core/capability-registry';

describe('Sentinel Scope & Capability Registry Test Suite', () => {
  describe('Scope and Authorization Engine', () => {
    it('should strictly approve only authorized target hostnames', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://example.com',
        authorizedHostnames: ['example.com', '*.target-app.com'],
        permitActiveTesting: false
      });

      // Valid in-scope host
      const res1 = scope.validateUrl('https://example.com/api/v1/profile');
      assert.strictEqual(res1.isAuthorized, true);

      // Valid wildcard subdomain
      const res2 = scope.validateUrl('https://api.target-app.com/graphql');
      assert.strictEqual(res2.isAuthorized, true);

      // Invalid out-of-scope host
      const res3 = scope.validateUrl('https://evil-unauthorized.com/test');
      assert.strictEqual(res3.isAuthorized, false);
      assert.ok(res3.reason?.includes('not in the approved authorized list'));
    });

    it('should block explicitly excluded paths even on authorized hosts', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.com',
        authorizedHostnames: ['app.com'],
        excludedPaths: ['/logout', '/admin/destroy']
      });

      const res = scope.validateUrl('https://app.com/logout?token=abc');
      assert.strictEqual(res.isAuthorized, false);
      assert.ok(res.reason?.includes('explicitly excluded'));
    });

    it('should enforce explicit permission for active testing', () => {
      const passiveScope = new ScopeManager({
        targetOrigin: 'https://app.com',
        permitActiveTesting: false
      });
      assert.strictEqual(passiveScope.canExecuteActiveRequest().allowed, false);

      const activeScope = new ScopeManager({
        targetOrigin: 'https://app.com',
        permitActiveTesting: true
      });
      assert.strictEqual(activeScope.canExecuteActiveRequest().allowed, true);
    });

    it('should record an immutable audit trail of scope checks', () => {
      const scope = new ScopeManager({
        targetOrigin: 'https://app.com'
      });
      scope.validateUrl('https://app.com/login');
      scope.validateUrl('https://out-of-scope.com/api');

      const audit = scope.getAuditTrail();
      assert.ok(audit.length >= 3);
      assert.strictEqual(audit[0].action, 'INITIALIZED');
      assert.strictEqual(audit[1].action, 'TARGET_CHECKED');
      assert.strictEqual(audit[2].action, 'UNAUTHORIZED');
    });
  });

  describe('Machine-Readable Capability & Coverage Registry', () => {
    it('should define complete and verified capability records', () => {
      assert.ok(SENTINEL_CAPABILITY_REGISTRY.length >= 10);
      for (const item of SENTINEL_CAPABILITY_REGISTRY) {
        assert.ok(item.featureId.length > 0);
        assert.ok(item.category.length > 0);
        assert.ok(item.description.length > 0);
        assert.ok(item.implementationLocation.length > 0);
        assert.ok(['IMPLEMENTED', 'TESTED', 'PARTIALLY_IMPLEMENTED', 'UNAVAILABLE', 'NOT_TESTED'].includes(item.status));
      }
    });

    it('should compute accurate coverage summary statistics', () => {
      const summary = getCapabilityRegistrySummary();
      assert.ok(summary.totalCapabilities > 0);
      assert.ok(summary.testedCount > 0);
      assert.ok(summary.coveragePercentage > 50);
    });
  });
});
