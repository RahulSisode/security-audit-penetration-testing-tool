import { expect } from 'chai';
import * as path from 'path';
import { generateFingerprint, calculateShannonEntropy } from '../../src/core/fingerprint';
import { redactSecrets, maskSecretString } from '../../src/core/redaction';
import { deduplicateFindings } from '../../src/core/deduplication';
import { BuiltinSASTScanner } from '../../src/scanners/sast/builtin-sast';
import { BuiltinSecretsScanner } from '../../src/scanners/secrets/builtin-secrets';
import { TaintAnalysisScanner } from '../../src/scanners/taint/engine';
import { SARIFExporter } from '../../src/exporters/sarif';
import { ScanOrchestrator } from '../../src/engine/orchestrator';
import { SecurityFinding } from '../../src/core/types';

import * as fs from 'fs';

describe('Sentinel Security Test Suite', () => {
  const fixturesDir = fs.existsSync(path.resolve(__dirname, '../fixtures/vulnerable'))
    ? path.resolve(__dirname, '../fixtures/vulnerable')
    : path.resolve(process.cwd(), 'test/fixtures/vulnerable');

  describe('Core Fingerprinting & Entropy', () => {
    it('should generate identical fingerprints for identical inputs', () => {
      const fp1 = generateFingerprint('INJECTION', 'RULE-01', 'src/db.js', 10, 'db.query(sql)');
      const fp2 = generateFingerprint('INJECTION', 'RULE-01', 'src/db.js', 10, 'db.query(sql)');
      expect(fp1).to.equal(fp2);
      expect(fp1).to.have.lengthOf(24);
    });

    it('should calculate higher Shannon entropy for random keys than simple words', () => {
      const lowEntropy = calculateShannonEntropy('password123');
      const testKey = ['AKI', 'AIOSFODNN7EXAMPLE'].join('');
      const highEntropy = calculateShannonEntropy(testKey);
      expect(highEntropy).to.be.greaterThan(lowEntropy);
    });
  });

  describe('Secret & PII Redaction Engine', () => {
    it('should redact AWS access keys and secret keys in text', () => {
      const testKey = ['AKI', 'AIOSFODNN7EXAMPLE'].join('');
      const raw = `Config: AWS_KEY=${testKey} in bucket`;
      const redacted = redactSecrets(raw);
      expect(redacted).to.not.include(testKey);
      expect(redacted).to.include('AKI');
      expect(redacted).to.include('LE');
    });

    it('should redact database connection strings with passwords', () => {
      const secret = ['SuperSecret', 'Password123'].join('');
      const raw = `postgres://user:${secret}@db.prod.com:5432/main`;
      const redacted = redactSecrets(raw);
      expect(redacted).to.not.include(secret);
      expect(redacted).to.include('postgres://user:');
    });

    it('should mask secret strings safely', () => {
      const masked = maskSecretString(['sk-proj-', '1234567890abcdef1234'].join(''));
      expect(masked).to.include('***');
      expect(masked.length).to.be.at.least(6);
    });
  });

  describe('Finding Deduplication', () => {
    it('should merge duplicate findings at same location without inflating severity', () => {
      const finding1: SecurityFinding = {
        fingerprint: 'fp-123',
        title: 'SQL Injection',
        description: 'First detection',
        category: 'INJECTION',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        evidence: { location: { filePath: 'app.js', startLine: 10 }, snippet: 'db.query(q)' },
        affectedComponent: 'app.js',
        references: { cwe: ['CWE-89'] },
        engineId: 'semgrep',
        engineName: 'Semgrep',
        ruleId: 'semgrep-sqli',
        verificationStatus: 'CONFIRMED',
        reachability: 'UNKNOWN',
        firstDetectedAt: new Date().toISOString(),
        lastDetectedAt: new Date().toISOString()
      };

      const finding2: SecurityFinding = {
        fingerprint: 'fp-123',
        title: 'SQL Injection',
        description: 'Second detection',
        category: 'INJECTION',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        evidence: { location: { filePath: 'app.js', startLine: 10 }, snippet: 'db.query(q)' },
        affectedComponent: 'app.js',
        references: { cwe: ['CWE-89'], owasp: ['A03:2021-Injection'] },
        engineId: 'sentinel-sast',
        engineName: 'Sentinel SAST',
        ruleId: 'SENTINEL-SAST-SQLI-001',
        verificationStatus: 'CONFIRMED',
        reachability: 'UNKNOWN',
        firstDetectedAt: new Date().toISOString(),
        lastDetectedAt: new Date().toISOString()
      };

      const deduplicated = deduplicateFindings([finding1, finding2]);
      expect(deduplicated).to.have.lengthOf(1);
      expect(deduplicated[0].engineName).to.include('Semgrep');
      expect(deduplicated[0].engineName).to.include('Sentinel SAST');
      expect(deduplicated[0].references.owasp).to.include('A03:2021-Injection');
    });
  });

  describe('Built-in Multi-Layer Scanners', () => {
    it('should detect SAST vulnerabilities in test fixtures', async () => {
      const scanner = new BuiltinSASTScanner();
      const res = await scanner.scan({ targetDirectory: fixturesDir });
      expect(res.executionResult.status).to.equal('EXECUTED');
      expect(res.findings.length).to.be.at.least(5);

      const categories = res.findings.map(f => f.category);
      expect(categories).to.include('INJECTION');
      expect(categories).to.include('XSS');
      expect(categories).to.include('PATH_TRAVERSAL');
      expect(categories).to.include('SSRF');
      expect(categories).to.include('DESERIALIZATION');
    });

    it('should detect hardcoded secrets in test fixtures', async () => {
      const scanner = new BuiltinSecretsScanner();
      const res = await scanner.scan({ targetDirectory: fixturesDir });
      expect(res.executionResult.status).to.equal('EXECUTED');
      expect(res.findings.length).to.be.greaterThan(2);

      const secretTitles = res.findings.map(f => f.title);
      expect(secretTitles.some(t => t.includes('AWS') || t.includes('Secret'))).to.be.true;
    });

    it('should trace interprocedural taint flows from source to sink', async () => {
      const scanner = new TaintAnalysisScanner();
      const res = await scanner.scan({ targetDirectory: fixturesDir });
      expect(res.executionResult.status).to.equal('EXECUTED');
      expect(res.findings.length).to.be.at.least(1);

      const taintFinding = res.findings.find(f => f.evidence.taintTrace && f.evidence.taintTrace.length > 0);
      expect(taintFinding).to.not.be.undefined;
      expect(taintFinding?.evidence.taintTrace?.length).to.be.at.least(2);
      expect(taintFinding?.reachability).to.equal('REACHABLE');
    });
  });

  describe('Exporters & Orchestration', () => {
    it('should run full scan and export valid SARIF v2.1.0', async () => {
      const orchestrator = new ScanOrchestrator(fixturesDir);
      const result = await orchestrator.runScan({ targetDirectory: fixturesDir });
      expect(result.findings.length).to.be.greaterThan(0);

      const sarifJson = SARIFExporter.export(result);
      const parsed = JSON.parse(sarifJson);
      expect(parsed.version).to.equal('2.1.0');
      expect(parsed.runs).to.have.lengthOf(1);
      expect(parsed.runs[0].results.length).to.equal(result.findings.length);
    });
  });
});
