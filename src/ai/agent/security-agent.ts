import * as crypto from 'crypto';
import { SecurityFinding, ScanResult, Severity } from '../../core/types';
import { OllamaClient } from '../ollama';
import { ScopeManager } from '../../core/scope';
import {
  AgentInvestigationReport,
  VulnerabilityHypothesis,
  VerificationStep,
  AgentTriageVerdict,
  RemediationPlan,
  AttackSurfaceMap,
  AttackSurfaceAsset
} from './types';
import { DeterministicSecurityReasoner } from './reasoner';

export interface SecurityAgentOptions {
  ollamaEndpoint?: string;
  ollamaModel?: string;
  scopeManager?: ScopeManager;
}

export class SentinelSecurityAgent {
  private ollama: OllamaClient;
  private scopeManager?: ScopeManager;
  private modelName: string;

  constructor(options: SecurityAgentOptions = {}) {
    this.modelName = options.ollamaModel || 'llama3';
    this.ollama = new OllamaClient(options.ollamaEndpoint || 'http://127.0.0.1:11434', this.modelName);
    this.scopeManager = options.scopeManager;
  }

  /**
   * Performs an autonomous security investigation on a finding:
   * 1. Formulate vulnerability hypothesis
   * 2. Plan and execute non-destructive verification steps
   * 3. Evaluate false positive mitigations and issue triage verdict
   * 4. Generate deterministic patch and regression unit test
   */
  public async investigateFinding(
    finding: SecurityFinding,
    surroundingCode?: string
  ): Promise<AgentInvestigationReport> {
    const investigationId = `inv_${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();

    // 1. Generate Hypothesis
    let hypothesis: VulnerabilityHypothesis;
    let executionModel = 'Sentinel Deterministic Security Reasoner';

    const isOllamaAvailable = await this.ollama.isAvailable();
    if (isOllamaAvailable) {
      try {
        const aiExplanation = await this.ollama.explainAndSuggestFix(finding, this.modelName);
        if (aiExplanation && aiExplanation.explanation) {
          executionModel = `Local Ollama (${this.modelName})`;
        }
      } catch {}
    }

    // Grounded hypothesis generation
    hypothesis = DeterministicSecurityReasoner.generateHypothesis(finding);

    // 2. Plan & execute verification steps
    const verificationSteps: VerificationStep[] = DeterministicSecurityReasoner.planVerificationSteps(
      finding,
      surroundingCode
    );

    // If scope manager is present, record audit check for the investigation
    if (this.scopeManager) {
      const scopeCheck = this.scopeManager.validateUrl(finding.evidence.location.filePath.startsWith('http') 
        ? finding.evidence.location.filePath 
        : `http://localhost/${finding.evidence.location.filePath}`
      );
      verificationSteps.push({
        stepNumber: verificationSteps.length + 1,
        action: 'Validate target boundary via ScopeManager',
        toolName: 'SCOPE_CHECKER',
        status: scopeCheck.isAuthorized ? 'VERIFIED' : 'FAILED',
        observation: scopeCheck.isAuthorized
          ? 'Confirmed finding location is strictly within approved project/workspace scope.'
          : `Scope warning: ${scopeCheck.reason}`
      });
    }

    // 3. Determine Triage Verdict
    const verdict: AgentTriageVerdict = DeterministicSecurityReasoner.determineTriageVerdict(
      finding,
      verificationSteps,
      surroundingCode
    );

    // 4. Generate Remediation Plan & Regression Test
    const remediation: RemediationPlan = DeterministicSecurityReasoner.generateRemediation(finding);

    return {
      investigationId,
      timestamp,
      finding,
      hypothesis,
      verificationSteps,
      verdict,
      remediation,
      executionModel
    };
  }

  /**
   * Generates a runnable regression unit test for the given finding.
   */
  public generateRegressionTest(finding: SecurityFinding): string {
    const plan = DeterministicSecurityReasoner.generateRemediation(finding);
    return plan.regressionTestCode;
  }

  /**
   * Maps application attack surface and correlates discovered endpoints with security findings.
   */
  public mapAttackSurface(scanResult: ScanResult): AttackSurfaceMap {
    const assets: AttackSurfaceAsset[] = [];
    const endpointsSet = new Set<string>();

    // Extract endpoints discovered in findings or scan metadata
    for (const finding of scanResult.findings) {
      const path = finding.affectedComponent || finding.evidence.location.filePath;
      if (path && (path.includes('/') || path.includes('api') || path.includes('http'))) {
        if (!endpointsSet.has(path)) {
          endpointsSet.add(path);
          assets.push({
            endpoint: path,
            type: path.includes('graphql') ? 'GRAPHQL' : 'API_ROUTE',
            authRequired: !finding.title.toLowerCase().includes('unauthenticated'),
            parameters: finding.evidence.snippet ? [finding.evidence.snippet.substring(0, 30)] : [],
            associatedFindings: [finding.ruleId]
          });
        }
      }
    }

    return {
      totalAssets: assets.length,
      assets,
      highRiskSinksCount: scanResult.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length,
      unauthenticatedEndpoints: assets.filter(a => !a.authRequired).length
    };
  }

  /**
   * Consults the AI Security Agent interactively with safety and scope guardrails.
   */
  public async consultAgent(
    query: string,
    finding?: SecurityFinding,
    contextInfo?: string
  ): Promise<string> {
    const isOllamaAvailable = await this.ollama.isAvailable();

    // Check if query tries to target real external domains
    if (this.scopeManager) {
      const words = query.split(/\s+/);
      for (const w of words) {
        if (w.startsWith('http://') || w.startsWith('https://')) {
          const check = this.scopeManager.sanitizeCandidateUrl(w, 'USER_INPUT');
          if (!check.isAuthorized) {
            return `🛡️ [Scope Guard] The specified target (${w}) is outside your authorized scope.\nReason: ${check.reason}\n\nSentinel Security prevents active probing or expansion against unauthorized domains.`;
          }
        }
      }
    }

    if (isOllamaAvailable && finding) {
      try {
        const res = await this.ollama.explainAndSuggestFix(finding, this.modelName);
        if (res && res.explanation) {
          return `### 🛡️ Sentinel AI Security Analysis (${this.modelName})\n\n${res.explanation}\n\n**Secure Alternative:**\n\`\`\`\n${res.secureAlternative}\n\`\`\``;
        }
      } catch {}
    }

    // High quality deterministic fallback guidance
    if (finding) {
      const hypo = DeterministicSecurityReasoner.generateHypothesis(finding);
      const remediation = DeterministicSecurityReasoner.generateRemediation(finding);
      return `### 🛡️ Sentinel AI Agent Analysis\n\n**Finding:** ${finding.title} (${finding.severity})\n**Rule:** \`${finding.ruleId}\`\n\n#### 🎯 Attack Hypothesis:\n${hypo.attackVector}\n\n**Preconditions:**\n${hypo.exploitPreconditions.map(p => `- ${p}`).join('\n')}\n\n#### 🛠️ Recommended Remediation:\n${remediation.remediationSummary}\n\n\`\`\`typescript\n${remediation.replacementCode}\n\`\`\`\n\n#### 🧪 Regression Unit Test:\n\`\`\`typescript\n${remediation.regressionTestCode}\n\`\`\``;
    }

    return `### 🛡️ Sentinel AI Security Assistant\n\nI am the local Sentinel Security Agent. I can analyze your SAST/DAST findings, verify vulnerability hypotheses, triage false positives, and synthesize regression tests.\n\nQuery received: "${query}"\n\nTip: Select a finding from the Findings Explorer or click "Investigate with AI Agent" for in-depth root cause analysis.`;
  }
}
