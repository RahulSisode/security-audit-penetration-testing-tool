import { SecurityFinding, Severity } from '../../core/types';

export type HypothesisConfidence = 'CONFIRMED' | 'PROBABLE' | 'SPECULATIVE' | 'REFUTED';

export interface VulnerabilityHypothesis {
  id: string;
  findingFingerprint: string;
  vulnerabilityType: string;
  attackVector: string;
  threatActorModel: string;
  exploitPreconditions: string[];
  expectedImpact: string;
  confidence: HypothesisConfidence;
}

export type VerificationTool =
  | 'CODE_AST_INSPECTOR'
  | 'TAINT_FLOW_ANALYZER'
  | 'SCOPE_CHECKER'
  | 'CANARY_VALIDATOR'
  | 'FRAMEWORK_FILTER';

export type StepStatus = 'PLANNED' | 'EXECUTING' | 'VERIFIED' | 'FAILED' | 'SKIPPED';

export interface VerificationStep {
  stepNumber: number;
  action: string;
  toolName: VerificationTool;
  status: StepStatus;
  observation: string;
  evidenceSnippet?: string;
}

export type TriageVerdictType =
  | 'TRUE_POSITIVE_CONFIRMED'
  | 'SUSPECTED_RISK'
  | 'MITIGATED_BY_FRAMEWORK'
  | 'FALSE_POSITIVE';

export interface AgentTriageVerdict {
  findingFingerprint: string;
  verdict: TriageVerdictType;
  explanation: string;
  mitigatingControlsFound: string[];
  severityAdjustment?: Severity;
  auditNotes: string;
}

export interface RemediationPlan {
  findingFingerprint: string;
  remediationSummary: string;
  patchDiff: string;
  replacementCode: string;
  regressionTestCode: string;
  testFramework: 'mocha' | 'jest' | 'node:test';
  verificationProcedure: string;
}

export interface AgentInvestigationReport {
  investigationId: string;
  timestamp: string;
  finding: SecurityFinding;
  hypothesis: VulnerabilityHypothesis;
  verificationSteps: VerificationStep[];
  verdict: AgentTriageVerdict;
  remediation: RemediationPlan;
  executionModel: string;
}

export interface AttackSurfaceAsset {
  endpoint: string;
  method?: string;
  type: 'API_ROUTE' | 'GRAPHQL' | 'FORM' | 'STATIC_RESOURCE';
  authRequired: boolean;
  parameters: string[];
  associatedFindings: string[];
}

export interface AttackSurfaceMap {
  totalAssets: number;
  assets: AttackSurfaceAsset[];
  highRiskSinksCount: number;
  unauthenticatedEndpoints: number;
}
