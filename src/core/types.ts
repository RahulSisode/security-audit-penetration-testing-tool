/**
 * Sentinel Security - Unified Type Definitions
 * Cross-platform, zero-API security scanning platform
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Confidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'HYPOTHESIS';

export type VulnerabilityCategory =
  | 'INJECTION'
  | 'XSS'
  | 'PATH_TRAVERSAL'
  | 'SSRF'
  | 'UNSAFE_REDIRECT'
  | 'DESERIALIZATION'
  | 'AUTH_AUTHZ'
  | 'IDOR_BOLA'
  | 'CRYPTOGRAPHY'
  | 'INSECURE_RNG'
  | 'RACE_CONDITION'
  | 'MEMORY_SAFETY'
  | 'INTEGER_OVERFLOW'
  | 'NULL_DEREFERENCE'
  | 'FORMAT_STRING'
  | 'INPUT_VALIDATION'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'INSECURE_TEMP_FILE'
  | 'UNSAFE_REFLECTION'
  | 'PROTOTYPE_POLLUTION'
  | 'REDOS'
  | 'RESOURCE_EXHAUSTION'
  | 'XXE'
  | 'FILE_UPLOAD'
  | 'BUSINESS_LOGIC'
  | 'SECRETS'
  | 'DEPENDENCY_VULNERABILITY'
  | 'SUPPLY_CHAIN_RISK'
  | 'LICENSE_VIOLATION'
  | 'IAC_MISCONFIGURATION'
  | 'CONTAINER_SECURITY'
  | 'CI_CD_SECURITY'
  | 'API_SECURITY'
  | 'DAST_DYNAMIC_FINDING'
  | 'TAINT_FLOW';

export type VerificationStatus =
  | 'CONFIRMED'
  | 'SUSPECTED'
  | 'UNVERIFIED'
  | 'FIXED_VERIFIED'
  | 'REGRESSION';

export type ReachabilityStatus = 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN';

export interface CodeLocation {
  filePath: string;
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

export interface TaintTraceStep {
  step: number;
  type: 'SOURCE' | 'PROPAGATION' | 'SANITIZER' | 'SINK';
  location: CodeLocation;
  variableName?: string;
  description: string;
  codeSnippet?: string;
}

export interface FindingEvidence {
  location: CodeLocation;
  snippet?: string;
  redactedSnippet?: string;
  rawMatch?: string;
  redactedMatch?: string;
  taintTrace?: TaintTraceStep[];
  contextLinesBefore?: string[];
  contextLinesAfter?: string[];
}

export interface FindingReference {
  cwe?: string[];
  cve?: string[];
  owasp?: string[];
  cvss?: number;
  urls?: string[];
}

export interface ProposedFix {
  description: string;
  replacementCode?: string;
  patchDiff?: string;
  targetFile: string;
  startLine: number;
  endLine: number;
  isDeterministic: boolean;
  requiresManualReview: boolean;
  explanation: string;
}

export interface FindingSuppression {
  isSuppressed: boolean;
  justification?: string;
  suppressedBy?: string;
  suppressedAt?: string;
}

export interface SecurityFinding {
  fingerprint: string;
  title: string;
  description: string;
  category: VulnerabilityCategory;
  severity: Severity;
  confidence: Confidence;
  evidence: FindingEvidence;
  affectedComponent: string;
  references: FindingReference;
  exploitPreconditions?: string;
  impact?: string;
  remediation?: string;
  proposedFix?: ProposedFix;
  engineId: string;
  engineName: string;
  ruleId: string;
  verificationStatus: VerificationStatus;
  reachability: ReachabilityStatus;
  reachabilityEvidence?: string;
  suppression?: FindingSuppression;
  firstDetectedAt: string;
  lastDetectedAt: string;
}

export type ScannerStatus = 'AVAILABLE' | 'EXECUTED' | 'FAILED' | 'UNAVAILABLE' | 'SKIPPED';

export interface ScannerExecutionResult {
  scannerId: string;
  scannerName: string;
  version?: string;
  status: ScannerStatus;
  executionTimeMs: number;
  findingsCount: number;
  errorMessage?: string;
  commandExecuted?: string;
}

export interface ScanCoverage {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  linesOfCodeScanned: number;
  languagesIdentified: string[];
  frameworksIdentified: string[];
  scanners: ScannerExecutionResult[];
  categoriesChecked: VulnerabilityCategory[];
  categoriesNotChecked: VulnerabilityCategory[];
  dastStatus: 'DISABLED' | 'EXECUTED' | 'FAILED' | 'UNAUTHORIZED';
  advisoryDataCurrent: boolean;
  advisoryDataTimestamp?: string;
  unverifiedResultsCount: number;
  knownLimitations: string[];
  summaryMessage: string;
  isCompleteScan: boolean;
}

export interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  suppressedCount: number;
  fixedCount: number;
  durationMs: number;
  startedAt: string;
  completedAt: string;
}

export interface ScanResult {
  scanId: string;
  targetDirectory: string;
  summary: ScanSummary;
  coverage: ScanCoverage;
  findings: SecurityFinding[];
}

export interface ScanOptions {
  targetDirectory: string;
  scanModes?: ('SAST' | 'TAINT' | 'SCA' | 'SECRETS' | 'IAC' | 'API' | 'DAST' | 'SPECIALIZED')[];
  timeoutMs?: number;
  maxFileSizeMb?: number;
  customIgnorePatterns?: string[];
  includeGitHistory?: boolean;
  dastOptions?: {
    enabled: boolean;
    targetUrl: string;
    authorizedScope: string[];
    maxRequestsPerSec?: number;
    timeoutSeconds?: number;
    safeModeOnly?: boolean;
  };
  ollamaOptions?: {
    enabled: boolean;
    endpoint?: string;
    model?: string;
  };
  licensePolicy?: {
    prohibitedLicenses?: string[];
    warnLicenses?: string[];
  };
}

export interface FixVerificationResult {
  findingFingerprint: string;
  patchApplied: boolean;
  rescanExecuted: boolean;
  issueResolved: boolean;
  newFindingsIntroduced: SecurityFinding[];
  checksPerformed: string[];
  remainingUncertainty?: string;
  message: string;
}

export interface BenchmarkMetrics {
  totalTestCases: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  duplicateFindings: number;
  precision: number;
  recall: number;
  f1Score: number;
  scanDurationMs: number;
  categoryBreakdown: Record<string, { tp: number; fp: number; fn: number }>;
}

export type LifecycleStatus =
  | 'OBSERVED'
  | 'POTENTIAL'
  | 'VALIDATING'
  | 'CONFIRMED'
  | 'INCONCLUSIVE'
  | 'REJECTED'
  | 'INFORMATIONAL'
  | 'FIXED_AFTER_RETEST';

export interface ScopeManifest {
  targetOrigin: string;
  authorizedHostnames: string[];
  excludedPaths: string[];
  permitActiveTesting: boolean;
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  timeoutMs: number;
  approvedBy?: string;
  approvalTimestamp?: string;
}

export type CapabilityStatus =
  | 'IMPLEMENTED'
  | 'TESTED'
  | 'PARTIALLY_IMPLEMENTED'
  | 'UNAVAILABLE'
  | 'NOT_TESTED'
  | 'BLOCKED_BY_PERMISSION'
  | 'BLOCKED_BY_DEPENDENCY';

export interface CapabilityRegistryItem {
  featureId: string;
  category: string;
  description: string;
  implementationLocation: string;
  requiredPermissions: string[];
  requiredDependencies: string[];
  testSuite: string;
  status: CapabilityStatus;
  knownLimitations: string[];
}

