import { ScanCoverage, ScannerExecutionResult, VulnerabilityCategory, SecurityFinding } from './types';

export const ALL_SECURITY_CATEGORIES: VulnerabilityCategory[] = [
  'INJECTION',
  'XSS',
  'PATH_TRAVERSAL',
  'SSRF',
  'UNSAFE_REDIRECT',
  'DESERIALIZATION',
  'AUTH_AUTHZ',
  'IDOR_BOLA',
  'CRYPTOGRAPHY',
  'INSECURE_RNG',
  'RACE_CONDITION',
  'MEMORY_SAFETY',
  'INTEGER_OVERFLOW',
  'NULL_DEREFERENCE',
  'FORMAT_STRING',
  'INPUT_VALIDATION',
  'SENSITIVE_DATA_EXPOSURE',
  'INSECURE_TEMP_FILE',
  'UNSAFE_REFLECTION',
  'PROTOTYPE_POLLUTION',
  'REDOS',
  'RESOURCE_EXHAUSTION',
  'XXE',
  'FILE_UPLOAD',
  'BUSINESS_LOGIC',
  'SECRETS',
  'DEPENDENCY_VULNERABILITY',
  'SUPPLY_CHAIN_RISK',
  'LICENSE_VIOLATION',
  'IAC_MISCONFIGURATION',
  'CONTAINER_SECURITY',
  'CI_CD_SECURITY',
  'API_SECURITY',
  'DAST_DYNAMIC_FINDING',
  'TAINT_FLOW'
];

export function computeScanCoverage(
  filesDiscovered: number,
  filesScanned: number,
  filesSkipped: number,
  linesOfCodeScanned: number,
  languages: string[],
  frameworks: string[],
  scanners: ScannerExecutionResult[],
  categoriesChecked: VulnerabilityCategory[],
  findings: SecurityFinding[],
  dastStatus: 'DISABLED' | 'EXECUTED' | 'FAILED' | 'UNAUTHORIZED' = 'DISABLED',
  knownLimitations: string[] = []
): ScanCoverage {
  const checkedSet = new Set(categoriesChecked);
  const categoriesNotChecked = ALL_SECURITY_CATEGORIES.filter(cat => !checkedSet.has(cat));

  const unverifiedResultsCount = findings.filter(
    f => f.verificationStatus === 'UNVERIFIED' || f.verificationStatus === 'SUSPECTED'
  ).length;

  const hasScannerFailures = scanners.some(s => s.status === 'FAILED');
  const isCompleteScan = filesSkipped === 0 && !hasScannerFailures;

  let summaryMessage: string;
  if (findings.length === 0) {
    summaryMessage = 'No findings detected in the completed checks. Note: This does not prove no vulnerabilities exist.';
  } else {
    summaryMessage = `Scan completed with ${findings.length} findings across ${categoriesChecked.length} checked security categories.`;
  }

  return {
    filesDiscovered,
    filesScanned,
    filesSkipped,
    linesOfCodeScanned,
    languagesIdentified: languages,
    frameworksIdentified: frameworks,
    scanners,
    categoriesChecked,
    categoriesNotChecked,
    dastStatus,
    advisoryDataCurrent: true,
    advisoryDataTimestamp: new Date().toISOString(),
    unverifiedResultsCount,
    knownLimitations: [
      ...knownLimitations,
      'Static analysis cannot deterministically verify complex dynamic multi-factor authorization flows without runtime simulation',
      'Reachability is reported only when call-graph or import-chain evidence is detected'
    ],
    summaryMessage,
    isCompleteScan
  };
}
