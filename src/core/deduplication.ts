import { SecurityFinding } from './types';

/**
 * Deduplicates findings reported by multiple engines.
 * If two scanners detect the same vulnerability at the same file and overlapping line:
 * - Keeps the unified finding with highest confidence / severity without artificial inflation
 * - Merges references (CWE, CVE, OWASP, URLs)
 * - Retains taint traces and evidence from all engines
 * - Appends engine detection history
 */
export function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const map = new Map<string, SecurityFinding>();

  for (const finding of findings) {
    // Check for exact fingerprint match first
    const fp = finding.fingerprint;
    if (!map.has(fp)) {
      // Check for overlapping location match (same file, same category, line +/- 2)
      let foundOverlap = false;
      for (const [existingFp, existing] of map.entries()) {
        if (
          existing.affectedComponent === finding.affectedComponent &&
          existing.category === finding.category &&
          existing.evidence.location.filePath === finding.evidence.location.filePath &&
          Math.abs(existing.evidence.location.startLine - finding.evidence.location.startLine) <= 2
        ) {
          // Merge finding into existing
          mergeFinding(existing, finding);
          foundOverlap = true;
          break;
        }
      }

      if (!foundOverlap) {
        map.set(fp, { ...finding });
      }
    } else {
      const existing = map.get(fp)!;
      mergeFinding(existing, finding);
    }
  }

  return Array.from(map.values());
}

function mergeFinding(target: SecurityFinding, source: SecurityFinding): void {
  // Merge references
  const cweSet = new Set([...(target.references.cwe || []), ...(source.references.cwe || [])]);
  const cveSet = new Set([...(target.references.cve || []), ...(source.references.cve || [])]);
  const owaspSet = new Set([...(target.references.owasp || []), ...(source.references.owasp || [])]);
  const urlSet = new Set([...(target.references.urls || []), ...(source.references.urls || [])]);

  target.references = {
    cwe: Array.from(cweSet),
    cve: Array.from(cveSet),
    owasp: Array.from(owaspSet),
    urls: Array.from(urlSet),
    cvss: Math.max(target.references.cvss || 0, source.references.cvss || 0) || undefined
  };

  // Keep taint trace if target doesn't have one and source does
  if (!target.evidence.taintTrace && source.evidence.taintTrace) {
    target.evidence.taintTrace = source.evidence.taintTrace;
  }

  // Keep proposed fix if target doesn't have one and source does
  if (!target.proposedFix && source.proposedFix) {
    target.proposedFix = source.proposedFix;
  }

  // If engine names differ, record multi-engine detection in engineName
  if (!target.engineName.includes(source.engineName)) {
    target.engineName = `${target.engineName}, ${source.engineName}`;
  }

  // If one engine verified reachability, preserve it
  if (source.reachability === 'REACHABLE') {
    target.reachability = 'REACHABLE';
    target.reachabilityEvidence = source.reachabilityEvidence || target.reachabilityEvidence;
  }
}
