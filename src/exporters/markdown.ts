import { ScanResult } from '../core/types';

export class MarkdownExporter {
  public static export(result: ScanResult): string {
    const s = result.summary;
    const c = result.coverage;

    let md = `# Sentinel Security Scan Report\n\n`;
    md += `**Target Directory:** \`${result.targetDirectory}\`  \n`;
    md += `**Scan ID:** \`${result.scanId}\`  \n`;
    md += `**Date:** ${s.completedAt} | **Duration:** ${s.durationMs}ms  \n\n`;

    md += `## Executive Summary\n\n`;
    md += `| Total Active Findings | Critical | High | Medium | Low | Info | Suppressed |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
    md += `| **${s.totalFindings}** | 🔴 ${s.criticalCount} | 🟠 ${s.highCount} | 🟡 ${s.mediumCount} | 🔵 ${s.lowCount} | ⚪ ${s.infoCount} | 🔒 ${s.suppressedCount} |\n\n`;

    md += `> **Status:** ${c.summaryMessage}\n\n`;

    md += `## Coverage Transparency\n\n`;
    md += `- **Files Discovered:** ${c.filesDiscovered}\n`;
    md += `- **Files Scanned:** ${c.filesScanned}\n`;
    md += `- **Files Skipped:** ${c.filesSkipped}\n`;
    md += `- **Approximate Lines of Code:** ${c.linesOfCodeScanned}\n`;
    md += `- **Languages Detected:** ${c.languagesIdentified.join(', ') || 'None'}\n`;
    md += `- **Frameworks Detected:** ${c.frameworksIdentified.join(', ') || 'None'}\n`;
    md += `- **Checked Security Categories:** ${c.categoriesChecked.join(', ')}\n\n`;

    md += `### Executed Scanners\n\n`;
    md += `| Scanner | Version | Status | Duration | Findings |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;
    for (const sc of c.scanners) {
      md += `| **${sc.scannerName}** | \`${sc.version || 'N/A'}\` | \`${sc.status}\` | ${sc.executionTimeMs}ms | ${sc.findingsCount} |\n`;
    }
    md += `\n`;

    if (result.findings.length > 0) {
      md += `## Detailed Findings\n\n`;
      for (const f of result.findings) {
        if (f.suppression?.isSuppressed) continue;
        const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🔵';
        md += `### ${icon} [${f.severity}] ${f.title}\n\n`;
        md += `- **Category:** \`${f.category}\`\n`;
        md += `- **Location:** \`${f.evidence.location.filePath}:${f.evidence.location.startLine}\`\n`;
        md += `- **Engine / Rule:** \`${f.engineName}\` (\`${f.ruleId}\`)\n`;
        if (f.references.cwe?.length) md += `- **CWE:** ${f.references.cwe.join(', ')}\n`;
        if (f.references.cve?.length) md += `- **CVE:** ${f.references.cve.join(', ')}\n`;
        if (f.reachability !== 'UNKNOWN') md += `- **Reachability:** \`${f.reachability}\` (${f.reachabilityEvidence || ''})\n`;
        md += `\n**Description:** ${f.description}\n\n`;

        if (f.evidence.snippet) {
          md += `**Evidence Code:**\n\`\`\`\n${f.evidence.redactedSnippet || f.evidence.snippet}\n\`\`\`\n\n`;
        }

        if (f.evidence.taintTrace && f.evidence.taintTrace.length > 0) {
          md += `**Taint Propagation Trace:**\n`;
          for (const step of f.evidence.taintTrace) {
            md += `  ${step.step}. [${step.type}] \`${step.location.filePath}:${step.location.startLine}\` — ${step.description}\n`;
          }
          md += `\n`;
        }

        if (f.remediation) {
          md += `**Remediation:** ${f.remediation}\n\n`;
        }

        if (f.proposedFix?.patchDiff) {
          md += `**Proposed Fix Diff:**\n\`\`\`diff\n${f.proposedFix.patchDiff}\n\`\`\`\n\n`;
        }

        md += `---\n\n`;
      }
    }

    return md;
  }
}
