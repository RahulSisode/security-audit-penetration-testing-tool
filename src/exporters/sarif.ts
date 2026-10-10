import { ScanResult, SecurityFinding } from '../core/types';

export class SARIFExporter {
  public static export(result: ScanResult): string {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Sentinel Security',
              version: '1.0.0',
              informationUri: 'https://github.com/sentinel-security/sentinel',
              rules: this.extractRules(result.findings)
            }
          },
          results: result.findings.map(f => this.convertFindingToSarifResult(f))
        }
      ]
    };

    return JSON.stringify(sarif, null, 2);
  }

  private static extractRules(findings: SecurityFinding[]): any[] {
    const ruleMap = new Map<string, any>();

    for (const f of findings) {
      if (!ruleMap.has(f.ruleId)) {
        ruleMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          shortDescription: { text: f.title },
          fullDescription: { text: f.description },
          help: { text: f.remediation || f.description },
          properties: {
            category: f.category,
            precision: f.confidence.toLowerCase(),
            tags: [...(f.references.cwe || []), ...(f.references.owasp || [])]
          }
        });
      }
    }

    return Array.from(ruleMap.values());
  }

  private static convertFindingToSarifResult(f: SecurityFinding): any {
    return {
      ruleId: f.ruleId,
      level: this.mapSeverityToSarifLevel(f.severity),
      message: {
        text: `${f.title}: ${f.description}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.evidence.location.filePath.replace(/\\/g, '/')
            },
            region: {
              startLine: f.evidence.location.startLine || 1,
              startColumn: f.evidence.location.startColumn || 1,
              endLine: f.evidence.location.endLine || f.evidence.location.startLine || 1,
              endColumn: f.evidence.location.endColumn || 80,
              snippet: {
                text: f.evidence.redactedSnippet || f.evidence.snippet || ''
              }
            }
          }
        }
      ],
      fingerprints: {
        'sentinel/v1': f.fingerprint
      }
    };
  }

  private static mapSeverityToSarifLevel(sev: string): string {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
      case 'INFO':
        return 'note';
      default:
        return 'warning';
    }
  }
}
