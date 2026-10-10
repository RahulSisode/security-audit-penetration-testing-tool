import { SecurityFinding, ProposedFix } from '../core/types';

export interface RemediationGuidance {
  title: string;
  summary: string;
  securePatternExample: string;
  insecurePatternExample: string;
  remediationSteps: string[];
  referenceLinks: string[];
}

export class RuleBasedRemediationEngine {
  public static getGuidance(finding: SecurityFinding): RemediationGuidance {
    switch (finding.category) {
      case 'INJECTION':
        return {
          title: 'SQL / Command Injection Remediation',
          summary: 'Prevent dynamic string construction of queries or commands using untrusted inputs.',
          insecurePatternExample: 'db.query("SELECT * FROM users WHERE id = " + userId);\nchild_process.exec("ping " + host);',
          securePatternExample: 'db.query("SELECT * FROM users WHERE id = $1", [userId]);\nchild_process.execFile("ping", [host]);',
          remediationSteps: [
            '1. Replace string concatenation with parameterized query placeholders (? or $1).',
            '2. Bind user values as parameters in an array.',
            '3. For system commands, use execFile or spawn with argument arrays without shell: true.',
            '4. Implement strict input validation with whitelist regexes.'
          ],
          referenceLinks: [
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/89.html'
          ]
        };

      case 'XSS':
        return {
          title: 'Cross-Site Scripting (XSS) Remediation',
          summary: 'Ensure untrusted data is never directly interpreted as executable HTML markup.',
          insecurePatternExample: 'element.innerHTML = userInput;\n<div dangerouslySetInnerHTML={{ __html: content }} />',
          securePatternExample: 'element.textContent = userInput;\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
          remediationSteps: [
            '1. Use textContent or innerText instead of innerHTML.',
            '2. If rich HTML is required, sanitize through DOMPurify.sanitize().',
            '3. Implement a robust Content Security Policy (CSP) with nonce-based script execution.'
          ],
          referenceLinks: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
          ]
        };

      case 'SECRETS':
        return {
          title: 'Hardcoded Credential Remediation',
          summary: 'Remove credentials from source control and load via secure environment variables.',
          insecurePatternExample: 'const apiKey = "sk-proj-928374982374982374";',
          securePatternExample: 'const apiKey = process.env.OPENAI_API_KEY;',
          remediationSteps: [
            '1. Remove the plaintext secret from source code immediately.',
            '2. Revoke and rotate the exposed token in the provider dashboard.',
            '3. Add secret variables to local .env and verify .env is in .gitignore.',
            '4. Load credentials via process.env or cloud secret managers (AWS Secrets Manager, Vault).'
          ],
          referenceLinks: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
          ]
        };

      case 'DEPENDENCY_VULNERABILITY':
        return {
          title: 'Vulnerable Dependency Upgrade Guidance',
          summary: 'Upgrade third-party library to a patched release without known security advisories.',
          insecurePatternExample: '"lodash": "4.17.15"',
          securePatternExample: '"lodash": "^4.17.21"',
          remediationSteps: [
            '1. Review advisory details and fixed version numbers.',
            '2. Update package manifest and lockfile (npm install <pkg>@latest / pip install -U <pkg>).',
            '3. Run project unit and integration test suite to verify backwards compatibility.'
          ],
          referenceLinks: [
            'https://github.com/advisories'
          ]
        };

      default:
        return {
          title: `${finding.category} Security Guidance`,
          summary: finding.description,
          insecurePatternExample: finding.evidence.snippet || 'Unsafe pattern',
          securePatternExample: '// Refer to remediation instructions below',
          remediationSteps: [
            '1. ' + (finding.remediation || 'Apply principle of least privilege and strict input validation.')
          ],
          referenceLinks: finding.references.urls || []
        };
    }
  }
}
