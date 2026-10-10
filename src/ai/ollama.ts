import * as http from 'http';
import { URL } from 'url';
import { SecurityFinding } from '../core/types';
import { redactSecrets } from '../core/redaction';

export interface OllamaModelInfo {
  name: string;
  modified_at: string;
  size: number;
}

export interface OllamaExplanationResult {
  explanation: string;
  secureAlternative: string;
  proposedPatch?: string;
  suggestedTests?: string;
  modelUsed: string;
}

export class OllamaClient {
  private endpoint: string;
  private defaultModel: string;

  constructor(endpoint: string = 'http://127.0.0.1:11434', defaultModel: string = 'llama3') {
    this.endpoint = endpoint;
    this.defaultModel = defaultModel;
  }

  public async isAvailable(): Promise<boolean> {
    try {
      const url = new URL('/api/tags', this.endpoint);
      const res = await this.makeRequest(url, 'GET');
      return res.statusCode === 200;
    } catch {
      return false;
    }
  }

  public async listModels(): Promise<OllamaModelInfo[]> {
    try {
      const url = new URL('/api/tags', this.endpoint);
      const res = await this.makeRequest(url, 'GET');
      if (res.statusCode === 200 && res.body) {
        const parsed = JSON.parse(res.body);
        return parsed.models || [];
      }
    } catch {}
    return [];
  }

  public async explainAndSuggestFix(
    finding: SecurityFinding,
    model?: string
  ): Promise<OllamaExplanationResult | null> {
    const isAvail = await this.isAvailable();
    if (!isAvail) return null;

    const selectedModel = model || this.defaultModel;
    const sanitizedSnippet = redactSecrets(finding.evidence.snippet || '');

    const prompt = `You are a cybersecurity expert. Analyze the following security finding:
Vulnerability: ${finding.title} (${finding.category})
Severity: ${finding.severity}
File: ${finding.evidence.location.filePath}:${finding.evidence.location.startLine}
Code Snippet:
\`\`\`
${sanitizedSnippet}
\`\`\`

Provide:
1. Concise Explanation: Why this is insecure and what the attack vector is.
2. Secure Code Alternative: The minimal secure code replacement.
3. Unit / Regression Test: A test case to verify the fix and prevent regressions.

Format response clearly with Markdown code blocks.`;

    try {
      const url = new URL('/api/generate', this.endpoint);
      const payload = JSON.stringify({
        model: selectedModel,
        prompt,
        stream: false
      });

      const res = await this.makeRequest(url, 'POST', payload);
      if (res.statusCode === 200 && res.body) {
        const parsed = JSON.parse(res.body);
        const responseText = parsed.response || '';

        return {
          explanation: responseText,
          secureAlternative: 'See generated AI explanation',
          modelUsed: selectedModel
        };
      }
    } catch {}

    return null;
  }

  private makeRequest(url: URL, method: string, data?: string): Promise<{ statusCode?: number; body: string }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        url,
        {
          method,
          timeout: 15000,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': data ? Buffer.byteLength(data) : 0
          }
        },
        (res) => {
          let body = '';
          res.on('data', chunk => body += chunk.toString('utf8'));
          res.on('end', () => resolve({ statusCode: res.statusCode, body }));
        }
      );

      req.on('error', (err) => resolve({ statusCode: 500, body: err.message }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ statusCode: 408, body: 'Timeout' });
      });

      if (data) req.write(data);
      req.end();
    });
  }
}
