import * as path from 'path';
import * as fs from 'fs';
import { executeSafeProcess } from '../utils/process';

export interface DiscoveredTools {
  semgrep?: string;
  gitleaks?: string;
  trivy?: string;
  osvScanner?: string;
  checkov?: string;
  zap?: string;
  ollama?: string;
}

export class ToolDiscovery {
  private static cachedTools: DiscoveredTools | null = null;

  public static async discover(workspaceRoot?: string): Promise<DiscoveredTools> {
    if (this.cachedTools) return this.cachedTools;

    const tools: DiscoveredTools = {};
    const candidatePaths = [
      process.env.PATH?.split(path.delimiter) || [],
      workspaceRoot ? [path.join(workspaceRoot, '.sentinel', 'bin')] : [],
      ['/usr/local/bin', '/opt/homebrew/bin', '/usr/bin', process.env.USERPROFILE ? path.join(process.env.USERPROFILE, '.sentinel', 'bin') : '']
    ].flat().filter(Boolean);

    // List of binaries to check
    const binaries = [
      { key: 'semgrep' as const, name: 'semgrep' },
      { key: 'gitleaks' as const, name: 'gitleaks' },
      { key: 'trivy' as const, name: 'trivy' },
      { key: 'osvScanner' as const, name: 'osv-scanner' },
      { key: 'checkov' as const, name: 'checkov' },
      { key: 'zap' as const, name: process.platform === 'win32' ? 'zap.bat' : 'zap.sh' },
      { key: 'ollama' as const, name: 'ollama' }
    ];

    for (const b of binaries) {
      for (const dir of candidatePaths) {
        const ext = process.platform === 'win32' ? '.exe' : '';
        const target = path.join(dir, b.name + ext);
        if (fs.existsSync(target)) {
          tools[b.key] = target;
          break;
        }
      }

      // If not found in standard directories, try checking PATH via 'which' or 'where'
      if (!tools[b.key]) {
        const cmd = process.platform === 'win32' ? 'where' : 'which';
        const res = await executeSafeProcess(cmd, [b.name], { timeoutMs: 2000 });
        if (res.exitCode === 0 && res.stdout.trim()) {
          const firstPath = res.stdout.trim().split('\n')[0].trim();
          if (fs.existsSync(firstPath)) {
            tools[b.key] = firstPath;
          }
        }
      }
    }

    this.cachedTools = tools;
    return tools;
  }

  public static clearCache(): void {
    this.cachedTools = null;
  }
}
