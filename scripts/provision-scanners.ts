import * as fs from 'fs';
import * as path from 'path';
import { ToolDiscovery } from '../src/scanners/discovery';

async function main() {
  console.log('====================================================');
  console.log('🛡️  Sentinel Security — Scanner Environment Setup');
  console.log('====================================================\n');

  console.log(`Operating System: ${process.platform} (${process.arch})`);
  console.log(`Node.js Version: ${process.version}\n`);

  const tools = await ToolDiscovery.discover();

  console.log('--- Scanner Discovery Status ---');
  console.log(`1. Semgrep (SAST Engine):        ${tools.semgrep ? `✅ ${tools.semgrep}` : '⚠️ Not in PATH (Built-in multi-rule SAST active)'}`);
  console.log(`2. Gitleaks (Credential Engine): ${tools.gitleaks ? `✅ ${tools.gitleaks}` : '⚠️ Not in PATH (Built-in Shannon entropy active)'}`);
  console.log(`3. Trivy (SCA/IaC):               ${tools.trivy ? `✅ ${tools.trivy}` : '⚠️ Not in PATH (Built-in CVE advisory & IaC active)'}`);
  console.log(`4. OSV-Scanner (SCA):          ${tools.osvScanner ? `✅ ${tools.osvScanner}` : '⚠️ Not in PATH (Built-in offline advisory database active)'}`);
  console.log(`5. Checkov (IaC):              ${tools.checkov ? `✅ ${tools.checkov}` : '⚠️ Not in PATH (Built-in Docker/K8s/TF engine active)'}`);
  console.log(`6. OWASP ZAP (DAST):           ${tools.zap ? `✅ ${tools.zap}` : '⚠️ Not in PATH (Built-in safe canary DAST active)'}`);
  console.log(`7. Ollama (Optional AI):       ${tools.ollama ? `✅ ${tools.ollama}` : 'ℹ️ Optional: Not installed'}\n`);

  console.log('✨ All Sentinel built-in multi-layer scanners are ready to scan with 100% local, zero-API fallback.');
  console.log('Optional CLI installation guides:');
  if (process.platform === 'darwin') {
    console.log('  brew install gitleaks trivy semgrep\n');
  } else if (process.platform === 'linux') {
    console.log('  apt-get install gitleaks trivy OR snap install semgrep\n');
  } else if (process.platform === 'win32') {
    console.log('  choco install gitleaks trivy semgrep\n');
  }
}

main().catch(console.error);
