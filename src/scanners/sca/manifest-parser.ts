import * as fs from 'fs';
import * as path from 'path';

export interface DiscoveredPackage {
  name: string;
  version: string;
  isDirect: boolean;
  ecosystem: 'npm' | 'pypi' | 'golang' | 'maven' | 'cargo' | 'rubygems' | 'packagist';
  manifestPath: string;
  license?: string;
}

export class ManifestParser {
  public static parseAll(workspaceRoot: string): DiscoveredPackage[] {
    const packages: DiscoveredPackage[] = [];

    // 1. Node / NPM: package.json & package-lock.json
    const packageJsonPath = path.join(workspaceRoot, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const deps = { ...(raw.dependencies || {}), ...(raw.devDependencies || {}) };
        for (const [name, ver] of Object.entries(deps)) {
          packages.push({
            name,
            version: String(ver).replace(/^[\^~>=<]/, ''),
            isDirect: true,
            ecosystem: 'npm',
            manifestPath: 'package.json',
            license: raw.license
          });
        }
      } catch {}
    }

    const lockPath = path.join(workspaceRoot, 'package-lock.json');
    if (fs.existsSync(lockPath)) {
      try {
        const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        const packagesObj = lock.packages || {};
        for (const [pkgPath, meta] of Object.entries(packagesObj) as [string, any][]) {
          if (pkgPath && meta.version) {
            const name = pkgPath.replace(/^node_modules\//, '');
            if (!packages.some(p => p.name === name)) {
              packages.push({
                name,
                version: meta.version,
                isDirect: false,
                ecosystem: 'npm',
                manifestPath: 'package-lock.json',
                license: meta.license
              });
            }
          }
        }
      } catch {}
    }

    // 2. Python: requirements.txt
    const reqPath = path.join(workspaceRoot, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      try {
        const lines = fs.readFileSync(reqPath, 'utf8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim().split('#')[0];
          if (!trimmed) continue;
          const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-_]+)/);
          if (match) {
            packages.push({
              name: match[1],
              version: match[2],
              isDirect: true,
              ecosystem: 'pypi',
              manifestPath: 'requirements.txt'
            });
          }
        }
      } catch {}
    }

    // 3. Go: go.mod
    const goModPath = path.join(workspaceRoot, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const lines = fs.readFileSync(goModPath, 'utf8').split('\n');
        for (const line of lines) {
          const match = line.trim().match(/^([a-zA-Z0-9\.\_\-\/]+)\s+v([0-9a-zA-Z\.\-_]+)/);
          if (match && !match[1].startsWith('module') && !match[1].startsWith('go')) {
            packages.push({
              name: match[1],
              version: match[2],
              isDirect: !line.includes('// indirect'),
              ecosystem: 'golang',
              manifestPath: 'go.mod'
            });
          }
        }
      } catch {}
    }

    // 4. Rust: Cargo.lock or Cargo.toml
    const cargoLock = path.join(workspaceRoot, 'Cargo.lock');
    if (fs.existsSync(cargoLock)) {
      try {
        const content = fs.readFileSync(cargoLock, 'utf8');
        const pkgBlocks = content.split('[[package]]');
        for (const block of pkgBlocks) {
          const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
          const verMatch = block.match(/version\s*=\s*"([^"]+)"/);
          if (nameMatch && verMatch) {
            packages.push({
              name: nameMatch[1],
              version: verMatch[1],
              isDirect: false,
              ecosystem: 'cargo',
              manifestPath: 'Cargo.lock'
            });
          }
        }
      } catch {}
    }

    return packages;
  }
}
