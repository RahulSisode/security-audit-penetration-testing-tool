import * as fs from 'fs';
import * as path from 'path';

export interface WorkspaceDiscoveryResult {
  allFiles: string[];
  scannableFiles: string[];
  skippedFiles: string[];
  languages: string[];
  frameworks: string[];
  totalLinesOfCode: number;
}

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.vscode',
  '.idea',
  'target',
  'bin',
  'obj',
  'vendor',
  '.terraform',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.nuxt',
  'coverage',
  '.vsce',
  'fixtures'
]);

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  '.js': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.jsx': 'JavaScript',
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.py': 'Python',
  '.java': 'Java',
  '.go': 'Go',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.cs': 'C#',
  '.c': 'C',
  '.cpp': 'C++',
  '.cc': 'C++',
  '.h': 'C/C++ Header',
  '.hpp': 'C++ Header',
  '.rs': 'Rust',
  '.kt': 'Kotlin',
  '.swift': 'Swift',
  '.sql': 'SQL',
  '.sh': 'Shell',
  '.bash': 'Shell',
  '.zsh': 'Shell',
  '.ps1': 'PowerShell',
  '.tf': 'Terraform',
  '.yaml': 'YAML/IaC',
  '.yml': 'YAML/IaC',
  '.json': 'JSON',
  '.xml': 'XML',
  '.html': 'HTML'
};

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
  '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.jar',
  '.woff', '.woff2', '.ttf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.wasm'
]);

export class WorkspaceScanner {
  public static isPathInsideWorkspace(targetPath: string, workspaceRoot: string): boolean {
    const rel = path.relative(workspaceRoot, targetPath);
    return !rel.startsWith('..') && !path.isAbsolute(rel);
  }

  public static discoverFiles(
    workspaceRoot: string,
    maxFileSizeMb: number = 5,
    customIgnorePatterns: string[] = []
  ): WorkspaceDiscoveryResult {
    const allFiles: string[] = [];
    const scannableFiles: string[] = [];
    const skippedFiles: string[] = [];
    const languages = new Set<string>();
    const frameworks = new Set<string>();
    let totalLinesOfCode = 0;

    const customIgnores = new Set(customIgnorePatterns);

    function walkDir(currentDir: string) {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        const relPath = path.relative(workspaceRoot, fullPath);

        if (entry.isDirectory()) {
          if (
            (DEFAULT_IGNORE_DIRS.has(entry.name) && !workspaceRoot.includes(entry.name)) ||
            customIgnores.has(entry.name) ||
            entry.name.startsWith('.sentinel')
          ) {
            continue;
          }
          walkDir(fullPath);
        } else if (entry.isFile()) {
          const base = entry.name.toLowerCase();
          const ext = path.extname(entry.name).toLowerCase();

          // Ignore generated report files and build artifacts
          if (
            base.startsWith('scan-report.') ||
            base.endsWith('.sarif') ||
            base.endsWith('.vsix') ||
            base.startsWith('.sentinel-')
          ) {
            continue;
          }

          allFiles.push(fullPath);

          // Detect Frameworks & Manifests
          if (base === 'package.json') frameworks.add('Node.js');
          if (base === 'requirements.txt' || base === 'pyproject.toml') frameworks.add('Python');
          if (base === 'go.mod') frameworks.add('Go');
          if (base === 'pom.xml' || base === 'build.gradle') frameworks.add('Java');
          if (base === 'cargo.toml') frameworks.add('Rust');
          if (base === 'gemfile') frameworks.add('Ruby');
          if (base === 'composer.json') frameworks.add('PHP');
          if (base === 'dockerfile' || base.endsWith('.dockerfile')) frameworks.add('Docker');
          if (ext === '.tf') frameworks.add('Terraform');
          if (relPath.includes('.github/workflows')) frameworks.add('GitHub Actions');

          // Check for binary or skip criteria
          if (BINARY_EXTENSIONS.has(ext)) {
            skippedFiles.push(fullPath);
            continue;
          }

          try {
            const stats = fs.statSync(fullPath);
            if (stats.size > maxFileSizeMb * 1024 * 1024) {
              skippedFiles.push(fullPath);
              continue;
            }

            if (EXTENSION_LANGUAGE_MAP[ext] || base.startsWith('dockerfile') || ext === '.env') {
              languages.add(EXTENSION_LANGUAGE_MAP[ext] || 'Configuration');
              scannableFiles.push(fullPath);

              // Count approximate lines
              const content = fs.readFileSync(fullPath, 'utf8');
              totalLinesOfCode += content.split('\n').length;

              // Check web framework hints
              if (content.includes('express()') || content.includes('require("express")')) frameworks.add('Express');
              if (content.includes('from fastapi') || content.includes('import FastAPI')) frameworks.add('FastAPI');
              if (content.includes('from flask') || content.includes('import Flask')) frameworks.add('Flask');
              if (content.includes('django') || content.includes('DJANGO_SETTINGS_MODULE')) frameworks.add('Django');
              if (content.includes('@nestjs/common') || content.includes('@Controller')) frameworks.add('NestJS');
              if (content.includes('org.springframework.boot')) frameworks.add('Spring Boot');
              if (content.includes('react') && (ext === '.jsx' || ext === '.tsx' || ext === '.js')) frameworks.add('React');
            } else {
              scannableFiles.push(fullPath);
            }
          } catch {
            skippedFiles.push(fullPath);
          }
        }
      }
    }

    walkDir(workspaceRoot);

    return {
      allFiles,
      scannableFiles,
      skippedFiles,
      languages: Array.from(languages),
      frameworks: Array.from(frameworks),
      totalLinesOfCode
    };
  }
}
