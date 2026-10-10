#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { ScanOrchestrator } from '../src/engine/orchestrator';
import { SARIFExporter } from '../src/exporters/sarif';
import { HTMLExporter } from '../src/exporters/html';
import { JSONExporter } from '../src/exporters/json';
import { MarkdownExporter } from '../src/exporters/markdown';
import { ToolDiscovery } from '../src/scanners/discovery';
import { ScanOptions } from '../src/core/types';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';

  if (command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  if (command === 'discovery' || command === 'tools') {
    console.log('\n🔍 Sentinel Security — Scanner Discovery\n');
    const tools = await ToolDiscovery.discover();
    for (const [k, v] of Object.entries(tools)) {
      console.log(`  - ${k.padEnd(14)}: ${v ? `✅ Found at ${v}` : '❌ Not installed (Built-in engine fallback active)'}`);
    }
    console.log('');
    return;
  }

  if (command === 'scan') {
    const targetDir = args[1] ? path.resolve(args[1]) : process.cwd();
    let sarifOut: string | undefined;
    let htmlOut: string | undefined;
    let jsonOut: string | undefined;
    let dastUrl: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if (args[i] === '--sarif' && args[i + 1]) sarifOut = args[++i];
      if (args[i] === '--html' && args[i + 1]) htmlOut = args[++i];
      if (args[i] === '--json' && args[i + 1]) jsonOut = args[++i];
      if (args[i] === '--dast' && args[i + 1]) dastUrl = args[++i];
    }

    console.log(`\n🛡️  Sentinel Security — Starting Scan on: ${targetDir}`);

    const options: ScanOptions = {
      targetDirectory: targetDir,
      dastOptions: dastUrl ? {
        enabled: true,
        targetUrl: dastUrl,
        authorizedScope: [dastUrl],
        safeModeOnly: true
      } : undefined
    };

    const orchestrator = new ScanOrchestrator(targetDir);
    const result = await orchestrator.runScan(options);

    console.log(MarkdownExporter.export(result));

    if (sarifOut) {
      fs.writeFileSync(path.resolve(sarifOut), SARIFExporter.export(result), 'utf8');
      console.log(`✅ Saved SARIF report to: ${sarifOut}`);
    }

    if (htmlOut) {
      fs.writeFileSync(path.resolve(htmlOut), HTMLExporter.export(result), 'utf8');
      console.log(`✅ Saved HTML report to: ${htmlOut}`);
    }

    if (jsonOut) {
      fs.writeFileSync(path.resolve(jsonOut), JSONExporter.export(result), 'utf8');
      console.log(`✅ Saved JSON report to: ${jsonOut}`);
    }

    // Exit code: 1 if critical/high findings, 0 otherwise
    if (result.summary.criticalCount > 0 || result.summary.highCount > 0) {
      process.exitCode = 1;
    }
    return;
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exitCode = 1;
}

function printHelp() {
  console.log(`
🛡️  Sentinel Security CLI — Zero-API Multi-Layer Security Platform

Usage:
  sentinel scan [dir] [options]    Scan directory for vulnerabilities
  sentinel tools                   Discover installed scanner binaries
  sentinel help                    Show this help menu

Options:
  --sarif <file>                   Output report in SARIF v2.1.0 format
  --html <file>                    Output report as interactive HTML dashboard
  --json <file>                    Output raw JSON scan results
  --dast <url>                     Run authorized dynamic tests against URL
  `);
}

main().catch(err => {
  console.error('Fatal Sentinel CLI Error:', err);
  process.exit(1);
});
