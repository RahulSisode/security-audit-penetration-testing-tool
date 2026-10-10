# Sentinel Security — One-Command Setup for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "🛡️  Sentinel Security — One-Command Setup (Windows)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Check Node.js
try {
    $nodeVer = node -v
    Write-Host "✅ Node.js $nodeVer detected" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js is required but not found in PATH. Please install Node.js >= 18." -ForegroundColor Red
    exit 1
}

# 2. Install Project Dependencies
Write-Host "📦 Installing npm dependencies..." -ForegroundColor Yellow
npm install

# 3. Discover / Check Scanner Tools
Write-Host "🔍 Discovering security scanners..." -ForegroundColor Yellow
npm run setup:tools

# 4. Compile TypeScript
Write-Host "🔨 Building TypeScript extension..." -ForegroundColor Yellow
npm run build

# 5. Run Validation Tests
Write-Host "🧪 Running unit & benchmark test suites..." -ForegroundColor Yellow
npm test

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "🎉 Sentinel Security Setup Complete!" -ForegroundColor Green
Write-Host "To package the extension into an installable VSIX:" -ForegroundColor Yellow
Write-Host "  npm run package"
Write-Host "To run a scan via CLI:" -ForegroundColor Yellow
Write-Host "  npm run scan -- ."
Write-Host "====================================================" -ForegroundColor Cyan
