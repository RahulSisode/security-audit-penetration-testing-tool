#!/usr/bin/env bash
set -e

echo "===================================================="
echo "🛡️  Sentinel Security — One-Command Setup (macOS / Linux)"
echo "===================================================="

# 1. Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed. Please install Node.js >= 18."
    exit 1
fi

echo "✅ Node.js $(node -v) detected"

# 2. Install Project Dependencies
echo "📦 Installing npm dependencies..."
npm install

# 3. Discover / Check Scanner Tools
echo "🔍 Discovering security scanners..."
npm run setup:tools

# 4. Compile TypeScript
echo "🔨 Building TypeScript extension..."
npm run build

# 5. Run Validation Tests
echo "🧪 Running unit & benchmark test suites..."
npm test

echo ""
echo "===================================================="
echo "🎉 Sentinel Security Setup Complete!"
echo "To package the extension into an installable VSIX:"
echo "  npm run package"
echo "To run a scan via CLI:"
echo "  npm run scan -- ."
echo "===================================================="
