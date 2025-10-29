# Build & Package Instructions

## Prerequisites

```bash
# Required software:
- Node.js v14+ (check: node --version)
- npm v6+ (check: npm --version)
- VSCode v1.75+ (check: code --version)
```

## Quick Build (3 steps)

### Step 1: Install VSCE (VSCode Extension Packager)

```bash
npm install -g vsce
```

### Step 2: Package the Extension

```bash
cd "/Users/kraj/Desktop/Company-code/Static Analysis/kr_vscode"
vsce package
```

This creates: `malware-steganography-detector-1.0.0.vsix`

### Step 3: Install in VSCode

```bash
code --install-extension malware-steganography-detector-1.0.0.vsix
```

Or via VSCode UI:
1. Open VSCode
2. `Ctrl+Shift+P` / `Cmd+Shift+P`
3. Type: "Install from VSIX"
4. Select the `.vsix` file

### Step 4: Reload VSCode

```bash
# Via Command Palette:
Ctrl+Shift+P / Cmd+Shift+P
> Developer: Reload Window
```

## Verify Installation

```bash
# Check extension is installed
code --list-extensions | grep malware

# Expected output:
# kr-security.malware-steganography-detector
```

## Test the Extension

```bash
# Open test file
cd "/Users/kraj/Desktop/Company-code/Static Analysis/kr_vscode"
code test-examples.js

# Check Problems panel (Ctrl+Shift+M / Cmd+Shift+M)
# Should see ~17 detections
```

## Development Mode

### Option 1: F5 Launch (Recommended)

1. Open `kr_vscode` folder in VSCode
2. Press `F5` (or Run → Start Debugging)
3. New "Extension Development Host" window opens
4. Test changes in the dev window
5. Reload with `Ctrl+R` / `Cmd+R`

### Option 2: Manual Testing

```bash
# Watch for changes
npm run watch

# In another terminal, reload extension
code --reload
```

## Publishing (Future)

### To VSCode Marketplace

```bash
# Create publisher account at: https://marketplace.visualstudio.com/

# Login
vsce login <publisher-name>

# Publish
vsce publish
```

### To GitHub Releases

```bash
# Tag version
git tag v1.0.0
git push origin v1.0.0

# Upload .vsix file to GitHub Releases
# Go to: https://github.com/your-repo/releases/new
```

## File Structure

```
kr_vscode/
├── extension.js              # Main extension (340 lines)
├── detector.js               # Detection engine (580 lines)
├── package.json              # Manifest
├── test-examples.js          # Test cases
├── README.md                 # Main docs
├── INSTALLATION.md           # Setup guide
├── QUICK_START.md            # Quick guide
├── CHANGELOG.md              # Version history
├── UNICODE_ATTACKS_RESEARCH.md  # Technical research
├── PROJECT_OVERVIEW.md       # Architecture
├── BUILD_INSTRUCTIONS.md     # This file
├── LICENSE                   # MIT License
├── .gitignore               # Git exclusions
└── .vscodeignore            # Package exclusions
```

## Troubleshooting

### Error: "vsce: command not found"

```bash
npm install -g vsce
# Or use npx:
npx vsce package
```

### Error: "A 'repository' field is missing"

Add to `package.json`:
```json
{
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/malware-detector"
  }
}
```

### Error: "Extension activation failed"

Check Output panel:
1. `Ctrl+Shift+U` / `Cmd+Shift+U`
2. Select "Malware Detector" from dropdown
3. Look for error messages

### Extension not detecting anything

1. Check settings: `malwareDetector.enabled` = `true`
2. Check status bar (should show shield icon)
3. Try manual scan: `Cmd/Ctrl+Shift+P` → "Scan Current File"
4. Check file type isn't excluded

## Clean Build

```bash
# Remove old .vsix files
rm *.vsix

# Clear npm cache (if needed)
npm cache clean --force

# Rebuild
vsce package
```

## Distribution

### Share with Team

```bash
# Option 1: Share .vsix file directly
# Send: malware-steganography-detector-1.0.0.vsix
# Recipients run: code --install-extension <file>

# Option 2: Internal marketplace
# Upload to company's internal extension repo

# Option 3: Git repository
git clone <repo>
cd malware-detector
vsce package
code --install-extension malware-steganography-detector-1.0.0.vsix
```

## Continuous Integration

### GitHub Actions (Example)

```yaml
name: Build Extension

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '16'
      - run: npm install -g vsce
      - run: vsce package
      - uses: actions/upload-artifact@v2
        with:
          name: extension
          path: '*.vsix'
```

## Version Management

### Update Version

```bash
# Edit package.json:
"version": "1.0.1"

# Rebuild
vsce package

# Commit
git add package.json
git commit -m "Bump version to 1.0.1"
git tag v1.0.1
git push origin main --tags
```

## Dependencies

Currently, the extension has **zero dependencies** (other than VSCode API).

To add dependencies:
```bash
npm init  # If package-lock.json doesn't exist
npm install <package-name>
vsce package  # Will include node_modules
```

## File Size Optimization

Current size: ~50KB (uncompressed)

To reduce:
1. Already minimal - no dependencies
2. Already excluded test files via `.vscodeignore`
3. Code is not minified (for readability/audit)

## Security Considerations

### Before Publishing

1. ✅ Review all code for vulnerabilities
2. ✅ Test with malicious samples
3. ✅ Verify no external network calls
4. ✅ Check no telemetry/tracking
5. ✅ Audit dependencies (none currently)
6. ✅ Test on Windows/macOS/Linux

### Code Signing (Optional)

```bash
# For enterprise distribution
# Sign the .vsix file with company certificate
```

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/malware-detector/issues)
- Docs: [README.md](./README.md)
- Quick Start: [QUICK_START.md](./QUICK_START.md)

---

**🛡️ Build completed! Your extension is ready to protect developers from invisible threats.**

