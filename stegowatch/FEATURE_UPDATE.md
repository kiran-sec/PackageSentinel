# 🆕 Feature Update: Extension Scanner

## What's New

Your **Suspicious Code Detector** extension can now scan **all installed VSCode extensions** for malicious code patterns!

## Why This Matters

VSCode extensions have full system access and can:
- Read/modify your files
- Steal credentials and tokens
- Execute arbitrary commands
- Send data to external servers

The `ellacrity.recoil` malware (1000+ downloads) used invisible Unicode characters to hide a GitHub token stealer in a VSCode extension. This new feature would have caught it immediately.

## New Commands

### 1. Scan All Installed Extensions
```
Cmd+Shift+P → "Security: Scan All Installed Extensions"
```
- Scans all non-built-in extensions
- Shows progress notification
- Opens detailed report if issues found

### 2. View Extension Scan Report
```
Cmd+Shift+P → "Security: Show Extension Scan Report"
```
- View results from last scan
- Detailed breakdown by extension
- Line-by-line findings with severity levels

## How to Use

### Quick Start

1. **Open Command Palette** (Cmd+Shift+P)
2. Type: `scan extensions`
3. Select: **"Security: Scan All Installed Extensions"**
4. Wait for scan to complete (~5-30 seconds)
5. Review report if suspicious patterns found

### What It Scans

For each extension, checks all `.js` and `.node` files for:

✓ Unicode steganography (invisible characters hiding payloads)  
✓ Dynamic code execution (`eval(atob(...))`, `new Function(...)`)  
✓ Zero-width characters and invisible Unicode  
✓ Bidirectional text overrides (Trojan Source attacks)  
✓ Excessive indentation hiding code  
✓ Homoglyph attacks (lookalike characters)  

## Example Output

If suspicious patterns are found:

```
⚠️ Found potential issues in 2 extension(s). Scanned 47 extensions in 8.3s.
[View Report] [Dismiss]
```

### Report Shows:

```
Extension Security Scan Results
Found potential issues in 2 extension(s) - 5 total findings

─────────────────────────────────────────────────
Example Extension
suspicious-publisher.bad-extension

by suspicious-publisher | v1.0.0

3 potential issue(s) found | 1 critical

Files:
  extension/index.js
    Line 42: ⚠️ Dynamic code execution pattern detected
             Severity: CRITICAL
    
    Line 156: ⚠️ Invisible character detected: Zero Width Space
              Severity: MEDIUM

  extension/utils.js
    Line 89: ⚠️ Unusual indentation detected: 250 spaces
             Severity: MEDIUM
─────────────────────────────────────────────────
```

## What to Do If Issues Found

### 1. Assess Risk
- Check extension's reputation (downloads, ratings, publisher)
- Consider if patterns are expected for its functionality
- Look for verified/trusted publisher badges

### 2. Investigate
- Review the suspicious code lines
- Check the extension's GitHub repository
- Search for security reports: `"extension-name" vulnerability`

### 3. Take Action

**If Suspicious:**
- ⚠️ Uninstall immediately
- 🔒 Report to VSCode marketplace
- 🚨 Warn your team if used in organization

**If Legitimate (False Positive):**
- ✓ Document why it's safe
- ✓ Continue using with confidence

## Performance

- **Speed**: 5-30 seconds for typical setups
- **Files Scanned**: Up to 100 per extension
- **Memory**: Minimal - one file at a time
- **Excluded**: Skips `node_modules`, `test`, `.git`

## Real-World Protection

### Case Study: ellacrity.recoil

**What happened:**
- Malicious VSCode extension with 1000+ downloads
- Used 135 invisible Unicode Variation Selectors
- Hid token-stealing payload in plain sight
- Developers couldn't see it in their editor

**How our scanner would detect it:**
```
⚠️ Potential Unicode steganography detected: 135 invisible characters
Severity: CRITICAL
File: extension/index.js, Line 42
```

## Privacy & Security

- ✓ All scanning happens **locally** on your machine
- ✓ No code is sent to external servers
- ✓ No telemetry or data collection
- ✓ Open source - verify the code yourself

## Best Practices

### Personal Use
1. Scan after installing new extensions
2. Run monthly scans (extensions update frequently)
3. Scan before working on sensitive projects

### Teams
1. Create approved extension lists
2. Require scans before approval
3. Share reports with team members
4. Document false positives

## Test Files Included

Try the scanner with these test files:

1. **`test-chinese-false-positives.js`**
   - Pure legitimate Chinese code
   - Should have 0 detections

2. **`test-chinese-with-actual-issues.js`**
   - Mix of Chinese + actual threats
   - Should detect 4 suspicious patterns

3. **`test-multilingual.js`**
   - 10 languages (Chinese, Japanese, Korean, Arabic, etc.)
   - Should have 0 false positives

4. **`test-examples.js`**
   - Various obfuscation techniques
   - Demonstrates all detection types

## Configuration

Uses the same settings as file scanning:

```json
{
  "malwareDetector.detectUnicodeStego": true,
  "malwareDetector.detectSuspiciousEval": true,
  "malwareDetector.detectInvisibleChars": true,
  "malwareDetector.detectBidiOverride": true,
  "malwareDetector.detectHomoglyphs": true,
  "malwareDetector.detectExcessiveIndentation": true,
  "malwareDetector.minStegoSequence": 10,
  "malwareDetector.maxIndentation": 200
}
```

## Limitations

Cannot detect:
- ❌ Advanced encryption/packing
- ❌ Native binary payloads
- ❌ Time-delayed attacks
- ❌ Server-side malicious logic
- ❌ All possible obfuscation techniques

Always use common sense and verify extension trustworthiness!

## Documentation

Full guide: **`EXTENSION_SCANNER_GUIDE.md`**

## Try It Now!

1. Press **Cmd+Shift+P** (or Ctrl+Shift+P)
2. Type: `scan extensions`
3. Hit Enter
4. See your results in ~10 seconds!

---

**Stay secure! 🔒**

