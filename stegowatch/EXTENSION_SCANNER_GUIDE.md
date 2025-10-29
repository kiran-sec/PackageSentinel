# Extension Scanner Feature

## Overview

The Suspicious Code Detector now includes the ability to scan **all installed VSCode extensions** for suspicious code patterns. This feature was inspired by real-world malware like `ellacrity.recoil` that hide malicious payloads in extension files.

## Why Scan Extensions?

VSCode extensions have full access to your:
- **Files and code**: Can read, modify, or delete any file in your workspace
- **Network**: Can send data to external servers
- **System commands**: Can execute arbitrary commands on your machine
- **Credentials**: Can potentially access tokens, API keys, and passwords

Malicious extensions can:
- Steal your source code
- Exfiltrate GitHub tokens or API keys
- Install backdoors or cryptominers
- Modify your code silently
- Track your development activities

## How to Use

### Option 1: Manual Scan

1. Open **Command Palette** (Cmd+Shift+P / Ctrl+Shift+P)
2. Type: `Security: Scan All Installed Extensions`
3. Wait for the scan to complete
4. Review the report if issues are found

### Option 2: View Previous Results

1. Open **Command Palette**
2. Type: `Security: Show Extension Scan Report`
3. View detailed findings

## What It Detects

The scanner checks all JavaScript files (`.js` and `.node`) in each extension for:

1. **Unicode Steganography**
   - Invisible Unicode Variation Selectors (U+FE00-U+FE0F)
   - Private Use Area characters (U+E000-U+F8FF)
   - Hidden payload techniques

2. **Dynamic Code Execution**
   - `eval(atob(...))` - Base64-encoded code execution
   - `new Function(atob(...))` - Dynamic function creation
   - `Buffer.from(..., 'base64').toString()` - Hidden payloads
   - `.then(eval)` - Promise-based code execution

3. **Invisible Characters**
   - Zero-width spaces (U+200B, U+200C, U+200D)
   - Byte Order Mark (U+FEFF)
   - Other invisible Unicode characters

4. **Code Obfuscation**
   - Bidirectional text overrides (Trojan Source attacks)
   - Homoglyph attacks (lookalike characters)
   - Excessive indentation to hide code

5. **Suspicious Patterns**
   - `child_process.exec()` with sensitive commands
   - Network requests to unusual domains
   - File system operations on sensitive paths

## Understanding Results

### Severity Levels

- **Critical**: Highly suspicious patterns (e.g., `eval(atob(...))`)
- **High**: Potentially dangerous code (e.g., command execution)
- **Medium**: Unusual but possibly legitimate patterns

### Report Format

The report shows:
- **Extension Name & ID**: Full identifier of the extension
- **Publisher**: Who created the extension
- **Version**: Current installed version
- **Files with Issues**: Which files contain suspicious patterns
- **Line Numbers**: Exact location of each finding
- **Detection Details**: What was found and why it's flagged

### Example Report

```
Extension Name: Example Extension
ID: publisher.example-extension
Publisher: publisher
Version: 1.2.3

Issues Found: 3 potential issue(s)
├─ 1 critical

Files:
├─ extension/index.js
│  ├─ Line 42: ⚠️ Dynamic code execution pattern detected: eval with base64 decoding
│  │  Severity: Critical
│  └─ Line 156: ⚠️ Invisible character detected: Zero Width Space
│     Severity: Medium
└─ extension/lib/utils.js
   └─ Line 89: ⚠️ Unusual indentation detected: 250 spaces
      Severity: Medium
```

## What to Do If Issues Are Found

### Step 1: Assess the Risk

- **Check Extension Reputation**
  - How many downloads/installs?
  - Who is the publisher?
  - Is it verified or from a known company?
  - Read reviews and ratings

- **Consider the Context**
  - Does the extension need to run code dynamically? (e.g., code formatters, linters)
  - Are the patterns expected for its functionality?
  - Is this a development tool that legitimately uses eval?

### Step 2: Investigate Further

- **Read the Source Code**
  - Click on the file path in the report
  - Navigate to the extension directory
  - Review the suspicious lines in context

- **Check the Extension's Repository**
  - Look for the source code on GitHub
  - Compare installed code with repository
  - Check for recent issues or security reports

- **Search for Security Reports**
  - Google: `"extension-name" vulnerability`
  - Check VSCode marketplace reviews
  - Look for security advisories

### Step 3: Take Action

**If Suspicious:**
- ⚠️ **Uninstall immediately** if you don't recognize it
- 🔒 **Disable the extension** while investigating
- 📝 **Report to VSCode** via the marketplace
- 🚨 **Warn others** by leaving a review

**If Legitimate:**
- ✓ The patterns may be false positives
- ✓ Document why it's safe (for future reference)
- ✓ Consider reaching out to the developer to improve their code

## Performance Notes

- **Scan Time**: Typically 5-30 seconds depending on number of extensions
- **File Limit**: Scans up to 100 files per extension to prevent slowdowns
- **Excluded Directories**: Skips `node_modules`, `test`, `tests`, `.git`
- **Memory Usage**: Minimal - files are scanned one at a time

## Limitations

This scanner cannot:
- **Detect all malware**: Only finds known suspicious patterns
- **Analyze binary files**: `.node` files are checked if readable as text
- **Guarantee safety**: Clean scans don't mean 100% safe
- **Replace human judgment**: Always use common sense

## Real-World Example: ellacrity.recoil

This scanner was inspired by the discovery of the `ellacrity.recoil` malware:

- **Attack Vector**: VSCode extension with 1000+ downloads
- **Technique**: Used Unicode Variation Selectors (U+FE00-U+FE0F) to hide payload
- **Target**: Stole GitHub tokens and session data
- **Detection**: Would be caught by "Unicode Steganography" detector

### The Hidden Payload

```javascript
// What developers saw (appeared blank):
const data = '';

// What was actually there (invisible Unicode characters):
const data = '󠀀󠀁󠀂󠀃󠀄...'; // 135+ invisible variation selectors encoding malicious code
```

Our scanner would flag this as:
```
⚠️ Potential Unicode steganography detected: 135 invisible characters in sequence
Severity: Critical
```

## Recommended Workflow

### For Personal Development

1. **Scan after installing new extensions**
   ```
   Install Extension → Run "Security: Scan All Installed Extensions"
   ```

2. **Periodic scans** (monthly)
   - Extensions update regularly
   - New vulnerabilities may be discovered

3. **Before sensitive work**
   - Scan before working on confidential projects
   - Especially before handling credentials or API keys

### For Teams

1. **Create an approved extensions list**
2. **Require scans before adding to approved list**
3. **Share scan reports with team**
4. **Document false positives** to avoid confusion

## Configuration

Currently, extension scanning uses the same detection settings as file scanning. You can adjust thresholds in VSCode settings:

```json
{
  "malwareDetector.detectUnicodeStego": true,
  "malwareDetector.detectSuspiciousEval": true,
  "malwareDetector.minStegoSequence": 10,
  "malwareDetector.maxIndentation": 200
}
```

## Troubleshooting

### "Cannot read extension from..."
- **Cause**: Extension files are locked or inaccessible
- **Solution**: Restart VSCode or scan individual extensions

### "No issues found" but extension seems suspicious
- **Cause**: Advanced obfuscation or encryption
- **Solution**: Manually review the code or consult a security expert

### False positives on legitimate extensions
- **Cause**: Some tools legitimately use eval or dynamic code
- **Solution**: Review the code context and verify it's expected behavior

## Privacy Note

All scanning happens **locally on your machine**. No extension code or scan results are sent to external servers. The scanner only reads files in your installed extensions directory.

## Feedback and Improvements

Found a malicious extension? Have ideas for better detection?
- Report issues via the extension's repository
- Contribute detection patterns
- Share your findings with the community

---

**Stay safe! Regular extension audits are an important part of development security.**

