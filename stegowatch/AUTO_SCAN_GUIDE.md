# 🛡️ Automatic Extension Scanning

## Overview

Your Suspicious Code Detector now **automatically scans new extensions** when they are installed - providing real-time protection against malicious VSCode extensions!

## 🔄 How It Works

### Automatic Detection

When you install a new extension:

1. **Detection**: The extension immediately detects the new installation
2. **Scan**: Automatically scans all JavaScript files in the new extension
3. **Alert**: Shows a security alert if suspicious patterns are found
4. **Action**: Offers options to view details or uninstall immediately

### Real-Time Protection

```
Install Extension
    ↓
Automatic Scan (5-10 seconds)
    ↓
┌─────────────────────────────┐
│  No Issues Found            │
│  ✓ Extension appears clean  │
└─────────────────────────────┘

OR

┌─────────────────────────────────────────┐
│  ⚠️ Security Alert!                     │
│  Contains 3 issues (1 critical)        │
│  [View Details] [Uninstall] [Dismiss]  │
└─────────────────────────────────────────┘
```

## 🚨 Security Alerts

### When Issues Are Found

You'll see an alert with:
- **Extension name**: What was just installed
- **Issue count**: Total number of suspicious patterns
- **Critical count**: Number of high-risk issues
- **Actions**:
  - **View Details**: Opens full security report
  - **Uninstall**: Immediately removes the extension
  - **Dismiss**: Ignore the warning (not recommended)

### Example Alert

```
⚠️ Security Alert: Newly installed extension "suspicious-ext" 
contains 5 potential issue(s) (2 critical).

[View Details]  [Uninstall]  [Dismiss]
```

## 📋 Security Report

Click **"View Details"** to see:

```
Extension Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Suspicious Extension
publisher.suspicious-ext

by suspicious-publisher | v1.0.0

5 potential issue(s) found | 2 critical

Files:
  extension/index.js
    Line 42: ⚠️ Dynamic code execution: eval(atob(...))
             Severity: CRITICAL
    
    Line 89: ⚠️ Unicode steganography: 45 invisible characters
             Severity: CRITICAL
    
    Line 156: ⚠️ Invisible character: Zero Width Space
              Severity: MEDIUM

  extension/utils.js
    Line 23: ⚠️ Command execution: child_process.exec()
             Severity: HIGH
    
    Line 67: ⚠️ Excessive indentation: 350 spaces
             Severity: MEDIUM
```

## ⚙️ Configuration

### Enable/Disable Auto-Scan

By default, auto-scan is **enabled**. To change:

1. Open **VSCode Settings** (Cmd+, or Ctrl+,)
2. Search: `autoScanNewExtensions`
3. Toggle: **"Auto Scan New Extensions"**

**Recommended: Keep it enabled** for maximum protection!

### If Auto-Scan is Disabled

When you install a new extension, you'll get a prompt:

```
New extension(s) installed: suspicious-ext. Scan for security issues?

[Scan Now]  [Skip]
```

You can choose to scan manually or skip.

## 🎯 What Gets Scanned

### Automatically Scanned

- ✅ All newly installed extensions
- ✅ JavaScript files (`.js`)
- ✅ Native modules (`.node` if readable)
- ✅ Up to 100 files per extension

### Not Scanned

- ❌ VSCode built-in extensions (trusted)
- ❌ Extensions installed before activation
- ❌ Binary files (`.node` native modules)
- ❌ `node_modules` directories
- ❌ `test` and `tests` directories

## 🔍 Detection Capabilities

Every new extension is checked for:

### 1. **Unicode Steganography** (Critical)
Hidden payloads using invisible characters
- Example: `ellacrity.recoil` malware used 135 invisible chars

### 2. **Dynamic Code Execution** (Critical)
Obfuscated malicious code execution
- `eval(atob(...))` - Base64 + eval
- `new Function(atob(...))` - Dynamic functions
- `.then(eval)` - Promise-based execution

### 3. **Invisible Characters** (Medium-High)
Hidden manipulation attempts
- Zero-width spaces (U+200B)
- Zero-width joiners/non-joiners
- Byte Order Marks

### 4. **Trojan Source Attacks** (Critical)
Bidirectional text overrides
- Right-to-Left Override (RLO)
- Left-to-Right Override (LRO)

### 5. **Code Obfuscation** (Medium)
Attempts to hide code
- Excessive indentation (>200 spaces)
- Homoglyph attacks (lookalike chars)

### 6. **Suspicious System Calls** (High)
Potentially dangerous operations
- `child_process.exec()`
- `fs` operations on sensitive paths
- Network requests to unusual domains

## 💡 Response Actions

### If Alert Shows "Critical" Issues

🚨 **High Risk** - Consider uninstalling immediately

1. Click **"View Details"**
2. Review the suspicious code
3. If unsure, click **"Uninstall"**
4. Report to VSCode marketplace

**Example Critical Patterns:**
- `eval(atob(...))`
- Unicode steganography sequences
- Trojan Source attacks

### If Alert Shows "High" Issues

⚠️ **Medium Risk** - Investigate before deciding

1. Click **"View Details"**
2. Check if patterns are legitimate
3. Research the extension's reputation
4. Review publisher credibility

**Example High Patterns:**
- Command execution
- File system operations
- Network requests

### If Alert Shows "Medium" Issues Only

⚡ **Low Risk** - Likely false positives

1. Review the details
2. Consider the extension's purpose
3. Probably safe if from trusted publisher

**Example Medium Patterns:**
- Excessive indentation
- Homoglyph characters
- Single invisible characters

## 🔐 Best Practices

### Before Installing

1. **Check reputation**: Downloads, ratings, reviews
2. **Verify publisher**: Known company or individual?
3. **Read permissions**: What access does it need?
4. **Review source**: Is code on GitHub?

### After Auto-Scan Alert

1. **Don't panic**: Some patterns may be legitimate
2. **Review context**: What does the extension do?
3. **Check community**: Search for security reports
4. **When in doubt, uninstall**: Better safe than sorry

### For Teams

1. **Enable auto-scan** on all developer machines
2. **Create approved list** of safe extensions
3. **Share findings** when suspicious patterns detected
4. **Document false positives** to reduce noise

## 📊 Tracking

### What Gets Tracked

- List of currently installed extensions (IDs only)
- Scan results for recently installed extensions
- No code or personal data is stored

### Privacy

- ✅ All scanning happens locally
- ✅ No data sent to external servers
- ✅ No telemetry or analytics
- ✅ Open source - verify yourself

### Logs

Check the console for scan activity:
1. Help → Toggle Developer Tools
2. Console tab
3. Look for `[Security Scanner]` messages

Example logs:
```
[Security Scanner] Tracking 47 extensions for changes
[Security Scanner] Detected 1 new extension(s): publisher.new-ext
[Security Scanner] Auto-scanning new extension: publisher.new-ext
[Security Scanner] Found 3 detections
```

## 🧪 Testing

### Test the Auto-Scan Feature

You can test by:

1. **Installing a test extension** (any extension)
2. **Wait for scan** (~5-10 seconds)
3. **Check notification** for results

### Expected Behavior

**Clean Extension:**
```
Security Scan: New extension "example" appears clean.
```

**Suspicious Extension:**
```
⚠️ Security Alert: Newly installed extension "example" 
contains X issue(s).
```

## 🛠️ Troubleshooting

### "No notification appears"

**Possible causes:**
- Notifications are disabled in VSCode
- Auto-scan setting is off
- Extension failed to load

**Solutions:**
1. Check VSCode notification settings
2. Verify: Settings → `autoScanNewExtensions` = true
3. Check Developer Console for errors

### "False positives on legitimate extensions"

**This is normal!** Some legitimate tools use patterns that look suspicious:

- **Code formatters/linters**: May use dynamic code
- **Obfuscators**: Intentionally obfuscate
- **Minifiers**: Compress code aggressively

**What to do:**
1. Review the code context
2. Check extension reputation
3. If safe, click "Dismiss"

### "Scan takes too long"

**Normal behavior:**
- Small extensions: 2-5 seconds
- Large extensions: 10-30 seconds

**If longer:**
- Extension has many files
- System is under load
- Check console for errors

## 🎓 Real-World Example

### Case: ellacrity.recoil Malware

**Attack Vector:**
- Published to VSCode marketplace
- 1000+ downloads before detection
- Used Unicode Variation Selectors to hide payload

**How Our Auto-Scan Would Detect:**

```
⚠️ Security Alert: Newly installed extension "recoil" 
contains 1 potential issue(s) (1 critical).

[View Details]
↓
Extension Security Scan Results

ellacrity.recoil
by ellacrity | v0.7.4

1 potential issue found | 1 critical

Files:
  extension/index.js
    Line 42: ⚠️ Potential Unicode steganography: 135 invisible characters
             Severity: CRITICAL
             
Note: This pattern matches the technique used in known malware.
Consider uninstalling immediately.
```

**Result:** Attack prevented before any damage!

## 📚 Additional Resources

- **Manual Scan**: Use `Security: Scan All Installed Extensions` to scan existing extensions
- **View Report**: Use `Security: Show Extension Scan Report` to review past scans
- **Full Guide**: See `EXTENSION_SCANNER_GUIDE.md` for complete documentation

## ⚡ Quick Reference

| Action | How |
|--------|-----|
| Enable auto-scan | Settings → `autoScanNewExtensions` = true |
| Disable auto-scan | Settings → `autoScanNewExtensions` = false |
| Manual scan all | Cmd+Shift+P → "Scan All Installed Extensions" |
| View last report | Cmd+Shift+P → "Show Extension Scan Report" |
| Check logs | Help → Toggle Developer Tools → Console |

## 🔒 Security Tip

**Always enable auto-scan!** It's your first line of defense against malicious VSCode extensions. The few seconds of scan time could save you from:

- 🚫 Data theft
- 🚫 Code manipulation
- 🚫 Credential stealing
- 🚫 System compromise

---

**Stay protected! Your code, your data, your security.** 🛡️

