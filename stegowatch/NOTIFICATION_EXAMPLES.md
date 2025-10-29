# Notification Examples

This document shows what security notifications look like with the detailed findings display.

---

## 🔔 Automatic Scan Notifications

### Example 1: Single Extension with Few Issues

When installing an extension with 3 findings:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠️ Security Alert: "suspicious-ext" (1 critical)                    │
│                                                                     │
│ • index.js:42 - ⚠️ Dynamic code execution pattern detected: eval   │
│   with base64 decoding (eval(atob(...)))                           │
│ • utils.js:89 - ⚠️ Invisible character detected: Zero Width Space  │
│ • main.js:156 - ⚠️ Unusual indentation detected: 250 spaces        │
│                                                                     │
│ [View Full Report]  [Uninstall]  [Dismiss]                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Example 2: Extension with Many Issues

When installing an extension with 15 findings (shows first 10):

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠️ Security Alert: "malicious-ext" (5 critical)                     │
│                                                                     │
│ • index.js:42 - ⚠️ Dynamic code execution pattern detected: eval   │
│   with base64 decoding                                             │
│ • index.js:87 - ⚠️ Potential Unicode steganography detected: 45    │
│   invisible characters                                             │
│ • loader.js:23 - ⚠️ Dynamic code execution pattern detected:       │
│   Function with base64 decoding                                    │
│ • utils.js:156 - ⚠️ Invisible character detected: Zero Width Space │
│ • main.js:89 - ⚠️ Command execution pattern detected:              │
│   child_process.exec()                                             │
│ • core.js:234 - ⚠️ Bidirectional text control character detected   │
│ • helper.js:67 - ⚠️ Unusual indentation detected: 350 spaces       │
│ • api.js:112 - ⚠️ Dynamic code execution pattern detected: promise │
│   chain with eval                                                  │
│ • worker.js:45 - ⚠️ Invisible character detected: Zero Width Joiner│
│ • config.js:78 - ⚠️ Non-ASCII character in identifier: 'а'         │
│   resembles 'a'                                                    │
│ ...and 5 more                                                      │
│                                                                     │
│ [View Full Report]  [Uninstall]  [Dismiss]                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Example 3: Clean Extension

When installing a safe extension:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ✓ Security Scan: New extension "prettier" appears clean.           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Manual Scan Notifications

### Example 1: Full Workspace Scan with Issues

When running `Security: Scan All Installed Extensions`:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠️ Found issues in 2 extension(s) (8.3s)                            │
│                                                                     │
│ • suspicious-ext/index.js:42 - ⚠️ Dynamic code execution pattern   │
│   detected: eval with base64 decoding                              │
│ • suspicious-ext/utils.js:89 - ⚠️ Invisible character detected:    │
│   Zero Width Space                                                 │
│ • another-ext/main.js:23 - ⚠️ Command execution pattern detected:  │
│   child_process.exec()                                             │
│ • another-ext/loader.js:156 - ⚠️ Potential Unicode steganography   │
│   detected: 135 invisible characters                               │
│ • another-ext/core.js:67 - ⚠️ Unusual indentation detected: 300    │
│   spaces                                                           │
│                                                                     │
│ [View Full Report]  [Dismiss]                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Example 2: Full Workspace Scan - All Clean

```
┌─────────────────────────────────────────────────────────────────────┐
│ ✓ Security Scan Complete: All 47 extensions appear clean (12.5s)   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📝 Notification Format Details

### Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│ [Icon] [Title with extension name] [(X critical)]                  │
│                                                                     │
│ • [filename]:[line] - [message]                                    │
│ • [filename]:[line] - [message]                                    │
│ • [filename]:[line] - [message]                                    │
│ ...                                                                │
│ ...and X more (if >10 findings)                                    │
│                                                                     │
│ [Action Buttons]                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Components

**Title:**
- `⚠️ Security Alert: "ext-name"` - Warning for new extension
- `⚠️ Found issues in X extension(s)` - Manual scan result
- `✓ Security Scan` - Clean results

**Critical Count:**
- Shows `(X critical)` if any Critical severity findings
- Omitted if no Critical findings

**Findings List:**
- Format: `• filename:line - message`
- Shows first 10 findings
- Sorted by file, then by line number
- Truncates long messages to fit

**More Indicator:**
- Shows `...and X more` if >10 total findings
- Clicking "View Full Report" shows all

**Action Buttons:**
- `View Full Report` - Opens HTML report with all details
- `Uninstall` - Removes the extension (auto-scan only)
- `Dismiss` - Closes notification

---

## 🎯 Real-World Examples

### ellacrity.recoil Malware Detection

If the malicious `ellacrity.recoil` extension were installed:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠️ Security Alert: "recoil" (1 critical)                            │
│                                                                     │
│ • index.js:42 - ⚠️ Potential Unicode steganography detected: 135   │
│   invisible characters in sequence                                 │
│                                                                     │
│ [View Full Report]  [Uninstall]  [Dismiss]                         │
└─────────────────────────────────────────────────────────────────────┘
```

**Clicking "View Full Report" would show:**
- Full file path
- Exact line number
- Complete detection message
- Severity level (CRITICAL)
- Recommendation to uninstall

### Common False Positive - Prettier

Safe extension with no issues:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ✓ Security Scan: New extension "prettier" appears clean.           │
└─────────────────────────────────────────────────────────────────────┘
```

### Code Obfuscator (Legitimate but Flagged)

Legitimate obfuscator may trigger warnings:

```
┌─────────────────────────────────────────────────────────────────────┐
│ ⚠️ Security Alert: "javascript-obfuscator"                          │
│                                                                     │
│ • index.js:89 - ⚠️ Dynamic code execution pattern detected: eval   │
│   with base64 decoding                                             │
│ • utils.js:234 - ⚠️ Unusual indentation detected: 400 spaces       │
│ • core.js:567 - ⚠️ Dynamic code execution pattern detected:        │
│   Function with base64 decoding                                    │
│                                                                     │
│ [View Full Report]  [Uninstall]  [Dismiss]                         │
└─────────────────────────────────────────────────────────────────────┘
```

**Note:** This is a **false positive** - the extension's purpose is to obfuscate code, so it legitimately uses these patterns. Safe to dismiss.

---

## 💡 How to Read Notifications

### Severity Indicators

**Critical Issues (Action Required):**
```
• index.js:42 - ⚠️ Potential Unicode steganography detected: 135 invisible characters
• loader.js:23 - ⚠️ Dynamic code execution pattern detected: eval(atob(...))
• main.js:67 - ⚠️ Bidirectional text control character detected
```

**High Issues (Review Needed):**
```
• utils.js:89 - ⚠️ Command execution pattern detected: child_process.exec()
• api.js:156 - ⚠️ Suspicious network request to unusual domain
```

**Medium Issues (Likely Safe):**
```
• config.js:234 - ⚠️ Unusual indentation detected: 250 spaces
• helper.js:45 - ⚠️ Invisible character detected: Zero Width Space
• worker.js:78 - ⚠️ Non-ASCII character in identifier: 'а' resembles 'a'
```

### File Naming

**Simple filename:**
- `index.js:42` - Main extension file
- `utils.js:89` - Utility file
- `main.js:23` - Entry point

**Multi-extension scan:**
- `suspicious-ext/index.js:42` - Shows extension name
- `another-ext/main.js:67` - Helps identify which extension

---

## ⚙️ Configuration

### Adjust Detection Sensitivity

To reduce false positives, adjust in VSCode Settings:

```json
{
  "malwareDetector.minStegoSequence": 20,  // Default: 10
  "malwareDetector.maxIndentation": 400,   // Default: 200
  "malwareDetector.detectHomoglyphs": false // If too many false positives
}
```

### Disable Auto-Scan (Not Recommended)

```json
{
  "malwareDetector.autoScanNewExtensions": false
}
```

When disabled, you'll get a prompt instead:
```
┌─────────────────────────────────────────────────────────────────────┐
│ New extension(s) installed: prettier. Scan for security issues?    │
│                                                                     │
│ [Scan Now]  [Skip]                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Privacy Note

All notifications are generated **locally**:
- ✅ No data sent to external servers
- ✅ No telemetry or tracking
- ✅ Findings stay on your machine
- ✅ Full transparency

---

## 📚 Additional Resources

- **AUTO_SCAN_GUIDE.md** - Complete guide to automatic scanning
- **EXTENSION_SCANNER_GUIDE.md** - Manual scanning reference
- **WHATS_NEW.md** - Feature overview

---

**Stay informed, stay secure!** 🛡️

