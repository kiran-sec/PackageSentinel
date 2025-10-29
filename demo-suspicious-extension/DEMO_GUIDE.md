# Demo Extension - Complete Testing Guide

This guide shows you how to use the demo extension to test and demonstrate the Suspicious Code Detector.

---

## 📦 What You Have

**File:** `demo-suspicious-extension-0.1.0.vsix`

**Location:** `/Users/kraj/Desktop/Company-code/Static Analysis/demo-suspicious-extension/`

**Size:** ~4.5 KB

**Patterns:** 9 intentionally suspicious code patterns

---

## 🎯 Quick Demo (5 Minutes)

### Step 1: Install the Demo Extension

```bash
cd "/Users/kraj/Desktop/Company-code/Static Analysis/demo-suspicious-extension"

code --install-extension demo-suspicious-extension-0.1.0.vsix
```

### Step 2: Wait for Auto-Scan

If you have the Suspicious Code Detector installed with auto-scan enabled:
- **Wait 5-10 seconds**
- You should see a security alert notification!

### Step 3: View Results

The notification will show:
```
⚠️ Security Alert: "demo-suspicious-extension" (4 critical)

• Dynamic code execution [🔴 Critical] - extension.js:23
• Dynamic code execution [🔴 Critical] - extension.js:42
• Dynamic code execution [🔴 Critical] - extension.js:45
• Unicode steganography [🔴 Critical] - extension.js:38
• Command execution [🟠 High] - extension.js:27
• Invisible character [🟡 Medium] - extension.js:31
• Excessive indentation [🟡 Medium] - extension.js:35
...and 2 more

[View Full Report] [Uninstall] [Dismiss]
```

### Step 4: View Full Report

Click **"View Full Report"** to see:
- All findings with clickable line numbers
- Severity badges
- Full detection messages
- Organized by file

### Step 5: Inspect the Code

Click on any `📍 Line XX` link to jump to the suspicious code!

---

## 🔍 Manual Scan Demo

If auto-scan didn't trigger or you want to scan manually:

### Option 1: Scan All Extensions

```
1. Cmd+Shift+P (or Ctrl+Shift+P)
2. Type: "Security: Scan All Installed Extensions"
3. Press Enter
4. Wait ~5-10 seconds
5. View the report
```

### Option 2: Scan the Extension File Directly

```
1. Open the extension.js file:
   File → Open → Navigate to:
   /Users/kraj/Desktop/Company-code/Static Analysis/demo-suspicious-extension/extension.js

2. Scan it:
   Cmd+Shift+P → "Security: Scan Current File"

3. View findings in Problems panel (Cmd+Shift+M)
```

---

## 📊 Expected Results

### Summary
```
⚠️ Found issues in 1 extension(s)

• Dynamic code execution [🔴 Critical] - demo-suspicious-extension/extension.js:23
• Dynamic code execution [🔴 Critical] - demo-suspicious-extension/extension.js:42
• Dynamic code execution [🔴 Critical] - demo-suspicious-extension/extension.js:45
• Unicode steganography [🔴 Critical] - demo-suspicious-extension/extension.js:38
• Command execution [🟠 High] - demo-suspicious-extension/extension.js:27
• Invisible character [🟡 Medium] - demo-suspicious-extension/extension.js:31
• Excessive indentation [🟡 Medium] - demo-suspicious-extension/extension.js:35
• Homoglyph [🟡 Medium] - demo-suspicious-extension/extension.js:53
```

### Breakdown by Severity

**Critical (4 findings):**
1. Line 23: `eval(atob('...'))` - Dynamic code execution
2. Line 38: Unicode Variation Selectors - Steganography
3. Line 42: `new Function(atob('...'))` - Dynamic function
4. Line 45: `.then(eval)` - Promise chain execution

**High (1 finding):**
1. Line 27: `exec('...')` - Command execution

**Medium (3 findings):**
1. Line 31: Zero-width space in variable name
2. Line 35: 300+ spaces indentation
3. Line 53: Cyrillic 'е' in identifier

---

## 🎪 Live Demo Script

### For Presentations

**Setup (Before Demo):**
```bash
# Make sure scanner is installed
cd "/Users/kraj/Desktop/Company-code/Static Analysis/kr_vscode"
code --install-extension suspicious-code-detector-1.0.0.vsix

# Restart VSCode
# Cmd+Q → Reopen
```

**Demo Script:**

1. **Introduction** (1 min)
   - "I'm going to show you a real-world malware detection in action"
   - "This extension mimics patterns from actual malware like ellacrity.recoil"

2. **Installation** (30 sec)
   ```bash
   code --install-extension demo-suspicious-extension-0.1.0.vsix
   ```
   - "Watch what happens when we install this extension..."

3. **Detection** (30 sec)
   - Wait for the alert to pop up
   - "Our scanner detected it immediately!"
   - Point out the severity levels

4. **Investigation** (2 min)
   - Click "View Full Report"
   - Show the findings list
   - Click on a line number to jump to code
   - Point out specific patterns:
     - Unicode steganography
     - Dynamic code execution
     - Command execution

5. **Comparison** (1 min)
   - "This is exactly what ellacrity.recoil did"
   - "It had 1000+ downloads before being caught"
   - "Our scanner would have caught it on day 1"

6. **Cleanup** (30 sec)
   - Click "Uninstall" in the report
   - Or: `code --uninstall-extension demo-publisher.demo-suspicious-extension`

---

## 🧪 Testing Scenarios

### Scenario 1: Auto-Scan on Install
**Purpose:** Test automatic scanning of new extensions

**Steps:**
1. Ensure auto-scan is enabled (it's on by default)
2. Install the demo extension
3. Watch for immediate security alert
4. Verify all findings are detected

**Expected:** Alert appears within 5-10 seconds

### Scenario 2: Manual Extension Scan
**Purpose:** Test on-demand scanning

**Steps:**
1. Install the demo extension (disable auto-scan first)
2. Cmd+Shift+P → "Scan All Installed Extensions"
3. View the report

**Expected:** Extension appears in scan results with all findings

### Scenario 3: File Scanning
**Purpose:** Test direct file analysis

**Steps:**
1. Open `extension.js` in editor
2. Cmd+Shift+P → "Scan Current File"
3. Check Problems panel (Cmd+Shift+M)

**Expected:** All 8-9 issues appear in Problems panel

### Scenario 4: Clickable Links
**Purpose:** Test code navigation

**Steps:**
1. Scan the extension (any method)
2. Open the HTML report
3. Click on `📍 Line XX` links
4. Verify code opens at correct line

**Expected:** Each click opens file at exact line

### Scenario 5: False Positive Check
**Purpose:** Verify Chinese/multilingual code isn't flagged

**Steps:**
1. Install demo extension (has only English code)
2. Compare with `test-chinese-false-positives.js`
3. Verify Chinese comments aren't flagged as homoglyphs

**Expected:** Only actual threats flagged, not legitimate Chinese text

---

## 📝 Presentation Talking Points

### Why This Matters

**Real-World Context:**
- "VSCode extensions have full system access"
- "ellacrity.recoil malware had 1000+ downloads"
- "It stole GitHub tokens from developers"
- "It was invisible in most IDEs"

### What We Detect

**Technical Details:**
- "Unicode Variation Selectors - invisible characters hiding payloads"
- "Dynamic code execution - eval with base64 encoding"
- "Command execution - running system commands"
- "Trojan Source attacks - bidirectional text manipulation"

### How It Works

**Detection Methods:**
- "Pattern matching for known malicious patterns"
- "Statistical analysis of character frequencies"
- "Context-aware to reduce false positives"
- "Real-time scanning with instant alerts"

---

## 🔧 Troubleshooting

### Alert Doesn't Appear

**Check:**
1. Is auto-scan enabled?
   - Settings → search `autoScanNewExtensions`
   - Should be `true`

2. Is the scanner extension active?
   - Check Extensions panel
   - "Suspicious Code Detector" should show "Enabled"

3. Try manual scan:
   - Cmd+Shift+P → "Scan All Installed Extensions"

### Report Shows No Findings

**Solutions:**
1. Open Developer Console (Help → Toggle Developer Tools)
2. Look for `[Security Scanner]` messages
3. Check if extension.js file is readable
4. Try reinstalling demo extension

### Links Don't Work

**Fix:**
1. Make sure you're in the HTML report (not notification)
2. Click directly on `📍 Line XX` text
3. Check file hasn't been deleted

---

## 🗑️ Cleanup

### Uninstall Demo Extension

**Via Command:**
```bash
code --uninstall-extension demo-publisher.demo-suspicious-extension
```

**Via VSCode:**
1. Cmd+Shift+X (Extensions panel)
2. Search: "demo suspicious"
3. Click gear icon → Uninstall

**Via Report:**
1. View Extension Scan Report
2. Click "Uninstall" button
3. Confirm

### Verify Removal

```bash
code --list-extensions | grep demo
```

Should return nothing.

---

## 📊 Benchmark Results

Use this extension to benchmark your scanner:

**Accuracy Metrics:**
- **True Positives:** Should detect 8-9 findings
- **False Positives:** Should be 0 (all patterns are intentionally suspicious)
- **Detection Time:** Should be < 10 seconds
- **Critical Detection Rate:** Should be 100% (all 4 critical patterns caught)

**Performance:**
- Scan time for this extension: ~0.5 seconds
- Memory usage: Minimal (<10MB)
- No false negatives expected

---

## 🎓 Educational Use

### For Training

This extension is perfect for:

1. **Security Training Sessions**
   - Show real malware patterns
   - Demonstrate detection techniques
   - Practice incident response

2. **Tool Demonstrations**
   - Showcase scanner capabilities
   - Compare with other tools
   - Validate detection accuracy

3. **Academic Research**
   - Study malware patterns
   - Test detection algorithms
   - Benchmark tools

4. **Development Testing**
   - Test scanner updates
   - Verify new detection rules
   - Regression testing

---

## 🔐 Safety Notes

### Is It Safe?

**Yes!** Here's why:

✅ **No Network Requests**
- Doesn't connect to any servers
- Doesn't send data anywhere
- Completely offline

✅ **No File Access**
- Doesn't read sensitive files
- Doesn't write any files
- No persistence mechanisms

✅ **Harmless Execution**
- `eval()` calls only log messages
- `exec()` only echoes text
- No system modifications

✅ **Transparent Code**
- All code is visible
- Well-commented
- Easy to audit

### What It Actually Does

**Functionality:** Just shows "Hello World" message

**That's it!** Everything else is for detection testing.

---

## 📚 Related Files

**In demo-suspicious-extension directory:**
- `package.json` - Extension manifest
- `extension.js` - Main code with suspicious patterns
- `README.md` - Overview
- `DEMO_GUIDE.md` - This file
- `demo-suspicious-extension-0.1.0.vsix` - Packaged extension

**Your scanner:**
- `suspicious-code-detector-1.0.0.vsix` - The security scanner

---

## 🎯 Quick Commands Reference

```bash
# Install demo extension
code --install-extension demo-suspicious-extension-0.1.0.vsix

# Scan extensions
Cmd+Shift+P → "Security: Scan All Installed Extensions"

# View report
Cmd+Shift+P → "Security: Show Extension Scan Report"

# Uninstall demo
code --uninstall-extension demo-publisher.demo-suspicious-extension

# List installed extensions
code --list-extensions
```

---

**Happy testing! This demo extension makes security demonstrations easy and effective.** 🚀

