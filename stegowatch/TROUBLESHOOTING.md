# Troubleshooting Guide

Common issues and how to fix them.

---

## 🔴 Report Not Updating with New Changes

### Problem
You made changes to your code but the security report still shows old findings.

### Symptoms
- Edit code but warnings don't disappear
- Fix issues but Problems panel still shows them
- Status bar shows stale counts

### Solutions

#### ✅ Solution 1: Auto-Refresh (Easiest)
Just save your file:
```
1. Make your changes
2. Press Cmd+S (or Ctrl+S)
3. Wait 1 second
4. Diagnostics update automatically
```

#### ✅ Solution 2: Manual Clear & Rescan
Force a complete refresh:
```
1. Cmd+Shift+P
2. Type: "Security: Clear Diagnostics and Rescan"
3. Press Enter
```
This clears everything and rescans the current file.

#### ✅ Solution 3: Rescan Current File
Quick rescan without clearing:
```
1. Cmd+Shift+P
2. Type: "Security: Scan Current File"
3. Press Enter
```

#### ✅ Solution 4: Toggle Real-Time Scanning
Reset the scanner:
```
1. Cmd+Shift+P
2. Type: "Security: Toggle Real-Time Scanning"
3. Press Enter (turns it off)
4. Press Cmd+Shift+P again
5. Toggle it back on
```

---

## 🔴 Extension Not Showing Any Alerts

### Problem
Extension is installed but no security warnings appear.

### Symptoms
- No diagnostics in Problems panel
- No squiggly underlines in code
- Status bar shows "Security Scan: Clear"

### Solutions

#### ✅ Check if Real-Time Scanning is Enabled
```
1. Look at status bar (bottom right)
2. Should say "Security Scan: X issues" or "Security Scan: Clear"
3. If not there, extension may not be active
```

#### ✅ Manually Trigger a Scan
```
1. Open a code file (e.g., test-examples.js)
2. Cmd+Shift+P
3. Type: "Security: Scan Current File"
4. Check Problems panel (Cmd+Shift+M)
```

#### ✅ Check Developer Console
```
1. Help → Toggle Developer Tools
2. Click "Console" tab
3. Look for "[Security Scanner]" messages
4. Should see: "[Security Scanner] Scanning document: ..."
```

#### ✅ Reinstall Extension
```bash
# Uninstall
code --uninstall-extension kr-security.suspicious-code-detector

# Reinstall
code --install-extension /path/to/suspicious-code-detector-1.0.0.vsix

# Fully restart VSCode (Cmd+Q, then reopen)
```

---

## 🔴 Too Many False Positives

### Problem
Extension flags legitimate code as suspicious.

### Symptoms
- Chinese/Japanese/Korean comments flagged
- Legitimate obfuscators flagged
- Build tools flagged

### Solutions

#### ✅ Ignore Individual Findings
Add a comment above the line:
```javascript
// security-ignore: This is intentional for...
eval(someCode); // This line will be ignored
```

#### ✅ Adjust Detection Thresholds
In VSCode Settings (Cmd+,):
```json
{
  "malwareDetector.minStegoSequence": 20,  // Default: 10
  "malwareDetector.maxIndentation": 400,   // Default: 200
  "malwareDetector.detectHomoglyphs": false // If too noisy
}
```

#### ✅ Exclude File Types
```json
{
  "malwareDetector.excludeLanguages": ["markdown", "plaintext"]
}
```

#### ✅ Allow CJK in Comments
```json
{
  "malwareDetector.allowCJKinComments": true  // Default: true
}
```

---

## 🔴 Extension Scanner Not Working

### Problem
Auto-scan doesn't trigger when installing extensions.

### Symptoms
- Install extension but no security alert
- No notification appears
- Extensions not being scanned

### Solutions

#### ✅ Check if Auto-Scan is Enabled
In Settings:
```json
{
  "malwareDetector.autoScanNewExtensions": true
}
```

#### ✅ Manual Extension Scan
```
1. Cmd+Shift+P
2. Type: "Security: Scan All Installed Extensions"
3. Wait for scan to complete (5-30 seconds)
4. View report if issues found
```

#### ✅ Check Extension is Loaded
```
1. Cmd+Shift+P
2. Type: "Extensions: Show Installed Extensions"
3. Search for "Suspicious Code Detector"
4. Should show as "Enabled"
```

---

## 🔴 Clickable Links Not Working

### Problem
Click on `📍 Line XX` in HTML report but nothing happens.

### Symptoms
- Links don't open files
- Cursor doesn't jump to line
- No response when clicking

### Solutions

#### ✅ Check File Path
- Links only work for files within VSCode workspace
- Extension files should be accessible
- File may have been deleted

#### ✅ Try Manual Navigation
```
1. Note the file path and line number
2. Cmd+P to open file picker
3. Type the filename
4. Press Cmd+G
5. Enter line number
```

#### ✅ Reload Extension
```
1. Cmd+Shift+P
2. Type: "Developer: Reload Window"
3. Try clicking links again
```

---

## 🔴 Performance Issues

### Problem
VSCode becomes slow when extension is active.

### Symptoms
- Typing lag
- High CPU usage
- Slow file opening

### Solutions

#### ✅ Disable Real-Time Scanning
```
1. Cmd+Shift+P
2. Type: "Security: Toggle Real-Time Scanning"
3. Use manual scans instead
```

#### ✅ Exclude Large Files
Extension automatically skips files >1MB, but you can manually exclude:
```json
{
  "malwareDetector.excludeLanguages": ["log", "plaintext"]
}
```

#### ✅ Scan On-Demand Only
```json
{
  "malwareDetector.enabled": false
}
```
Then use manual commands when needed.

---

## 🔴 Status Bar Not Showing

### Problem
No "Security Scan" indicator in status bar.

### Symptoms
- Bottom-right corner empty
- No scan statistics visible

### Solutions

#### ✅ Check Status Bar Settings
VSCode Settings → search "status bar" → ensure it's visible

#### ✅ Reload Window
```
1. Cmd+Shift+P
2. Type: "Developer: Reload Window"
3. Check status bar again
```

#### ✅ Scan a File
```
1. Open any .js file
2. Cmd+Shift+P
3. "Security: Scan Current File"
4. Status bar should update
```

---

## 🔴 Can't See Problems Panel

### Problem
Diagnostics are found but can't see them.

### Solutions

#### ✅ Open Problems Panel
```
Cmd+Shift+M (or Ctrl+Shift+M)
```

#### ✅ Check Panel Visibility
```
View → Problems
```

#### ✅ Filter Problems
In Problems panel, make sure no filters are active:
- Click filter icon
- Ensure "Security Scanner" is not excluded

---

## 🔴 Commands Not Appearing

### Problem
Can't find security commands in Command Palette.

### Solutions

#### ✅ Check Extension is Enabled
```
1. Cmd+Shift+P
2. "Extensions: Show Installed Extensions"
3. Find "Suspicious Code Detector"
4. Click "Enable" if needed
```

#### ✅ Reload Window
```
Cmd+Shift+P → "Developer: Reload Window"
```

#### ✅ Reinstall Extension
```bash
code --uninstall-extension kr-security.suspicious-code-detector
code --install-extension suspicious-code-detector-1.0.0.vsix
```

**Then fully quit (Cmd+Q) and restart VSCode.**

---

## 🔧 General Troubleshooting Steps

### Step 1: Check Console Logs
```
1. Help → Toggle Developer Tools
2. Console tab
3. Look for [Security Scanner] messages
4. Check for errors (red text)
```

### Step 2: Reload Window
```
Cmd+Shift+P → "Developer: Reload Window"
```

### Step 3: Restart VSCode
```
Fully quit (Cmd+Q) → Reopen
```

### Step 4: Reinstall Extension
```bash
code --uninstall-extension kr-security.suspicious-code-detector
code --install-extension /path/to/suspicious-code-detector-1.0.0.vsix
```

### Step 5: Check VSCode Version
Extension requires VSCode 1.75.0 or later:
```
Code → About Visual Studio Code
```

---

## 📋 Quick Command Reference

| Issue | Command |
|-------|---------|
| Stale diagnostics | `Security: Clear Diagnostics and Rescan` |
| Force scan | `Security: Scan Current File` |
| Scan workspace | `Security: Scan Entire Workspace` |
| View report | `Security: Show Anomaly Findings` |
| Toggle scanning | `Security: Toggle Real-Time Scanning` |
| Scan extensions | `Security: Scan All Installed Extensions` |
| Extension report | `Security: Show Extension Scan Report` |

---

## 🆘 Still Having Issues?

### Debug Mode

1. **Open Developer Tools**
   ```
   Help → Toggle Developer Tools
   ```

2. **Open Console Tab**

3. **Look for these messages:**
   ```
   [Security Scanner] is now active
   [Security Scanner] Scanning document: filename.js
   [Security Scanner] Found X detections
   ```

4. **If you see errors:**
   - Take a screenshot
   - Note the error message
   - Check if it's a known issue

### Report Issues

If nothing works:
1. Note your VSCode version
2. Note what you tried
3. Check console for errors
4. Report via GitHub (if repository available)

---

## ✅ After Fixing Issues

Once resolved:
1. ✅ Test with `test-examples.js`
2. ✅ Verify Problems panel shows findings
3. ✅ Check status bar updates
4. ✅ Test manual commands
5. ✅ Test auto-scan (edit & save)

---

**Most issues are resolved with a simple VSCode restart (Cmd+Q → reopen)** 🔄

