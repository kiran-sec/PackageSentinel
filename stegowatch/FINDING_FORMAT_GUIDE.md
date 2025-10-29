# Finding Format Guide

Complete guide to the structured finding format with severity badges and clickable links.

---

## 📋 Notification Format

### Structure

```
⚠️ Security Alert: "extension-name" (X critical)

• Finding Name [🔴 Severity] - file.js:42
• Finding Name [🟠 Severity] - file.js:89
• Finding Name [🟡 Severity] - file.js:156
...and X more

[View Full Report] [Uninstall] [Dismiss]
```

### Components

**1. Finding Name**
- Short, descriptive name of the issue
- Extracted from the full detection message
- Easy to scan quickly

**2. Severity Badge**
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Should be reviewed soon
- 🟡 **Medium**: Potentially concerning
- 🔵 **Low**: Minor issues

**3. Location**
- `file.js:42` format
- Shows file name and line number
- In HTML report, these are clickable

---

## 🎯 Real Examples

### Example 1: Single Extension with Critical Issues

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️ Security Alert: "suspicious-ext" (2 critical)                │
│                                                                 │
│ • Dynamic code execution [🔴 Critical] - index.js:42           │
│ • Unicode steganography [🔴 Critical] - utils.js:89            │
│ • Invisible character [🟡 Medium] - main.js:156                │
│ • Command execution [🟠 High] - loader.js:23                   │
│ • Excessive indentation [🟡 Medium] - core.js:67               │
│                                                                 │
│ Click "View Full Report" to see all details and jump to code.  │
│                                                                 │
│ [View Full Report]  [Uninstall]  [Dismiss]                     │
└─────────────────────────────────────────────────────────────────┘
```

### Example 2: Multiple Extensions Scanned

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️ Found issues in 2 extension(s) (8.3s)                        │
│                                                                 │
│ • Dynamic code execution [🔴 Critical] - ext1/index.js:42      │
│ • Unicode steganography [🔴 Critical] - ext1/utils.js:89       │
│ • Command execution [🟠 High] - ext2/main.js:23                │
│ • Invisible character [🟡 Medium] - ext2/loader.js:156         │
│ • Unusual indentation [🟡 Medium] - ext2/core.js:67            │
│ ...and 3 more                                                  │
│                                                                 │
│ Click "View Full Report" to see all details and jump to code.  │
│                                                                 │
│ [View Full Report]  [Dismiss]                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Example 3: Clean Extension

```
┌─────────────────────────────────────────────────────────────────┐
│ ✓ Security Scan: New extension "prettier" appears clean.       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 HTML Report Format

### Overview

The HTML report provides a detailed view with:
- Full finding names
- Color-coded severity badges
- **Clickable line numbers** to jump to code
- Complete file paths
- Organized by extension and file

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Extension Security Scan Results                             │
│ Found potential issues in 1 extension(s) - 5 total findings│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Suspicious Extension                                    │ │
│ │ publisher.suspicious-ext                                │ │
│ │                                                          │ │
│ │ by suspicious-publisher | v1.0.0                        │ │
│ │                                                          │ │
│ │ 5 potential issue(s) found | 2 critical                 │ │
│ │                                                          │ │
│ │ Files:                                                   │ │
│ │   extension/index.js                                     │ │
│ │                                                          │ │
│ │     Dynamic code execution                              │ │
│ │     [CRITICAL] 📍 Line 42  ← CLICKABLE                  │ │
│ │                                                          │ │
│ │     Unicode steganography                               │ │
│ │     [CRITICAL] 📍 Line 89  ← CLICKABLE                  │ │
│ │                                                          │ │
│ │   extension/utils.js                                     │ │
│ │                                                          │ │
│ │     Invisible character                                  │ │
│ │     [MEDIUM] 📍 Line 156   ← CLICKABLE                  │ │
│ │                                                          │ │
│ │     Command execution                                    │ │
│ │     [HIGH] 📍 Line 23      ← CLICKABLE                  │ │
│ │                                                          │ │
│ │     Excessive indentation                                │ │
│ │     [MEDIUM] 📍 Line 67    ← CLICKABLE                  │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Clickable Links

**How They Work:**
1. Click on any `📍 Line XX` link
2. The file opens in VSCode
3. Cursor jumps to the exact line
4. Line is highlighted and centered

**Visual Indicators:**
- 📍 emoji shows it's a link
- Blue underline on hover
- Background changes on hover
- Tooltip shows full path

---

## 🔍 Finding Name Categories

### 1. **Dynamic code execution**
```
• Dynamic code execution [🔴 Critical] - index.js:42
```
**Patterns:**
- `eval(atob(...))`
- `new Function(atob(...))`
- `.then(eval)`
- `Function(...).call()`

**Why Critical:**
- Can execute arbitrary code
- Common in malware
- Used to hide payloads

### 2. **Unicode steganography**
```
• Unicode steganography [🔴 Critical] - utils.js:89
```
**Patterns:**
- Sequences of invisible Unicode characters
- Unicode Variation Selectors (U+FE00-U+FE0F)
- Private Use Area characters (U+E000-U+F8FF)

**Why Critical:**
- Used to hide entire payloads
- Invisible in most editors
- Exact technique used in ellacrity.recoil malware

### 3. **Command execution**
```
• Command execution [🟠 High] - loader.js:23
```
**Patterns:**
- `child_process.exec()`
- `child_process.spawn()`
- System command execution

**Why High:**
- Can execute system commands
- Potential for system compromise
- Used for persistence

### 4. **Invisible character**
```
• Invisible character [🟡 Medium] - main.js:156
```
**Patterns:**
- Zero Width Space (U+200B)
- Zero Width Joiner (U+200D)
- Zero Width Non-Joiner (U+200C)
- Byte Order Mark (U+FEFF)

**Why Medium:**
- Used for manipulation
- Can hide code intent
- Often legitimate in some contexts

### 5. **Bidirectional text**
```
• Bidirectional text [🔴 Critical] - core.js:234
```
**Patterns:**
- Right-to-Left Override (RLO)
- Left-to-Right Override (LRO)
- Other bidirectional control characters

**Why Critical:**
- Trojan Source attack (CVE-2021-42574)
- Can reverse code display
- Extremely deceptive

### 6. **Excessive indentation** / **Unusual indentation**
```
• Excessive indentation [🟡 Medium] - helper.js:67
```
**Patterns:**
- Lines with >200 spaces
- Code hidden off-screen
- Unusual whitespace patterns

**Why Medium:**
- Can hide malicious code
- Makes review difficult
- Sometimes legitimate (minified code)

### 7. **Homoglyph** / **Non-ASCII character**
```
• Non-ASCII character [🟡 Medium] - worker.js:45
```
**Patterns:**
- Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
- Greek letters in identifiers
- Other lookalike characters

**Why Medium:**
- Used for variable spoofing
- Can bypass security checks
- Sometimes legitimate (international code)

---

## 🎨 Severity Badge Colors

### In Notifications

```
[🔴 Critical]  - Red emoji, urgent action
[🟠 High]      - Orange emoji, review soon
[🟡 Medium]    - Yellow emoji, potentially concerning
[🔵 Low]       - Blue emoji, minor issues
```

### In HTML Report

```
CRITICAL  - Red background, white text
HIGH      - Orange background, white text
MEDIUM    - Yellow background, dark text
LOW       - Blue background, white text
```

---

## 🖱️ Using Clickable Links

### In HTML Report

1. **Click the line link**
   - Look for `📍 Line XX`
   - Click anywhere on the link

2. **File opens**
   - VSCode opens the file automatically
   - If file is already open, switches to it

3. **Navigate to line**
   - Cursor jumps to the exact line
   - Line is highlighted
   - Line is centered in viewport

4. **Review the code**
   - Check if pattern is legitimate
   - Read surrounding context
   - Decide if it's a false positive

### Example Workflow

```
1. See notification:
   • Dynamic code execution [🔴 Critical] - index.js:42

2. Click "View Full Report"

3. In HTML report, click "📍 Line 42"

4. index.js opens at line 42:
   ──────────────────────────────────
   40 | function loader() {
   41 |   const payload = getData();
   42 |   eval(atob(payload));  ← CURSOR HERE
   43 |   return true;
   44 | }
   ──────────────────────────────────

5. Review the code and decide:
   - Legitimate? Add // security-ignore
   - Malicious? Uninstall extension
```

---

## 💡 Tips & Best Practices

### Reading Notifications

1. **Look at severity first**
   - 🔴 Critical = immediate attention
   - 🟠 High = review today
   - 🟡 Medium = review when possible

2. **Scan finding names**
   - Quick overview of issue types
   - Identify patterns

3. **Check file names**
   - `index.js` = main file
   - `utils.js` = utility functions
   - `loader.js` = loading logic

4. **Use "View Full Report"**
   - For detailed analysis
   - To jump to code
   - To see all findings

### Interpreting Findings

**Critical Findings**
```
• Dynamic code execution [🔴 Critical]
• Unicode steganography [🔴 Critical]
• Bidirectional text [🔴 Critical]
```
→ **Action**: Review immediately, likely malicious

**High Findings**
```
• Command execution [🟠 High]
```
→ **Action**: Check if necessary for extension's purpose

**Medium Findings**
```
• Invisible character [🟡 Medium]
• Excessive indentation [🟡 Medium]
• Homoglyph [🟡 Medium]
```
→ **Action**: Review in context, often false positives

### False Positive Management

**Common False Positives:**

1. **Obfuscators/Minifiers**
   ```
   • Dynamic code execution [🔴 Critical]
   • Excessive indentation [🟡 Medium]
   ```
   → Legitimate if extension is an obfuscator

2. **International Code**
   ```
   • Homoglyph [🟡 Medium]
   ```
   → Legitimate for non-English identifiers

3. **Build Tools**
   ```
   • Command execution [🟠 High]
   ```
   → Legitimate for build/compile extensions

**How to Handle:**
1. Review the code context
2. Check extension's description
3. Verify publisher reputation
4. If safe, dismiss the alert

---

## 📚 Format Comparison

### Before (Old Format)
```
⚠️ Security Alert: Extension contains 5 issues

[View Details] [Uninstall] [Dismiss]
```

### After (New Format)
```
⚠️ Security Alert: "extension-name" (2 critical)

• Dynamic code execution [🔴 Critical] - index.js:42
• Unicode steganography [🔴 Critical] - utils.js:89
• Invisible character [🟡 Medium] - main.js:156
• Command execution [🟠 High] - loader.js:23
• Excessive indentation [🟡 Medium] - core.js:67

Click "View Full Report" to see all details and jump to code.

[View Full Report] [Uninstall] [Dismiss]
```

### Benefits

✅ **Immediate context** - See what was found  
✅ **Severity indicators** - Know what's critical  
✅ **Location info** - Know where to look  
✅ **Clickable links** - Jump directly to code  
✅ **Better decisions** - Make informed choices  

---

## 🔧 Customization

### Adjust Detection Thresholds

```json
{
  "malwareDetector.minStegoSequence": 20,  // Reduce stego alerts
  "malwareDetector.maxIndentation": 400,   // Allow more indentation
  "malwareDetector.detectHomoglyphs": false // Disable homoglyph detection
}
```

### Disable Auto-Scan

```json
{
  "malwareDetector.autoScanNewExtensions": false
}
```

---

## ❓ FAQ

### Q: Why are line numbers clickable only in HTML report?

A: VSCode notifications don't support interactive links. The HTML report provides full interactivity.

### Q: Can I click line numbers in notifications?

A: No, but clicking "View Full Report" opens the HTML report where all line numbers are clickable.

### Q: What if the file doesn't open?

A: The extension file might be locked or inaccessible. Try:
1. Restarting VSCode
2. Checking file permissions
3. Re-installing the suspicious extension (if safe)

### Q: Do links work for regular code scanning?

A: Currently, clickable links are for extension scanning. Regular code files show line numbers in the Problems panel, which are already clickable by default in VSCode.

---

## 🚀 Quick Reference

| Element | Meaning | Action |
|---------|---------|--------|
| 🔴 Critical | Highly suspicious | Review immediately |
| 🟠 High | Potentially dangerous | Review soon |
| 🟡 Medium | Unusual pattern | Review if time permits |
| 📍 Line XX | Clickable link | Click to jump to code |
| [View Full Report] | Open HTML | See all details |
| [Uninstall] | Remove extension | For confirmed threats |
| [Dismiss] | Close alert | Use cautiously |

---

**Stay secure! Understanding the format helps you make better security decisions.** 🛡️

