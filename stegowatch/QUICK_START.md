# Quick Start Guide - 5 Minutes to Protection

## 🚀 Installation (1 minute)

### For Development/Testing:

```bash
cd "/Users/kraj/Desktop/Company-code/Static Analysis/kr_vscode"

# Install VSCE if needed
npm install -g vsce

# Package the extension
vsce package

# Install in VSCode
code --install-extension malware-steganography-detector-1.0.0.vsix
```

### Reload VSCode
Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS), then:
```
> Developer: Reload Window
```

---

## ✅ Verify Installation (30 seconds)

1. **Check Status Bar** (bottom right):
   - Should show: `🛡️ Malware: Clean`

2. **Open Test File**:
   ```bash
   # Open the test examples
   code test-examples.js
   ```

3. **Check Problems Panel**:
   - Press `Ctrl+Shift+M` (Windows/Linux) or `Cmd+Shift+M` (macOS)
   - Should see ~17 warnings/errors

---

## 🎯 Basic Usage (2 minutes)

### Command Palette
Press `Ctrl+Shift+P` / `Cmd+Shift+P` and try:

1. **Scan Current File**
   ```
   > Scan Current File for Malware Techniques
   ```

2. **Scan Entire Workspace**
   ```
   > Scan Entire Workspace for Malware Techniques
   ```

3. **View Report**
   ```
   > Show Malware Detection Report
   ```

4. **Toggle Detection**
   ```
   > Toggle Real-Time Malware Detection
   ```

---

## ⚙️ Basic Configuration (1 minute)

### Open Settings
`Ctrl+,` (Windows/Linux) or `Cmd+,` (macOS), then search: `malware`

### Essential Settings:
```json
{
  // Enable the extension
  "malwareDetector.enabled": true,
  
  // Allow Chinese/Japanese/Korean in comments (reduces false positives)
  "malwareDetector.allowCJKinComments": true,
  
  // Set warning level
  "malwareDetector.severity": "Warning"  // or "Error" or "Information"
}
```

---

## 🔍 What You'll See

### In the Editor:
- **Red underlines** = Critical issues (Unicode steganography, bidi attacks)
- **Orange underlines** = High severity (homoglyphs, excessive indentation)
- **Blue underlines** = Medium severity (format control chars)

### In the Status Bar:
- `🛡️ Malware: Clean` = No issues ✅
- `⚠️ Malware: 3 Critical` = Issues found ⚠️

### In the Problems Panel:
- Detailed list of all detections
- Click any issue to jump to code
- Hover for more information

---

## 🧪 Test Cases

Try these in a new file to see detection in action:

### Test 1: Unicode Steganography (CRITICAL)
```javascript
var payload = '󠅔󠅝󠄶󠅩󠄹󠄶󠄩󠅖󠅉󠄣󠄺󠅜󠅉󠅈󠅂󠅜󠄹󠄴󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠';
// ⚠️ Should warn: "CRITICAL: Found 30 Unicode Variation Selectors"
```

### Test 2: Suspicious eval (CRITICAL)
```javascript
eval(atob('Y29uc29sZS5sb2coInRlc3QiKQ=='));
// ⚠️ Should warn: "Suspicious code execution pattern: eval(atob(...))"
```

### Test 3: Excessive Indentation (HIGH)
```javascript
                                                                                                        console.log('hidden');
// ⚠️ Should warn: "Excessive indentation: 100+ spaces"
```

### Test 4: Legitimate CJK (NO WARNING)
```javascript
// 这是一个正常的中文注释 - Should NOT warn
const message = "你好世界";  // Should NOT warn
```

---

## 🎓 Understanding Results

### Critical Findings (🔴 Must Fix)
1. **Unicode Steganography**
   - Hidden invisible characters encoding data
   - Used in ellacrity.recoil malware
   - **Action:** Remove invisible characters, investigate source

2. **Bidirectional Override**
   - Code appearance reversed (Trojan Source attack)
   - **Action:** Remove bidi control characters immediately

3. **Suspicious eval() Patterns**
   - Dynamic code execution with encoding
   - **Action:** Refactor to avoid eval(), review logic

### High Severity (🟠 Should Fix)
1. **Excessive Indentation**
   - Code hidden off-screen
   - **Action:** Reduce indentation, check for hidden code

2. **Homoglyphs**
   - Lookalike characters in identifiers
   - **Action:** Replace with standard ASCII

3. **Zero-Width Characters**
   - Invisible spacing in code
   - **Action:** Remove invisible characters

### Medium Severity (🟡 Review)
1. **Format Control Characters**
   - Unusual formatting marks
   - **Action:** Verify purpose, remove if unnecessary

---

## 🌏 International Code

### For Teams Using Chinese/Japanese/Korean:

```json
{
  // Allow CJK in comments
  "malwareDetector.allowCJKinComments": true,
  
  // Exclude documentation files
  "malwareDetector.excludeLanguages": ["markdown"]
}
```

### This WILL flag (suspicious):
```javascript
var аdmin = true;  // Cyrillic 'а' in code
```

### This will NOT flag (legitimate):
```javascript
// 管理员权限检查
var admin = true;  // Chinese in comment, Latin in code ✅
```

---

## 🔧 Troubleshooting

### Extension Not Active?
```
Cmd/Ctrl + Shift + P
> Developer: Reload Window
```

### No Detections Appearing?
1. Check: Settings → `malwareDetector.enabled` = `true`
2. Check: Status bar shows shield icon
3. Try: Run "Scan Current File" manually

### Too Many False Positives?
```json
{
  "malwareDetector.allowCJKinComments": true,
  "malwareDetector.minStegoSequence": 20,  // Less sensitive
  "malwareDetector.maxIndentation": 300    // More lenient
}
```

### Performance Slow?
```json
{
  "malwareDetector.enabled": false  // Disable real-time, scan manually
}
```

---

## 📊 Next Steps

### Day 1: Learn
- ✅ Install extension
- ✅ Run test examples
- ✅ Understand detections

### Week 1: Configure
- Configure for your team's needs
- Adjust false positive settings
- Document findings

### Month 1: Integrate
- Add to CI/CD pipeline
- Train team on usage
- Share threat intelligence

---

## 🆘 Need Help?

### Documentation
- Full docs: [README.md](./README.md)
- Installation: [INSTALLATION.md](./INSTALLATION.md)
- Research: [UNICODE_ATTACKS_RESEARCH.md](./UNICODE_ATTACKS_RESEARCH.md)

### Commands
- `Cmd/Ctrl + Shift + P` → Search for "Malware"
- Click status bar icon for quick report
- Check Problems panel for details

### Support
- Issues: GitHub Issues (link in README)
- Questions: GitHub Discussions
- Security: Report privately

---

## ✨ Pro Tips

1. **Scan before committing:**
   ```
   > Scan Current File for Malware Techniques
   ```

2. **Review security weekly:**
   ```
   > Scan Entire Workspace for Malware Techniques
   ```

3. **Share with team:**
   - Send them this guide
   - Share your configuration
   - Review findings together

4. **Stay updated:**
   - Watch for extension updates
   - Review new detection techniques
   - Report new attack patterns

---

**🛡️ You're now protected! The extension will automatically scan files as you work.**

**⚠️ Remember: This is one layer of defense. Always practice secure coding and review untrusted code carefully.**

