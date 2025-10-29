# Demo Suspicious Extension

⚠️ **WARNING: This is a DEMONSTRATION extension with intentionally suspicious code patterns!**

## Purpose

This extension is designed to **test and demonstrate** security scanners and malware detection tools. It contains various code patterns that are commonly found in malicious extensions but does nothing harmful.

## What This Extension Does

**Actual functionality:** Just shows a "Hello World" message.

**Suspicious patterns included for testing:**

1. ✅ **Dynamic Code Execution** (`eval(atob(...))`) - CRITICAL
2. ✅ **Command Execution** (`child_process.exec()`) - HIGH
3. ✅ **Invisible Characters** (Zero-width spaces) - MEDIUM
4. ✅ **Excessive Indentation** (Code hidden off-screen) - MEDIUM
5. ✅ **Unicode Steganography** (Hidden payload) - CRITICAL
6. ✅ **Function Constructor** (`new Function(atob(...))`) - CRITICAL
7. ✅ **Promise Chain with eval** (`.then(eval)`) - CRITICAL
8. ✅ **Buffer Encoding** (`Buffer.from(...).toString()`) - MEDIUM
9. ✅ **Homoglyph Attack** (Cyrillic characters) - MEDIUM

## How to Use

### Testing Your Security Scanner

1. **Package the extension:**
   ```bash
   cd demo-suspicious-extension
   vsce package
   ```

2. **Install it in VSCode:**
   ```bash
   code --install-extension demo-suspicious-extension-0.1.0.vsix
   ```

3. **Scan it with your security scanner:**
   - If using the Suspicious Code Detector:
   - `Cmd+Shift+P` → "Security: Scan All Installed Extensions"
   - Wait for automatic scan (if auto-scan is enabled)

4. **Expected Results:**
   - Should detect **~9 findings**
   - **3-4 Critical** severity
   - **2-3 High** severity
   - **3-4 Medium** severity

### Expected Detections

Your scanner should flag:

```
⚠️ Security Alert: "demo-suspicious-extension" (4 critical)

• Dynamic code execution [🔴 Critical] - extension.js:23
• Dynamic code execution [🔴 Critical] - extension.js:42
• Dynamic code execution [🔴 Critical] - extension.js:45
• Unicode steganography [🔴 Critical] - extension.js:38
• Command execution [🟠 High] - extension.js:27
• Invisible character [🟡 Medium] - extension.js:31
• Excessive indentation [🟡 Medium] - extension.js:35
• Homoglyph [🟡 Medium] - extension.js:53
```

## Is This Safe?

**Yes!** Despite containing suspicious patterns:

- ✅ The `eval()` calls only execute harmless console.log statements
- ✅ The `exec()` call only echoes a message
- ✅ No network requests are made
- ✅ No files are accessed or modified
- ✅ No credentials are stolen
- ✅ No actual malicious behavior

## Why These Patterns?

These patterns are based on **real malware** like:

- **ellacrity.recoil** - Used Unicode steganography
- **GlassWorm** - Used dynamic code execution
- Various npm/PyPI malware - Used command execution

## Uninstalling

```bash
code --uninstall-extension demo-publisher.demo-suspicious-extension
```

Or via VSCode:
1. Extensions panel
2. Find "Demo Suspicious Extension"
3. Uninstall

## For Security Researchers

This extension can be used to:

- ✅ Test malware detection tools
- ✅ Benchmark scanner accuracy
- ✅ Demonstrate security issues
- ✅ Train security teams
- ✅ Validate scanner updates

## License

MIT License - Free to use for security research and testing.

---

**Remember:** This is for **DEMONSTRATION ONLY**. Never use these patterns in production code!

