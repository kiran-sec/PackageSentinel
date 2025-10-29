# Installation & Setup Guide

## Quick Installation (Coming Soon)

Once published to the VSCode Marketplace:

1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Malware Steganography Detector"
4. Click "Install"

## Manual Installation (For Development/Testing)

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- VSCode (v1.75.0 or higher)

### Step 1: Clone or Download

```bash
cd "Static Analysis/kr_vscode"
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Package the Extension

```bash
# Install VSCE (VSCode Extension packager) if you don't have it
npm install -g vsce

# Package the extension
vsce package
```

This creates a `.vsix` file (e.g., `malware-steganography-detector-1.0.0.vsix`)

### Step 4: Install in VSCode

#### Method A: Via Command Line
```bash
code --install-extension malware-steganography-detector-1.0.0.vsix
```

#### Method B: Via VSCode UI
1. Open VSCode
2. Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS)
3. Type "Install from VSIX"
4. Select the `.vsix` file
5. Reload VSCode

### Step 5: Verify Installation

1. Open any JavaScript/TypeScript file
2. Check the status bar (bottom right) - you should see "🛡️ Malware: Clean"
3. Open the test file: `test-examples.js`
4. You should see warnings and errors highlighted

## Configuration

### First-Time Setup

1. Open VSCode Settings (`Ctrl+,` or `Cmd+,`)
2. Search for "Malware Detector"
3. Configure your preferences:

```json
{
  "malwareDetector.enabled": true,
  "malwareDetector.detectUnicodeStego": true,
  "malwareDetector.detectInvisibleChars": true,
  "malwareDetector.detectExcessiveIndentation": true,
  "malwareDetector.maxIndentation": 200,
  "malwareDetector.minStegoSequence": 10,
  "malwareDetector.allowCJKinComments": true
}
```

### Recommended Settings for Different Teams

#### For Security-Focused Teams
```json
{
  "malwareDetector.enabled": true,
  "malwareDetector.severity": "Error",  // Block with errors
  "malwareDetector.maxIndentation": 100,  // Stricter
  "malwareDetector.minStegoSequence": 5   // More sensitive
}
```

#### For International Teams
```json
{
  "malwareDetector.enabled": true,
  "malwareDetector.allowCJKinComments": true,
  "malwareDetector.excludeLanguages": ["markdown", "latex"],
  "malwareDetector.detectHomoglyphs": false  // Reduce false positives
}
```

#### For CI/CD Integration
```json
{
  "malwareDetector.enabled": true,
  "malwareDetector.severity": "Error",
  "malwareDetector.detectSuspiciousEval": true
}
```

## Testing the Installation

### Quick Test

1. Create a new file: `test.js`
2. Paste this code:
```javascript
eval(atob('Y29uc29sZS5sb2coInRlc3QiKQ=='));
```
3. You should see a warning: "⚠️ Suspicious code execution pattern"

### Full Test

1. Open the included `test-examples.js` file
2. Check the Problems panel (`Ctrl+Shift+M` / `Cmd+Shift+M`)
3. You should see ~17 detections
4. Click the status bar item to see the full report

## Usage Examples

### Scan Current File
```
Cmd/Ctrl + Shift + P
> Scan Current File for Malware Techniques
```

### Scan Workspace
```
Cmd/Ctrl + Shift + P
> Scan Entire Workspace for Malware Techniques
```

### View Report
```
Cmd/Ctrl + Shift + P
> Show Malware Detection Report
```

### Toggle Real-Time Detection
```
Cmd/Ctrl + Shift + P
> Toggle Real-Time Malware Detection
```

## Troubleshooting

### Extension Not Working

**Check if extension is active:**
1. Open Output panel (`Ctrl+Shift+U` / `Cmd+Shift+U`)
2. Select "Malware Detector" from dropdown
3. Look for activation message

**Reload VSCode:**
```
Cmd/Ctrl + Shift + P
> Developer: Reload Window
```

### No Warnings Appearing

1. Check that detection is enabled:
   - Settings → `malwareDetector.enabled` = `true`
2. Check the status bar - it should show the shield icon
3. Try running "Scan Current File" command manually
4. Check if file type is excluded in settings

### Too Many False Positives

1. Enable CJK allowance:
   ```json
   "malwareDetector.allowCJKinComments": true
   ```

2. Exclude specific languages:
   ```json
   "malwareDetector.excludeLanguages": ["markdown", "plaintext"]
   ```

3. Adjust thresholds:
   ```json
   "malwareDetector.minStegoSequence": 20,  // Less sensitive
   "malwareDetector.maxIndentation": 300    // More lenient
   ```

### Performance Issues

If the extension slows down VSCode:

1. Disable real-time detection:
   ```json
   "malwareDetector.enabled": false
   ```
   Then scan manually when needed.

2. Exclude large directories:
   - Add to `.vscodeignore` or workspace settings

3. Increase file size threshold (modify `extension.js`):
   ```javascript
   if (document.getText().length > 1024 * 1024 * 5) // 5MB instead of 1MB
   ```

## Uninstallation

### Via VSCode UI
1. Go to Extensions panel
2. Find "Malware Steganography Detector"
3. Click "Uninstall"
4. Reload VSCode

### Via Command Line
```bash
code --uninstall-extension kr-security.malware-steganography-detector
```

## Development Mode

To develop/debug the extension:

1. Open the `kr_vscode` folder in VSCode
2. Press `F5` to launch Extension Development Host
3. Make changes to code
4. Press `Ctrl+R` in the Development Host to reload
5. Test your changes

### Debug Output

Enable debug logging by modifying `extension.js`:
```javascript
console.log('Debug: Detection results:', detections);
```

View logs in:
- Output panel → "Malware Detector"
- Developer Tools (`Help` → `Toggle Developer Tools`)

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/yourusername/malware-steganography-detector/issues)
- **Documentation:** [README.md](./README.md)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## Next Steps

1. ✅ Install the extension
2. ✅ Configure settings for your needs
3. ✅ Test with `test-examples.js`
4. ✅ Scan your workspace
5. ✅ Review any detections
6. ✅ Adjust settings to reduce false positives
7. ✅ Share with your team

---

**🛡️ Stay safe! This extension is your first line of defense against code-based attacks.**

