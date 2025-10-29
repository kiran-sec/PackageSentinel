# Changelog

All notable changes to the "Malware Steganography Detector" extension will be documented in this file.

## [1.0.0] - 2025-10-28

### Added - Initial Release

#### Core Detection Features
- **Unicode Steganography Detection**: Detects Unicode Variation Selectors (U+FE00-U+FE0F, U+E0100-U+E01EF) and Private Use Area characters used to hide malicious payloads
- **Bidirectional Override Detection**: Detects "Trojan Source" attacks using bidirectional text control characters
- **Zero-Width Character Detection**: Finds invisible characters like zero-width spaces, joiners, and non-joiners
- **Excessive Indentation Detection**: Warns about lines with extreme indentation (>200 spaces) that hide code off-screen
- **Homoglyph Detection**: Identifies lookalike characters (e.g., Cyrillic 'а' vs Latin 'a')
- **Suspicious Code Pattern Detection**: Flags dangerous patterns like `eval(atob(...))` and `child_process.exec()`

#### User Interface
- Real-time scanning as you type
- Status bar indicator showing detection statistics
- Detailed HTML report with malware information
- VSCode diagnostics integration (Problems panel)
- Configurable severity levels (Error/Warning/Information)

#### Configuration Options
- Toggle individual detection features on/off
- Adjustable thresholds (max indentation, min steganography sequence)
- Language exclusions for false positive reduction
- CJK-aware detection (allows Chinese/Japanese/Korean in comments)

#### Commands
- `Scan Current File`: Quick scan of active editor
- `Scan Entire Workspace`: Deep scan of all code files
- `Show Malware Detection Report`: Detailed HTML report
- `Toggle Real-Time Detection`: Enable/disable live scanning

#### Intelligence
- Based on analysis of real malware:
  - ellacrity.recoil (Unicode steganography malware)
  - GlassWorm (developer-targeting information stealer)
  - Trojan Source (CVE-2021-42574)

#### Performance
- Skips files >1MB for performance
- Efficient pattern matching
- Debounced scanning on text changes
- Minimal CPU/memory footprint

### Technical Details

#### Detection Algorithms
1. **Steganography Scanner**: Character-by-character analysis of Unicode code points
2. **Context-Aware Analysis**: Distinguishes legitimate Unicode from malicious patterns
3. **Pattern Matching**: Regex-based detection of suspicious code patterns
4. **Statistical Analysis**: Identifies unusual character frequency distributions

#### False Positive Mitigation
- Whitelist for legitimate Unicode ranges (CJK, Arabic, Hebrew, Cyrillic, Emoji)
- Comment-aware detection (allows international text in comments)
- Configurable exclusions by language/file type
- Smart thresholds to reduce noise

## [Upcoming]

### Planned Features for 1.1.0
- [ ] Machine learning-based anomaly detection
- [ ] Integration with static analysis tools (Semgrep, CodeQL)
- [ ] Export reports to JSON/CSV
- [ ] Workspace-wide statistics dashboard
- [ ] Custom rule creation UI
- [ ] Git pre-commit hook integration
- [ ] Team sharing of detection rules

### Research & Development
- [ ] Deep learning model for obfuscation detection
- [ ] Integration with VirusTotal/hybrid-analysis
- [ ] Automatic deobfuscation of simple techniques
- [ ] Supply chain vulnerability database integration

## Bug Reports & Feature Requests

Please report issues at: [GitHub Issues](https://github.com/yourusername/malware-steganography-detector/issues)

---

## Version History

- **1.0.0** (2025-10-28): Initial release with core detection features

