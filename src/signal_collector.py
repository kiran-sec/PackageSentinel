"""
Multi-Ecosystem Package Signal Collector
Generates structured signals for LLM-based malware analysis
"""

import json
import subprocess
import tempfile
import os
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import logging
from enum import Enum

class Ecosystem(Enum):
    NPM = "npm"
    PYPI = "pypi"
    VSIX = "vsix"

class SignalType(Enum):
    MALWARE_PATTERN = "malware_pattern"
    OBFUSCATION = "obfuscation"
    NETWORK_ACTIVITY = "network_activity"  
    FILE_OPERATIONS = "file_operations"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    CRYPTOJACKING = "cryptojacking"
    METADATA_ANOMALY = "metadata_anomaly"

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SignalLocation:
    """Represents the location of a detected pattern in code."""
    file_path: str
    line_start: int
    line_end: int
    column_start: int
    column_end: int
    code_snippet: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Signal:
    """Represents a single security signal detected in package analysis."""
    signal_id: str
    signal_type: SignalType
    severity: Severity
    confidence: float  # 0.0 to 1.0
    title: str
    description: str
    evidence: str
    locations: List[SignalLocation]
    tags: List[str]
    references: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'signal_id': self.signal_id,
            'signal_type': self.signal_type.value,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'locations': [loc.to_dict() for loc in self.locations],
            'tags': self.tags,
            'references': self.references,
            'metadata': self.metadata
        }

@dataclass
class PackageMetadata:
    """Package metadata for analysis context."""
    ecosystem: Ecosystem
    name: str
    version: str
    author: str
    description: str
    dependencies: Dict[str, str]
    dev_dependencies: Dict[str, str]
    scripts: Dict[str, str]
    repository_url: Optional[str]
    homepage_url: Optional[str]
    license: Optional[str]
    publish_date: Optional[str]
    download_count: Optional[int]
    file_count: int
    total_size: int
    # Enhanced remote metadata fields
    weekly_download_count: Optional[int] = None
    total_versions: Optional[int] = None
    total_dependants: Optional[int] = None
    registry_metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['ecosystem'] = self.ecosystem.value
        return result

@dataclass
class AnalysisResult:
    """Complete analysis result with signals and recommendations."""
    package_metadata: PackageMetadata
    signals: List[Signal]
    static_analysis_confidence: float
    recommend_dynamic_analysis: bool
    dynamic_analysis_reason: Optional[str]
    llm_context: Dict[str, Any]
    processing_time_ms: int
    errors: List[str]
    warnings: List[str]
    package_source: str = "local"  # "local" or "remote"
    package_path: Optional[str] = None  # Path to package for direct file scanning
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'static_analysis_confidence': self.static_analysis_confidence,
            'recommend_dynamic_analysis': self.recommend_dynamic_analysis,
            'dynamic_analysis_reason': self.dynamic_analysis_reason,
            'llm_context': self.llm_context,
            'iocs': self._extract_iocs(self.package_path),
            'package_source': self.package_source,  # Added package source
            'processing_time_ms': self.processing_time_ms,
            'errors': self.errors,
            'warnings': self.warnings
        }
    
    def _extract_iocs(self, package_path: Optional[str] = None) -> Dict[str, Any]:
        """Extract Indicators of Compromise (IOCs) for threat intelligence."""
        import re
        
        iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'email_addresses': set(),
            'cryptocurrency_addresses': set(),
            'binary_file_hashes': set()
        }
        
        # Add email from package metadata (author field)
        if hasattr(self, 'package_metadata') and self.package_metadata.author:
            author_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', self.package_metadata.author, re.IGNORECASE)
            iocs['email_addresses'].update(author_emails)
        
        # Enhanced regular expressions for IOC extraction
        patterns = {
            # More restrictive domain pattern - must have valid TLD and not be a method call
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|co|io|tk|cc|me|info|biz|name|tv|ws|mobi|asia|tel|jobs|travel|museum|aero|coop|pro|xxx|onion|ml|cf)\b',
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'url': r'https?://[^\s<>"\']+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'crypto_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|0x[a-fA-F0-9]{40}|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        }
        
        # Extract IOCs from all signals
        for signal in self.signals:
            # Extract from evidence
            if signal.evidence:
                self._extract_from_text(signal.evidence, patterns, iocs)
            
            # Extract from locations/code snippets
            if signal.locations:
                for location in signal.locations:
                    if hasattr(location, 'code_snippet') and location.code_snippet:
                        self._extract_from_text(location.code_snippet, patterns, iocs)
            
            # Extract signal-specific IOCs
            if signal.signal_type == SignalType.CRYPTOJACKING:
                # Look for mining pools and convert to appropriate format
                if 'pool' in signal.evidence.lower():
                    # Extract mining pool addresses with ports
                    pool_matches = re.findall(r'([a-zA-Z0-9.-]+\.(?:com|org|net|io|tk))(?::(\d+))?', signal.evidence)
                    for domain, port in pool_matches:
                        iocs['domains'].add(domain)
                        if port:
                            # Create URL for pool with port
                            iocs['urls'].add(f"stratum+tcp://{domain}:{port}")
            
            elif signal.signal_type == SignalType.NETWORK_ACTIVITY:
                # Extract network-related IOCs from hostname patterns
                hostname_matches = re.findall(r"hostname['\"]?\s*:\s*['\"]([^'\"]+)['\"]", signal.evidence)
                for hostname in hostname_matches:
                    if self._is_valid_domain(hostname):
                        iocs['domains'].add(hostname)
                    elif self._is_valid_ip(hostname):
                        iocs['ips'].add(hostname)
        
        # ENHANCED: Direct file content scanning for IOCs (even when no signals exist)
        if package_path:
            self._scan_package_files_for_iocs(package_path, patterns, iocs)
        
        # Extract binary file hashes from trust indicators if available
        if hasattr(self, 'llm_context') and self.llm_context:
            package_summary = self.llm_context.get('package_summary', {})
            trust_indicators = package_summary.get('trust_indicators', {})
            binary_info = trust_indicators.get('no_binary_files', {})
            
            # If binary files are present and have detailed information
            if isinstance(binary_info, dict) and 'binary_files' in binary_info:
                for binary_file in binary_info['binary_files']:
                    if binary_file.get('sha256') and binary_file['sha256'] != "hash_calculation_failed":
                        # Format: filename:hash:size for easy identification
                        hash_entry = f"{binary_file['name']}:{binary_file['sha256']}:{binary_file['size']}"
                        iocs['binary_file_hashes'].add(hash_entry)
        
        # Convert sets to sorted lists for JSON serialization
        return {k: sorted(list(v)) if v else [] for k, v in iocs.items()}
    
    def _is_valid_domain(self, hostname: str) -> bool:
        """Check if hostname is a valid domain name."""
        import re
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|co|io|tk|cc|me|info|biz|name|tv|ws|mobi|asia|tel|jobs|travel|museum|aero|coop|pro|xxx|onion)$'
        return bool(re.match(domain_pattern, hostname, re.IGNORECASE))
    
    def _is_valid_ip(self, hostname: str) -> bool:
        """Check if hostname is a valid IP address."""
        import re
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, hostname):
            # Validate IP ranges
            parts = hostname.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def _extract_from_text(self, text: str, patterns: Dict[str, str], iocs: Dict[str, set]):
        """Extract IOCs from text using regex patterns."""
        import re
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                if ioc_type == 'domain':
                    # Filter out common false positives and validate domains
                    for match in matches:
                        # Skip obvious non-domains
                        if any(fp in match.lower() for fp in ['example.com', 'localhost', 'test.com']):
                            continue
                        # Skip if it contains method-like patterns
                        if '(' in match or ')' in match or match.count('.') > 3:
                            continue
                        # Additional validation using helper method
                        if self._is_valid_domain(match):
                            iocs['domains'].add(match)
                
                elif ioc_type == 'ip':
                    # Filter out private/local IPs and validate
                    for match in matches:
                        if self._is_valid_ip(match) and not self._is_private_ip(match):
                            iocs['ips'].add(match)
                
                elif ioc_type == 'url':
                    # Clean and validate URLs
                    for match in matches:
                        if '://' in match and not any(fp in match.lower() for fp in ['example.com', 'localhost']):
                            iocs['urls'].add(match)
                
                elif ioc_type == 'email':
                    # Filter out obvious test/placeholder emails
                    for match in matches:
                        if not any(fp in match.lower() for fp in ['example.com', 'test.com', 'dummy', 'placeholder']):
                            iocs['email_addresses'].add(match)
                
                elif ioc_type == 'crypto_address':
                    # Add all crypto addresses (they're already validated by regex)
                    iocs['cryptocurrency_addresses'].update(matches)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/local ranges."""
        return (ip.startswith('192.168.') or ip.startswith('10.') or 
                ip.startswith('172.') or ip.startswith('127.') or 
                ip == '0.0.0.0' or ip == '255.255.255.255')
    
    def _scan_package_files_for_iocs(self, package_path: str, patterns: Dict[str, str], iocs: Dict[str, set]):
        """Scan package files directly for IOCs, even when no signals exist."""
        import logging
        from pathlib import Path
        import re
        
        logger = logging.getLogger(__name__)
        logger.info(f"\033[1;35mScanning package files directly for IOCs...\033[0m")
        
        try:
            package_dir = Path(package_path)
            if not package_dir.exists():
                return
            
            # File extensions to scan for IOCs
            scannable_extensions = {'.js', '.ts', '.py', '.json', '.txt', '.md', '.yml', '.yaml', '.sh', '.bat', '.ps1'}
            files_scanned = 0
            iocs_found = 0
            
            # Recursively scan all relevant files
            for file_path in package_dir.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in scannable_extensions:
                    try:
                        # Skip binary files and very large files
                        if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
                            continue
                        
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        files_scanned += 1
                        
                        # Count IOCs before extraction
                        initial_ioc_count = sum(len(ioc_set) for ioc_set in iocs.values())
                        
                        # Extract IOCs from file content
                        self._extract_from_text(content, patterns, iocs)
                        
                        # Check for specific C2 server patterns
                        self._extract_c2_servers(content, iocs)
                        
                        # Count IOCs after extraction
                        final_ioc_count = sum(len(ioc_set) for ioc_set in iocs.values())
                        
                        if final_ioc_count > initial_ioc_count:
                            new_iocs = final_ioc_count - initial_ioc_count
                            iocs_found += new_iocs
                            logger.info(f"\033[1;33mFound {new_iocs} IOCs in {file_path.name}\033[0m")
                        
                    except (OSError, IOError, UnicodeDecodeError) as e:
                        logger.debug(f"Could not read file {file_path}: {e}")
                        continue
            
            total_iocs = sum(len(ioc_set) for ioc_set in iocs.values())
            logger.info(f"\033[1;32mDirect file scan complete: {files_scanned} files scanned, {total_iocs} total IOCs found\033[0m")
            
        except Exception as e:
            logger.error(f"Error scanning package files for IOCs: {e}")
    
    def _extract_c2_servers(self, content: str, iocs: Dict[str, set]):
        """Extract C2 servers and related network indicators from content."""
        import re
        
        # Specific patterns for C2 servers
        c2_patterns = [
            # Domain:port format (common in backdoors)
            r'([a-zA-Z0-9.-]+\.(tk|ml|cf|com|org|net|io|cc|me)):(\d+)',
            # IP:port format
            r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\d+)',
            # URL format for C2
            r'https?://([a-zA-Z0-9.-]+\.(tk|ml|cf|com|org|net|io))',
            # Configuration object patterns
            r'c2_servers?\s*:\s*\[([^\]]+)\]',
            r'command[_-]?(?:and[_-]?)?control\s*:\s*[\'"]([^\'"]+)[\'"]',
            r'(?:evil|malicious|backup)[_-]?(?:server|c2)\s*[\.:\=]\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in c2_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match.groups()) >= 1:
                    # Extract domain/IP and port if available
                    server = match.group(1)
                    
                    # Validate and categorize
                    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', server):
                        # IP address
                        if self._is_valid_ip(server) and not self._is_private_ip(server):
                            iocs['ips'].add(server)
                    else:
                        # Domain
                        if self._is_valid_domain(server):
                            iocs['domains'].add(server)
                    
                    # If there's a port, create a full server:port entry in URLs
                    if len(match.groups()) >= 3 and match.group(3):
                        port = match.group(3)
                        full_address = f"{server}:{port}"
                        # Store as custom URL format for C2 servers
                        iocs['urls'].add(f"tcp://{full_address}")
        
        # Look for quoted C2 server lists (like in the backdoor sample)
        c2_list_pattern = r'[\'""]([a-zA-Z0-9.-]+\.(tk|ml|cf|com|org|net|io)):(\d+)[\'""]'
        matches = re.finditer(c2_list_pattern, content, re.IGNORECASE)
        for match in matches:
            domain = match.group(1)
            port = match.group(3)
            if self._is_valid_domain(domain):
                iocs['domains'].add(domain)
                iocs['urls'].add(f"tcp://{domain}:{port}")
    

class SignalCollector(ABC):
    """Abstract base class for signal collectors."""
    
    @abstractmethod
    def collect_signals(self, package_path: str, package_metadata: PackageMetadata) -> List[Signal]:
        """Collect signals from package analysis."""
        pass
    
    @abstractmethod
    def get_supported_ecosystems(self) -> List[Ecosystem]:
        """Return supported ecosystems."""
        pass

class OpenGrepSignalCollector(SignalCollector):
    """Signal collector using OpenGrep/Semgrep rules."""
    
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.logger = logging.getLogger(__name__)
        
        # Ecosystem-specific rule directories
        self.ecosystem_rules = {
            Ecosystem.NPM: self.rules_path / "npm",
            Ecosystem.PYPI: self.rules_path / "pypi",
            Ecosystem.VSIX: self.rules_path / "vsix"
        }
    
    def get_supported_ecosystems(self) -> List[Ecosystem]:
        return [Ecosystem.NPM, Ecosystem.PYPI, Ecosystem.VSIX]
    
    def collect_signals(self, package_path: str, package_metadata: PackageMetadata) -> List[Signal]:
        """Collect signals using OpenGrep rules for the specific ecosystem."""
        try:
            self.logger.info(f"\033[1;35mStarting OpenGrep signal collection for {package_metadata.ecosystem.value}\033[0m")
            
            # Get ecosystem-specific rules
            rule_path = self.ecosystem_rules.get(package_metadata.ecosystem)
            if not rule_path or not rule_path.exists():
                self.logger.warning(f"No rules found for ecosystem {package_metadata.ecosystem}")
                return []
            
            # Count available rules
            rule_files = list(rule_path.glob("*.yaml")) + list(rule_path.glob("*.yml"))
            self.logger.info(f"\033[1;37mFound {len(rule_files)} OpenGrep rule files in {rule_path}\033[0m")
            
            # Handle VSIX files - extract to temporary directory for analysis
            if package_metadata.ecosystem == Ecosystem.VSIX and Path(package_path).is_file() and package_path.endswith('.vsix'):
                return self._collect_vsix_signals_with_npm_rules(package_path, rule_path, package_metadata)
            
            # Run semgrep with ecosystem-specific rules
            self.logger.info(f"\033[1;33mExecuting semgrep analysis on {package_path}\033[0m")
            sarif_results = self._run_semgrep(package_path, rule_path)
            
            # Convert SARIF results to signals
            self.logger.info(f"\033[1;37mConverting SARIF results to signals\033[0m")
            signals = self._convert_sarif_to_signals(sarif_results, package_metadata.ecosystem)
            
            # If semgrep failed, log error but don't use manual fallback
            if len(signals) == 0 and (not sarif_results or 'runs' not in sarif_results):
                self.logger.error(f"\033[1;31mSemgrep analysis failed to produce results - check semgrep installation\033[0m")
            
            self.logger.info(f"\033[1;32mOpenGrep analysis complete: {len(signals)} signals detected\033[0m")
            return signals
            
        except Exception as e:
            self.logger.error(f"Error collecting OpenGrep signals: {e}")
            return []
    
    def _collect_vsix_signals_with_npm_rules(self, vsix_path: str, vsix_rules_path: Path, package_metadata: PackageMetadata) -> List[Signal]:
        """Extract VSIX file and run OpenGrep analysis using both VSIX and NPM rules."""
        import zipfile
        import shutil
        
        # Create extraction directory next to the VSIX file
        vsix_file_path = Path(vsix_path)
        extract_dir_name = f"{vsix_file_path.stem}_extracted"
        extract_path = vsix_file_path.parent / extract_dir_name
        
        try:
            # Remove existing extraction directory if it exists
            if extract_path.exists():
                shutil.rmtree(extract_path)
            
            # Create extraction directory
            extract_path.mkdir(exist_ok=True)
            
            # Extract VSIX file to local directory
            self.logger.info(f"\033[1;33mExtracting VSIX file for analysis: {vsix_path} -> {extract_path}\033[0m")
            
            with zipfile.ZipFile(vsix_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            all_signals = []
            
            # 1. Run VSIX-specific rules
            self.logger.info(f"\033[1;33mExecuting VSIX-specific semgrep analysis\033[0m")
            vsix_sarif_results = self._run_semgrep(str(extract_path), vsix_rules_path)
            vsix_signals = self._convert_sarif_to_signals(vsix_sarif_results, package_metadata.ecosystem)
            all_signals.extend(vsix_signals)
            self.logger.info(f"\033[1;36mVSIX-specific rules: {len(vsix_signals)} signals detected\033[0m")
            
            # 2. Run NPM JavaScript rules (since VSIX contains JS/TS code)
            npm_rules_path = self.ecosystem_rules.get(Ecosystem.NPM)
            if npm_rules_path and npm_rules_path.exists():
                self.logger.info(f"\033[1;33mExecuting NPM JavaScript rules on VSIX content\033[0m")
                npm_sarif_results = self._run_semgrep(str(extract_path), npm_rules_path)
                npm_signals = self._convert_sarif_to_signals(npm_sarif_results, Ecosystem.NPM)  # Keep as NPM for rule classification
                all_signals.extend(npm_signals)
                self.logger.info(f"\033[1;36mNPM JavaScript rules: {len(npm_signals)} additional signals detected\033[0m")
            else:
                self.logger.warning(f"NPM rules not found at {npm_rules_path}")
            
            # Remove duplicate signals (same rule + same location)
            unique_signals = self._deduplicate_overlapping_signals(all_signals)
            removed_count = len(all_signals) - len(unique_signals)
            if removed_count > 0:
                self.logger.info(f"\033[1;33mRemoved {removed_count} duplicate signals\033[0m")
            
            # Update signal locations to reference original VSIX file
            for signal in unique_signals:
                for location in signal.locations:
                    if hasattr(location, 'file_path') and location.file_path:
                        try:
                            # Replace extract path with original VSIX path reference
                            rel_path = Path(location.file_path).relative_to(extract_path)
                            location.file_path = f"{vsix_path}::{rel_path}"
                        except ValueError:
                            # If relative_to fails, just use the original path
                            pass
            
            self.logger.info(f"\033[1;32mCombined VSIX+NPM analysis complete: {len(unique_signals)} total signals detected\033[0m")
            return unique_signals
                
        except Exception as e:
            self.logger.error(f"Error analyzing VSIX file: {e}")
            return []
            
        finally:
            # Clean up extracted directory
            if extract_path.exists():
                try:
                    shutil.rmtree(extract_path)
                    self.logger.info(f"\033[1;37mCleaned up extraction directory: {extract_path}\033[0m")
                except Exception as cleanup_error:
                    self.logger.warning(f"Failed to clean up extraction directory {extract_path}: {cleanup_error}")
    
    def _run_semgrep(self, package_path: str, rules_path: Path) -> Dict[str, Any]:
        """Run semgrep with specified rules and return SARIF results."""
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.sarif', delete=False) as sarif_file:
            try:
                cmd = [
                    'semgrep',
                    '--config', str(rules_path),
                    '--sarif',
                    '--output', sarif_file.name,
                    '--timeout', '30',
                    '--max-memory', '2048',
                    package_path
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode not in [0, 1]:  # 0 = no findings, 1 = findings found
                    self.logger.warning(f"Semgrep returned code {result.returncode}: {result.stderr}")
                
                # Read SARIF results
                sarif_file.seek(0)
                with open(sarif_file.name, 'r') as f:
                    return json.load(f)
                    
            except subprocess.TimeoutExpired:
                self.logger.error("Semgrep execution timed out")
                return {}
            except Exception as e:
                self.logger.error(f"Error running semgrep: {e}")
                return {}
            finally:
                if os.path.exists(sarif_file.name):
                    os.unlink(sarif_file.name)
    
    def _convert_sarif_to_signals(self, sarif_data: Dict[str, Any], ecosystem: Ecosystem) -> List[Signal]:
        """Convert SARIF results to Signal objects."""
        signals = []
        
        if not sarif_data or 'runs' not in sarif_data:
            return signals
        
        for run in sarif_data['runs']:
            if 'results' not in run:
                continue
                
            for result in run['results']:
                try:
                    signal = self._create_signal_from_sarif_result(result, ecosystem)
                    if signal:
                        signals.append(signal)
                except Exception as e:
                    self.logger.error(f"Error converting SARIF result to signal: {e}")
        
        # Deduplicate overlapping signals from the same rule
        deduplicated_signals = self._deduplicate_overlapping_signals(signals)
        
        if len(signals) != len(deduplicated_signals):
            removed_count = len(signals) - len(deduplicated_signals)
            self.logger.info(f"\033[1;33mRemoved {removed_count} duplicate/overlapping signals\033[0m")
        
        return deduplicated_signals
    
    def _create_signal_from_sarif_result(self, sarif_result: Dict[str, Any], ecosystem: Ecosystem) -> Optional[Signal]:
        """Create a Signal from a SARIF result."""
        try:
            rule_id = sarif_result.get('ruleId', 'unknown')
            message = sarif_result.get('message', {}).get('text', 'No message')
            
            # Extract rule metadata
            rule_metadata = {}
            if 'rule' in sarif_result:
                rule_metadata = sarif_result['rule'].get('properties', {})
            
            # Determine signal type from rule ID and metadata
            signal_type = self._determine_signal_type(rule_id, rule_metadata)
            
            # Determine severity
            severity = self._map_sarif_severity(sarif_result.get('level', 'info'))
            
            # Extract locations
            locations = []
            for location in sarif_result.get('locations', []):
                if 'physicalLocation' in location:
                    phys_loc = location['physicalLocation']
                    loc = SignalLocation(
                        file_path=phys_loc.get('artifactLocation', {}).get('uri', ''),
                        line_start=phys_loc.get('region', {}).get('startLine', 0),
                        line_end=phys_loc.get('region', {}).get('endLine', 0),
                        column_start=phys_loc.get('region', {}).get('startColumn', 0),
                        column_end=phys_loc.get('region', {}).get('endColumn', 0),
                        code_snippet=phys_loc.get('region', {}).get('snippet', {}).get('text', '')
                    )
                    locations.append(loc)
            
            # Extract confidence from metadata
            confidence = rule_metadata.get('confidence', 0.5)
            if isinstance(confidence, str):
                confidence_map = {'LOW': 0.3, 'MEDIUM': 0.6, 'HIGH': 0.9}
                confidence = confidence_map.get(confidence.upper(), 0.5)
            
            # Create signal
            signal = Signal(
                signal_id=f"{ecosystem.value}_{rule_id}_{hash(message) % 10000}",
                signal_type=signal_type,
                severity=severity,
                confidence=confidence,
                title=f"Malware Pattern: {rule_id}",
                description=message,
                evidence=self._extract_evidence(sarif_result),
                locations=locations,
                tags=rule_metadata.get('tags', []),
                references=rule_metadata.get('references', []),
                metadata={
                    'rule_id': rule_id,
                    'ecosystem': ecosystem.value,
                    'sarif_level': sarif_result.get('level', 'info'),
                    **rule_metadata
                }
            )
            
            return signal
            
        except Exception as e:
            self.logger.error(f"Error creating signal from SARIF result: {e}")
            return None
    
    def _deduplicate_overlapping_signals(self, signals: List[Signal]) -> List[Signal]:
        """Remove duplicate and overlapping signals from the same rule."""
        if not signals:
            return signals
        
        # Group signals by rule_id and file_path for deduplication
        signal_groups = {}
        for signal in signals:
            rule_id = signal.metadata.get('rule_id', 'unknown')
            
            # Handle signals with multiple locations
            if signal.locations:
                for location in signal.locations:
                    key = (rule_id, location.file_path, location.line_start, location.line_end)
                    if key not in signal_groups:
                        signal_groups[key] = []
                    signal_groups[key].append((signal, location))
            else:
                # Handle signals without locations
                key = (rule_id, 'no_location', 0, 0)
                if key not in signal_groups:
                    signal_groups[key] = []
                signal_groups[key].append((signal, None))
        
        deduplicated = []
        processed_signals = set()
        
        # Group by rule and file for overlap detection
        rule_file_groups = {}
        for key, signal_location_pairs in signal_groups.items():
            rule_id, file_path, _, _ = key
            rule_file_key = (rule_id, file_path)
            
            if rule_file_key not in rule_file_groups:
                rule_file_groups[rule_file_key] = []
            rule_file_groups[rule_file_key].extend(signal_location_pairs)
        
        for rule_file_key, signal_location_pairs in rule_file_groups.items():
            if len(signal_location_pairs) == 1:
                # No potential duplicates for this rule+file combination
                signal, _ = signal_location_pairs[0]
                if id(signal) not in processed_signals:
                    deduplicated.append(signal)
                    processed_signals.add(id(signal))
                continue
            
            # Sort by line range and column range to process in order
            signal_location_pairs.sort(key=lambda x: (
                x[1].line_start if x[1] else 0,
                x[1].line_end if x[1] else 0,
                x[1].column_start if x[1] else 0,
                x[1].column_end if x[1] else 0
            ))
            
            # Keep track of which signals to include (avoid overlaps)
            signals_to_keep = []
            
            for signal, location in signal_location_pairs:
                is_overlapping = False
                
                # Check if this signal overlaps with any already kept signal
                for kept_signal, kept_location in signals_to_keep:
                    if location and kept_location and self._locations_overlap(location, kept_location):
                        # If they overlap, keep the one with larger range (more comprehensive)
                        if self._get_location_range(location) > self._get_location_range(kept_location):
                            # Replace the kept signal with this one
                            signals_to_keep = [(s, l) for s, l in signals_to_keep if s != kept_signal]
                            signals_to_keep.append((signal, location))
                        is_overlapping = True
                        break
                
                if not is_overlapping:
                    signals_to_keep.append((signal, location))
            
            # Add the deduplicated signals
            for signal, _ in signals_to_keep:
                if id(signal) not in processed_signals:
                    deduplicated.append(signal)
                    processed_signals.add(id(signal))
        
        return deduplicated
    
    def _locations_overlap(self, loc1: SignalLocation, loc2: SignalLocation) -> bool:
        """Check if two signal locations overlap."""
        if not loc1 or not loc2:
            return False
            
        # Same line with overlapping columns
        if loc1.line_start == loc2.line_start and loc1.line_end == loc2.line_end:
            # Check column overlap
            col_overlap = not (loc1.column_end < loc2.column_start or loc2.column_end < loc1.column_start)
            return col_overlap
        
        # Overlapping line ranges
        line_overlap = not (loc1.line_end < loc2.line_start or loc2.line_end < loc1.line_start)
        return line_overlap
    
    def _get_location_range(self, location: SignalLocation) -> int:
        """Get the character range size of a location."""
        if not location:
            return 0
            
        line_range = max(1, location.line_end - location.line_start + 1)
        col_range = max(1, location.column_end - location.column_start + 1)
        return line_range * 1000 + col_range  # Prioritize line range over column range
    
    def _determine_signal_type(self, rule_id: str, metadata: Dict[str, Any]) -> SignalType:
        """Determine signal type from rule ID and metadata."""
        rule_id_lower = rule_id.lower()
        
        if 'obfuscat' in rule_id_lower or 'entropy' in rule_id_lower:
            return SignalType.OBFUSCATION
        elif 'network' in rule_id_lower or 'http' in rule_id_lower or 'request' in rule_id_lower:
            return SignalType.NETWORK_ACTIVITY
        elif 'file' in rule_id_lower or 'fs' in rule_id_lower:
            return SignalType.FILE_OPERATIONS
        elif 'crypto' in rule_id_lower or 'mining' in rule_id_lower:
            return SignalType.CRYPTOJACKING
        elif 'supply' in rule_id_lower or 'typo' in rule_id_lower:
            return SignalType.SUPPLY_CHAIN_RISK
        elif 'behavior' in rule_id_lower or 'anomal' in rule_id_lower:
            return SignalType.BEHAVIORAL_ANOMALY
        else:
            return SignalType.MALWARE_PATTERN
    
    def _map_sarif_severity(self, sarif_level: str) -> Severity:
        """Map SARIF severity level to our Severity enum."""
        mapping = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
            'note': Severity.INFO
        }
        return mapping.get(sarif_level.lower(), Severity.INFO)
    
    def _extract_evidence(self, sarif_result: Dict[str, Any]) -> str:
        """Extract evidence text from SARIF result."""
        evidence_parts = []
        
        # Main message
        message = sarif_result.get('message', {}).get('text', '')
        if message:
            evidence_parts.append(f"Detection: {message}")
        
        # Code snippets
        for location in sarif_result.get('locations', []):
            snippet = location.get('physicalLocation', {}).get('region', {}).get('snippet', {}).get('text', '')
            if snippet:
                evidence_parts.append(f"Code: {snippet}")
        
        return " | ".join(evidence_parts)

class MetadataSignalCollector(SignalCollector):
    """Collector for package metadata-based signals."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_supported_ecosystems(self) -> List[Ecosystem]:
        return [Ecosystem.NPM, Ecosystem.PYPI, Ecosystem.VSIX]
    
    def collect_signals(self, package_path: str, package_metadata: PackageMetadata) -> List[Signal]:
        """Collect metadata-based signals."""
        signals = []
        self.logger.info(f"Starting metadata signal collection for package: {package_metadata.name}")
        
        # Suspicious package name patterns with ecosystem-specific dynamic popular packages check
        ecosystem_name = package_metadata.ecosystem.value if hasattr(package_metadata.ecosystem, 'value') else str(package_metadata.ecosystem)
        self.logger.info(f"Analyzing package name for typosquatting against top 150 popular {ecosystem_name} packages...")
        is_suspicious, matches = self._is_suspicious_package_name(package_metadata.name, ecosystem=ecosystem_name)
        
        if is_suspicious:
            self.logger.warning(f"Suspicious package name detected: {package_metadata.name}")
            
            # Create detailed evidence with matching information
            if matches:
                evidence_parts = [f"Package name: {package_metadata.name}"]
                evidence_parts.append(f"Potential typosquats detected ({len(matches)} matches):")
                
                for i, match in enumerate(matches[:5], 1):  # Show top 5 matches
                    evidence_parts.append(
                        f"{i}. {match['target_package']} ({match['ecosystem']}) - "
                        f"{match['download_count']:,} downloads - "
                        f"detected via {match['algorithm']}"
                    )
                
                if len(matches) > 5:
                    evidence_parts.append(f"... and {len(matches) - 5} more matches")
                
                evidence = "\n".join(evidence_parts)
                
                # Enhanced metadata with all match details
                metadata = {
                    'package_name': package_metadata.name,
                    'matches': matches,
                    'total_matches': len(matches),
                    'highest_download_target': matches[0] if matches else None
                }
            else:
                evidence = f"Package name: {package_metadata.name} (suspicious pattern detected)"
                metadata = {'package_name': package_metadata.name}
            
            signals.append(Signal(
                signal_id=f"metadata_suspicious_name_{hash(package_metadata.name) % 10000}",
                signal_type=SignalType.SUPPLY_CHAIN_RISK,
                severity=Severity.HIGH if matches else Severity.MEDIUM,
                confidence=0.9 if matches else 0.7,
                title="Suspicious Package Name - Potential Typosquatting",
                description=f"Package name '{package_metadata.name}' matches suspicious patterns or popular package names",
                evidence=evidence,
                locations=[],
                tags=["typosquatting", "name-confusion", "supply-chain"],
                references=[],
                metadata=metadata
            ))
        else:
            self.logger.info(f"Package name appears legitimate: {package_metadata.name}")
        
        # Recently created packages with high-risk patterns
        if self._is_recently_created_high_risk(package_metadata):
            signals.append(Signal(
                signal_id=f"metadata_recent_high_risk_{hash(package_metadata.name) % 10000}",
                signal_type=SignalType.SUPPLY_CHAIN_RISK,
                severity=Severity.HIGH,
                confidence=0.8,
                title="Recently Created High-Risk Package",
                description="Package was recently created and shows high-risk characteristics",
                evidence=f"Created: {package_metadata.publish_date}, Downloads: {package_metadata.download_count}",
                locations=[],
                tags=["recent-package", "supply-chain"],
                references=[],
                metadata={'publish_date': package_metadata.publish_date}
            ))
        
        # Suspicious install scripts
        if package_metadata.ecosystem == Ecosystem.NPM:
            self.logger.info(f"Checking npm install scripts for suspicious patterns...")
            suspicious_scripts = self._check_suspicious_npm_scripts(package_metadata.scripts)
            if suspicious_scripts:
                self.logger.warning(f"Found {len(suspicious_scripts)} suspicious scripts")
                for script_name, script_content in suspicious_scripts:
                    self.logger.warning(f"Suspicious script detected: {script_name}")
                    signals.append(Signal(
                        signal_id=f"metadata_suspicious_script_{hash(script_name) % 10000}",
                        signal_type=SignalType.BEHAVIORAL_ANOMALY,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        title=f"Suspicious {script_name} Script",
                        description=f"The {script_name} script contains potentially dangerous commands",
                        evidence=f"Script: {script_content}",
                        locations=[],
                        tags=["install-script", "dangerous-commands"],
                        references=[],
                        metadata={'script_name': script_name, 'script_content': script_content}
                    ))
            else:
                self.logger.info(f"No suspicious scripts found")
        
        # Enhanced package analysis using comprehensive registry data
        if package_metadata.ecosystem == Ecosystem.NPM:
            enhanced_signals = self._analyze_npm_package_enhanced(package_metadata)
            signals.extend(enhanced_signals)
        elif package_metadata.ecosystem == Ecosystem.PYPI:
            enhanced_signals = self._analyze_pypi_package_enhanced(package_metadata)
            signals.extend(enhanced_signals)
        
        self.logger.info(f"Metadata analysis complete: {len(signals)} signals detected")
        return signals
    
    def _is_suspicious_package_name(self, name: str, ecosystem: str = None) -> Tuple[bool, List[Dict]]:
        """Check if package name is suspicious using ecosystem-specific typosquatting detection."""
        is_typosquat, matches = self._detect_typosquatting(name, ecosystem=ecosystem)
        is_suspicious_pattern = self._detect_suspicious_patterns(name)
        
        # Store matches for later use in signal creation
        self._typosquatting_matches = matches
        
        return is_typosquat or is_suspicious_pattern, matches
    
    def _analyze_npm_package_enhanced(self, package_metadata: 'PackageMetadata') -> List['Signal']:
        """Enhanced npm package analysis using comprehensive registry API data."""
        signals = []
        
        try:
            self.logger.info(f"Starting enhanced npm analysis for {package_metadata.name}")
            
            # Import the enhanced fetcher
            try:
                from .popular_packages_fetcher import PopularPackagesFetcher
            except ImportError:
                from popular_packages_fetcher import PopularPackagesFetcher
            fetcher = PopularPackagesFetcher()
            
            # Get comprehensive package details
            package_details = fetcher.get_npm_package_details(package_metadata.name)
            if not package_details:
                self.logger.warning(f"Could not fetch enhanced package details for {package_metadata.name}")
                return signals
            
            # Analyze download trends for suspicious patterns
            download_trends = fetcher.get_npm_download_trends(package_metadata.name)
            if download_trends and 'error' not in download_trends:
                signals.extend(self._analyze_download_patterns(package_metadata, download_trends))
            
            # Analyze maintainer and dependency patterns
            signals.extend(self._analyze_package_metadata_enhanced(package_metadata, package_details))
            
            # Analyze version history patterns
            signals.extend(self._analyze_version_patterns(package_metadata, package_details))
            
            self.logger.info(f"Enhanced npm analysis complete: {len(signals)} additional signals detected")
            
        except Exception as e:
            self.logger.error(f"Enhanced npm analysis failed for {package_metadata.name}: {e}")
        
        return signals
    
    def _analyze_download_patterns(self, package_metadata: 'PackageMetadata', download_trends: Dict) -> List['Signal']:
        """Analyze download patterns for suspicious behavior."""
        signals = []
        
        try:
            # Check for suspicious download spikes
            suspicious_spikes = download_trends.get('suspicious_spikes', {})
            if suspicious_spikes.get('suspicious', False):
                signals.append(Signal(
                    signal_id=f"enhanced_download_spikes_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Suspicious Download Spike Pattern",
                    description="Package shows unusual download spikes that may indicate artificial inflation",
                    evidence=f"Detected {suspicious_spikes.get('spike_count', 0)} suspicious spikes. "
                             f"Average downloads: {suspicious_spikes.get('avg_downloads', 0):,.0f}, "
                             f"Standard deviation: {suspicious_spikes.get('std_deviation', 0):,.0f}",
                    locations=[],
                    tags=["download-anomaly", "artificial-inflation"],
                    references=[],
                    metadata={
                        'spike_count': suspicious_spikes.get('spike_count', 0),
                        'avg_downloads': suspicious_spikes.get('avg_downloads', 0),
                        'spikes': suspicious_spikes.get('spikes', [])
                    }
                ))
            
            # Check for unnatural download consistency
            consistency_analysis = download_trends.get('consistent_growth', {})
            if consistency_analysis.get('suspicious_uniformity', False):
                signals.append(Signal(
                    signal_id=f"enhanced_download_uniformity_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="Unnatural Download Uniformity",
                    description="Package shows suspiciously uniform download patterns suggesting bot activity",
                    evidence=f"Variance ratio: {consistency_analysis.get('variance_ratio', 0):.2f}, "
                             f"Zero variance days: {consistency_analysis.get('zero_variance_days', 0)}/{consistency_analysis.get('total_days', 0)}",
                    locations=[],
                    tags=["download-anomaly", "bot-activity"],
                    references=[],
                    metadata=consistency_analysis
                ))
                
        except Exception as e:
            self.logger.error(f"Download pattern analysis failed: {e}")
        
        return signals
    
    def _analyze_package_metadata_enhanced(self, package_metadata: 'PackageMetadata', package_details: Dict) -> List['Signal']:
        """Analyze enhanced package metadata for security risks."""
        signals = []
        
        try:
            # Check for suspicious dependency patterns
            dependencies = package_details.get('dependencies', {})
            if dependencies:
                suspicious_deps = self._detect_suspicious_dependencies(dependencies)
                if suspicious_deps:
                    signals.append(Signal(
                        signal_id=f"enhanced_suspicious_deps_{hash(package_metadata.name) % 10000}",
                        signal_type=SignalType.SUPPLY_CHAIN,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        title="Suspicious Dependencies Detected",
                        description="Package has dependencies that match suspicious patterns",
                        evidence=f"Found {len(suspicious_deps)} suspicious dependencies: {', '.join(suspicious_deps[:5])}",
                        locations=[],
                        tags=["suspicious-dependencies", "supply-chain"],
                        references=[],
                        metadata={'suspicious_dependencies': suspicious_deps}
                    ))
            
            # Check for executable binaries
            bin_files = package_details.get('bin', {})
            if bin_files:
                signals.append(Signal(
                    signal_id=f"enhanced_binary_files_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="Package Contains Executable Binaries",
                    description="Package includes executable binary files which require careful review",
                    evidence=f"Binary executables: {', '.join(bin_files.keys())}",
                    locations=[],
                    tags=["binary-files", "executables"],
                    references=[],
                    metadata={'binary_files': bin_files}
                ))
            
            # Check for missing or suspicious license
            license_info = package_details.get('license', '')
            if not license_info or license_info.lower() in ['none', 'unlicensed', 'proprietary']:
                signals.append(Signal(
                    signal_id=f"enhanced_license_missing_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.METADATA_INCONSISTENCY,
                    severity=Severity.LOW,
                    confidence=0.5,
                    title="Missing or Suspicious License",
                    description="Package has no license or suspicious license terms",
                    evidence=f"License: {license_info or 'Not specified'}",
                    locations=[],
                    tags=["license-issues", "legal-risk"],
                    references=[],
                    metadata={'license': license_info}
                ))
                
        except Exception as e:
            self.logger.error(f"Enhanced metadata analysis failed: {e}")
        
        return signals
    
    def _analyze_version_patterns(self, package_metadata: 'PackageMetadata', package_details: Dict) -> List['Signal']:
        """Analyze version history patterns for suspicious behavior."""
        signals = []
        
        try:
            versions_count = package_details.get('versions_count', 0)
            created_date = package_details.get('created', '')
            modified_date = package_details.get('modified', '')
            
            # Check for rapid version releases (potential version spam)
            if versions_count > 50:
                from datetime import datetime, timedelta
                try:
                    created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                    modified = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                    age_days = (modified - created).days
                    
                    if age_days > 0:
                        versions_per_day = versions_count / age_days
                        if versions_per_day > 2:  # More than 2 versions per day on average
                            signals.append(Signal(
                                signal_id=f"enhanced_version_spam_{hash(package_metadata.name) % 10000}",
                                signal_type=SignalType.BEHAVIORAL_ANOMALY,
                                severity=Severity.MEDIUM,
                                confidence=0.7,
                                title="Excessive Version Releases",
                                description="Package has an unusually high number of version releases",
                                evidence=f"{versions_count} versions in {age_days} days ({versions_per_day:.1f} versions/day)",
                                locations=[],
                                tags=["version-spam", "rapid-releases"],
                                references=[],
                                metadata={
                                    'versions_count': versions_count,
                                    'age_days': age_days,
                                    'versions_per_day': versions_per_day
                                }
                            ))
                except:
                    pass  # Skip if date parsing fails
                    
        except Exception as e:
            self.logger.error(f"Version pattern analysis failed: {e}")
        
        return signals
    
    def _detect_suspicious_dependencies(self, dependencies: Dict) -> List[str]:
        """Detect suspicious dependency patterns."""
        suspicious = []
        
        # Common suspicious dependency patterns
        suspicious_patterns = [
            r'.*crypto.*miner.*', r'.*bitcoin.*', r'.*mining.*',
            r'.*backdoor.*', r'.*malware.*', r'.*virus.*',
            r'.*keylog.*', r'.*stealer.*', r'.*trojan.*'
        ]
        
        import re
        for dep_name in dependencies.keys():
            dep_lower = dep_name.lower()
            for pattern in suspicious_patterns:
                if re.match(pattern, dep_lower):
                    suspicious.append(dep_name)
                    break
        
        return suspicious
    
    def _analyze_pypi_package_enhanced(self, package_metadata: 'PackageMetadata') -> List['Signal']:
        """Enhanced PyPI package analysis using comprehensive PyPI API data."""
        signals = []
        
        try:
            self.logger.info(f"Starting enhanced PyPI analysis for {package_metadata.name}")
            
            # Import the enhanced fetcher
            try:
                from .popular_packages_fetcher import PopularPackagesFetcher
            except ImportError:
                from popular_packages_fetcher import PopularPackagesFetcher
            fetcher = PopularPackagesFetcher()
            
            # Get comprehensive package details
            package_details = fetcher.get_pypi_package_details(package_metadata.name)
            if not package_details:
                self.logger.warning(f"Could not fetch enhanced PyPI package details for {package_metadata.name}")
                return signals
            
            # Analyze PyPI-specific metadata patterns
            signals.extend(self._analyze_pypi_metadata_enhanced(package_metadata, package_details))
            
            # Analyze PyPI dependency patterns
            dependency_analysis = fetcher.analyze_pypi_dependencies(package_metadata.name)
            if dependency_analysis and dependency_analysis.get('suspicious_count', 0) > 0:
                signals.extend(self._create_pypi_dependency_signals(package_metadata, dependency_analysis))
            
            # Analyze version and release patterns
            signals.extend(self._analyze_pypi_version_patterns(package_metadata, package_details))
            
            self.logger.info(f"Enhanced PyPI analysis complete: {len(signals)} additional signals detected")
            
        except Exception as e:
            self.logger.error(f"Enhanced PyPI analysis failed for {package_metadata.name}: {e}")
        
        return signals
    
    def _analyze_pypi_metadata_enhanced(self, package_metadata: 'PackageMetadata', package_details: Dict) -> List['Signal']:
        """Analyze enhanced PyPI package metadata for security risks."""
        signals = []
        
        try:
            # Check for missing or suspicious license
            license_info = package_details.get('license', '')
            if not license_info or license_info.lower() in ['none', 'unlicensed', 'proprietary', '']:
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_license_missing_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.METADATA_INCONSISTENCY,
                    severity=Severity.LOW,
                    confidence=0.5,
                    title="Missing or Suspicious License",
                    description="PyPI package has no license or suspicious license terms",
                    evidence=f"License: {license_info or 'Not specified'}",
                    locations=[],
                    tags=["pypi-license-issues", "legal-risk"],
                    references=[],
                    metadata={'license': license_info}
                ))
            
            # Check for missing maintainer information
            author = package_details.get('author', '')
            author_email = package_details.get('author_email', '')
            maintainer = package_details.get('maintainer', '')
            maintainer_email = package_details.get('maintainer_email', '')
            
            if not any([author, author_email, maintainer, maintainer_email]):
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_no_maintainer_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.METADATA_INCONSISTENCY,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="Missing Maintainer Information",
                    description="PyPI package has no author or maintainer information",
                    evidence="No author, author_email, maintainer, or maintainer_email specified",
                    locations=[],
                    tags=["pypi-maintainer-missing", "trust-issue"],
                    references=[],
                    metadata={'missing_fields': ['author', 'author_email', 'maintainer', 'maintainer_email']}
                ))
            
            # Check for suspicious classifiers
            classifiers = package_details.get('classifiers', [])
            suspicious_classifiers = [c for c in classifiers if any(
                sus_term in c.lower() for sus_term in ['private', 'internal', 'malware', 'virus', 'hack']
            )]
            
            if suspicious_classifiers:
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_suspicious_classifiers_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Suspicious Package Classifiers",
                    description="PyPI package has suspicious classifiers",
                    evidence=f"Suspicious classifiers: {', '.join(suspicious_classifiers)}",
                    locations=[],
                    tags=["pypi-classifiers", "suspicious-metadata"],
                    references=[],
                    metadata={'suspicious_classifiers': suspicious_classifiers}
                ))
            
            # Check for missing cryptographic signatures
            has_signature = package_details.get('has_signature', False)
            if not has_signature:
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_no_signature_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.SECURITY_RISK,
                    severity=Severity.LOW,
                    confidence=0.4,
                    title="Package Not Cryptographically Signed",
                    description="PyPI package upload is not cryptographically signed",
                    evidence="Package has no digital signature (has_sig=False)",
                    locations=[],
                    tags=["pypi-no-signature", "integrity-risk"],
                    references=[],
                    metadata={'has_signature': has_signature}
                ))
                
        except Exception as e:
            self.logger.error(f"PyPI metadata analysis failed: {e}")
        
        return signals
    
    def _create_pypi_dependency_signals(self, package_metadata: 'PackageMetadata', dependency_analysis: Dict) -> List['Signal']:
        """Create signals for suspicious PyPI dependencies."""
        signals = []
        
        try:
            suspicious_deps = dependency_analysis.get('suspicious_dependencies', [])
            if suspicious_deps:
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_suspicious_deps_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title="Suspicious PyPI Dependencies Detected",
                    description="PyPI package has dependencies that match suspicious patterns",
                    evidence=f"Found {len(suspicious_deps)} suspicious dependencies: {', '.join(suspicious_deps[:5])}",
                    locations=[],
                    tags=["pypi-suspicious-dependencies", "supply-chain"],
                    references=[],
                    metadata={
                        'suspicious_dependencies': suspicious_deps,
                        'total_dependencies': dependency_analysis.get('total_dependencies', 0)
                    }
                ))
                
        except Exception as e:
            self.logger.error(f"PyPI dependency signal creation failed: {e}")
        
        return signals
    
    def _analyze_pypi_version_patterns(self, package_metadata: 'PackageMetadata', package_details: Dict) -> List['Signal']:
        """Analyze PyPI version history patterns for suspicious behavior."""
        signals = []
        
        try:
            versions_count = package_details.get('versions_count', 0)
            upload_time = package_details.get('upload_time', '')
            
            # Check for excessive version releases (potential version spam)
            if versions_count > 100:
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_version_spam_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Excessive PyPI Version Releases",
                    description="PyPI package has an unusually high number of version releases",
                    evidence=f"{versions_count} versions released (threshold: >100)",
                    locations=[],
                    tags=["pypi-version-spam", "rapid-releases"],
                    references=[],
                    metadata={'versions_count': versions_count}
                ))
            
            # Check for suspicious file size patterns
            file_size = package_details.get('size', 0)
            if file_size > 50 * 1024 * 1024:  # Larger than 50MB
                signals.append(Signal(
                    signal_id=f"pypi_enhanced_large_package_{hash(package_metadata.name) % 10000}",
                    signal_type=SignalType.BEHAVIORAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title="Unusually Large PyPI Package",
                    description="PyPI package is unusually large which may indicate embedded malware",
                    evidence=f"Package size: {file_size / (1024*1024):.1f} MB (threshold: >50MB)",
                    locations=[],
                    tags=["pypi-large-package", "size-anomaly"],
                    references=[],
                    metadata={'size_bytes': file_size, 'size_mb': file_size / (1024*1024)}
                ))
                
        except Exception as e:
            self.logger.error(f"PyPI version pattern analysis failed: {e}")
        
        return signals
    
    def _detect_typosquatting(self, package_name: str, ecosystem: str = None) -> Tuple[bool, List[Dict]]:
        """Ecosystem-specific typosquatting detection using dynamic popular packages."""
        import time
        
        start_time = time.time()
        name_lower = package_name.lower()
        matches = []
        
        # Skip very short names (likely legitimate single-letter packages)
        if len(name_lower) <= 2:
            return False, []
        
        self.logger.info(f"Checking {package_name} against top 150 popular {ecosystem or 'all'} packages...")
        
        # Get popular packages for specific ecosystem only
        popular_packages = self._get_popular_packages_dynamic(ecosystem=ecosystem)
        
        # Check against ecosystem-specific popular packages with detailed matching
        for pkg_info in popular_packages:
            # Performance check - abort if taking too long (300ms total budget)
            if (time.time() - start_time) * 1000 > 300:
                self.logger.warning(f"Typosquatting check timeout for {package_name} after 300ms")
                break
            
            # Skip if identical (legitimate package)
            if name_lower == pkg_info.name.lower():
                continue
            
            # Quick length difference check (performance optimization)
            if abs(len(name_lower) - len(pkg_info.name)) > 4:
                continue
            
            # Check for typosquatting using all algorithms
            match_result = self._check_typosquatting_match(name_lower, pkg_info.name.lower())
            if match_result:
                match_info = {
                    'target_package': pkg_info.name,
                    'ecosystem': pkg_info.ecosystem,
                    'download_count': pkg_info.download_count,
                    'algorithm': match_result['algorithm'],
                    'confidence': match_result['confidence'],
                    'description': pkg_info.description or 'No description available',
                    'repository_url': pkg_info.repository_url or 'Not available'
                }
                matches.append(match_info)
                
                self.logger.warning(f"Typosquatting match: {package_name} -> {pkg_info.name} "
                                  f"({pkg_info.ecosystem}, {pkg_info.download_count:,} downloads) "
                                  f"via {match_result['algorithm']}")
        
        # Sort matches by download count (most popular first)
        matches.sort(key=lambda x: x['download_count'], reverse=True)
        
        elapsed_ms = (time.time() - start_time) * 1000
        self.logger.info(f"Typosquatting check complete: {len(matches)} matches found in {elapsed_ms:.1f}ms")
        
        return len(matches) > 0, matches
    
    def _check_against_package_list(self, name_lower: str, packages: List[str], 
                                   timeout_ms: int, phase: str) -> bool:
        """Check package name against a list of packages with timeout."""
        import time
        start_time = time.time()
        
        # Pre-filter: Skip if name is too different in length from any package in list
        if packages:
            min_len = min(len(pkg) for pkg in packages)
            max_len = max(len(pkg) for pkg in packages)
            if len(name_lower) < min_len - 3 or len(name_lower) > max_len + 3:
                return False
        
        for popular_pkg in packages:
            # Performance check - abort if taking too long
            if (time.time() - start_time) * 1000 > timeout_ms:
                self.logger.warning(f"⏱️ {phase.title()} check timeout for {name_lower} after {timeout_ms}ms")
                break
                
            # Skip if identical (legitimate package)
            if name_lower == popular_pkg.lower():
                continue
            
            # Quick length difference check first (fastest)
            if abs(len(name_lower) - len(popular_pkg)) > 3:
                continue
                
            # Run algorithms in order of speed (fastest first, early termination)
            if self._run_typosquatting_algorithms(name_lower, popular_pkg.lower(), phase):
                return True
        
        return False
    
    def _run_typosquatting_algorithms(self, name1: str, name2: str, phase: str) -> bool:
        """Run typosquatting detection algorithms in speed-optimized order."""
        # 1. Edit distance (fast, most common)
        if self._check_edit_distance(name1, name2):
            self.logger.info(f"🎯 Typosquatting detected via edit distance ({phase}): {name1} → {name2}")
            return True
            
        # 2. Character omission/insertion (fast)
        if (self._check_character_omission(name1, name2) or
            self._check_character_insertion(name1, name2)):
            self.logger.info(f"🎯 Typosquatting detected via character omission/insertion ({phase}): {name1} → {name2}")
            return True
            
        # 3. Character swapping (fast)
        if self._check_character_swapping(name1, name2):
            self.logger.info(f"🎯 Typosquatting detected via character swapping ({phase}): {name1} → {name2}")
            return True
            
        # 4. Keyboard typos (medium speed)
        if self._check_keyboard_typos(name1, name2):
            self.logger.info(f"🎯 Typosquatting detected via keyboard typos ({phase}): {name1} → {name2}")
            return True
        
        # For extended phase, run additional algorithms
        if phase == "extended":
            # 5. Homoglyph attack (medium speed)
            if self._check_homoglyph_attack(name1, name2):
                self.logger.info(f"🎯 Typosquatting detected via homoglyph attack ({phase}): {name1} → {name2}")
                return True
                
            # Only run expensive algorithms for very close matches
            if self._levenshtein_distance(name1, name2) <= 2:
                # 6. Character substitution (expensive - limited scope)
                if self._check_character_substitution_fast(name1, name2):
                    self.logger.info(f"🎯 Typosquatting detected via character substitution ({phase}): {name1} → {name2}")
                    return True
                    
                # 7. Phonetic similarity (expensive - only for very similar)
                if self._check_phonetic_similarity(name1, name2):
                    self.logger.info(f"🎯 Typosquatting detected via phonetic similarity ({phase}): {name1} → {name2}")
                    return True
        
        return False
    
    def _get_critical_packages(self) -> List[str]:
        """Get reduced list of most critical packages for fast typosquatting detection."""
        # Most frequently typosquatted packages (reduced from 70+ to 25 for performance)
        critical_packages = [
            # Most critical npm packages
            'react', 'lodash', 'express', 'axios', 'webpack', 'jquery', 'vue', 'angular',
            'typescript', 'babel', 'eslint', 'request', 'debug', 'chalk', 'moment',
            
            # Most critical PyPI packages  
            'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'tensorflow',
            'selenium', 'pytest', 'beautifulsoup4'
        ]
        return critical_packages
    
    def _get_extended_packages(self) -> List[str]:
        """Get extended list of popular packages for comprehensive typosquatting detection."""
        # Additional popular packages beyond the critical 25 (40+ more packages)
        extended_npm = [
            # Additional npm packages (commonly typosquatted)
            'prettier', 'moment', 'underscore', 'async', 'commander', 'inquirer', 
            'fs-extra', 'glob', 'semver', 'yargs', 'bluebird', 'uuid', 'mkdirp', 
            'rimraf', 'minimist', 'colors', 'mime', 'nodemon', 'cors', 'morgan', 
            'helmet', 'joi', 'bcrypt', 'jsonwebtoken', 'passport', 'socket.io', 
            'redis', 'mongoose', 'sequelize', 'dotenv', 'winston', 'cheerio',
            'handlebars', 'mustache', 'ejs', 'pug', 'sass', 'less', 'stylus'
        ]
        
        extended_pypi = [
            # Additional PyPI packages (commonly typosquatted)
            'matplotlib', 'scipy', 'scikit-learn', 'pillow', 'click', 'pyyaml', 
            'jinja2', 'sqlalchemy', 'psycopg2', 'mysql-connector-python', 'celery',
            'gunicorn', 'uwsgi', 'fastapi', 'aiohttp', 'asyncio', 'boto3', 'awscli',
            'cryptography', 'paramiko', 'fabric', 'ansible', 'docker', 'kubernetes',
            'scrapy', 'lxml', 'openpyxl', 'xlrd', 'xlwt', 'pandas-datareader',
            'networkx', 'imageio', 'opencv-python', 'pytz', 'dateutil', 'httpx'
        ]
        
        return extended_npm + extended_pypi
    
    def _get_popular_packages(self) -> List[str]:
        """Get combined list of critical + extended packages."""
        return self._get_critical_packages() + self._get_extended_packages()
    
    def _get_popular_packages_dynamic(self, ecosystem: str = None):
        """Get popular packages using ecosystem-specific dynamic API fetcher with caching."""
        try:
            # Import the fetcher (lazy import to avoid issues if file doesn't exist)
            try:
                from .popular_packages_fetcher import PopularPackagesFetcher
            except ImportError:
                from popular_packages_fetcher import PopularPackagesFetcher
            
            # Create fetcher instance (uses caching)
            fetcher = PopularPackagesFetcher()
            
            # Get ecosystem-specific packages (150 each)
            if ecosystem == "npm":
                popular_packages = fetcher.get_popular_npm_packages(150)
            elif ecosystem == "pypi":
                popular_packages = fetcher.get_popular_pypi_packages(150)
            else:
                # Fallback to combined list
                popular_packages = fetcher.get_popular_packages(300)
            
            self.logger.info(f"Loaded {len(popular_packages)} popular {ecosystem or 'all'} packages from APIs")
            return popular_packages
            
        except Exception as e:
            self.logger.warning(f"Failed to fetch dynamic popular packages: {e}")
            self.logger.info("Falling back to static package lists")
            
            # Fallback to ecosystem-specific static lists
            static_packages = []
            
            if ecosystem == "npm":
                # Only npm packages
                npm_packages = [
                    'react', 'lodash', 'express', 'axios', 'webpack', 'jquery', 'vue', 'angular',
                    'typescript', 'babel', 'eslint', 'prettier', 'moment', 'underscore', 'async',
                    'chalk', 'commander', 'inquirer', 'fs-extra', 'glob', 'semver', 'yargs'
                ]
                for i, pkg_name in enumerate(npm_packages):
                    download_count = 50000000 - (i * 100000)  # Decreasing count
                    static_packages.append(self._create_static_package_info(pkg_name, "npm", download_count))
            
            elif ecosystem == "pypi":
                # Only PyPI packages
                pypi_packages = [
                    'requests', 'urllib3', 'numpy', 'pandas', 'matplotlib', 'scipy', 'flask',
                    'django', 'tensorflow', 'keras', 'pytorch', 'scikit-learn', 'pillow',
                    'beautifulsoup4', 'selenium', 'pytest', 'click', 'pyyaml', 'jinja2'
                ]
                for i, pkg_name in enumerate(pypi_packages):
                    download_count = 45000000 - (i * 100000)  # Decreasing count
                    static_packages.append(self._create_static_package_info(pkg_name, "pypi", download_count))
            
            else:
                # Combined fallback
                critical = self._get_critical_packages()
                extended = self._get_extended_packages()
                
                for i, pkg_name in enumerate(critical + extended):
                    # Estimate ecosystem and download count
                    ecosystem_guess = "npm" if pkg_name in ['react', 'lodash', 'express', 'axios'] else "pypi"
                    if pkg_name in ['requests', 'urllib3', 'numpy', 'pandas']:
                        ecosystem_guess = "pypi"
                    
                    download_count = 10000000 - (i * 100000)  # Decreasing count
                    static_packages.append(self._create_static_package_info(pkg_name, ecosystem_guess, download_count))
            
            return static_packages
    
    def _create_static_package_info(self, name: str, ecosystem: str, download_count: int):
        """Create a static package info object for fallback scenarios."""
        class StaticPackageInfo:
            def __init__(self, name, ecosystem, download_count):
                self.name = name
                self.ecosystem = ecosystem
                self.download_count = download_count
                self.description = f"Popular {ecosystem} package"
                self.repository_url = f"https://github.com/example/{name}"
        
        return StaticPackageInfo(name, ecosystem, download_count)
    
    def _check_typosquatting_match(self, name1: str, name2: str) -> Optional[Dict]:
        """Check if two package names match using all algorithms and return match info."""
        # Try algorithms in order of reliability/speed
        algorithms = [
            ("edit_distance", self._check_edit_distance),
            ("character_omission", self._check_character_omission),
            ("character_insertion", self._check_character_insertion),
            ("character_swapping", self._check_character_swapping),
            ("keyboard_typos", self._check_keyboard_typos),
            ("homoglyph_attack", self._check_homoglyph_attack),
            ("character_substitution", self._check_character_substitution_fast),
            ("phonetic_similarity", self._check_phonetic_similarity)
        ]
        
        for algorithm_name, algorithm_func in algorithms:
            try:
                if algorithm_func(name1, name2):
                    # Calculate confidence based on algorithm and similarity
                    confidence = self._calculate_match_confidence(name1, name2, algorithm_name)
                    
                    return {
                        'algorithm': algorithm_name,
                        'confidence': confidence,
                        'similarity_score': self._calculate_similarity_score(name1, name2)
                    }
            except Exception as e:
                # Log the error but continue with other algorithms
                self.logger.debug(f"Algorithm {algorithm_name} failed for {name1}/{name2}: {e}")
                continue
        
        return None
    
    def _calculate_match_confidence(self, name1: str, name2: str, algorithm: str) -> float:
        """Calculate confidence score for a typosquatting match."""
        # Base confidence by algorithm reliability
        algorithm_confidence = {
            "edit_distance": 0.9,
            "character_omission": 0.85,
            "character_insertion": 0.85,
            "character_swapping": 0.8,
            "keyboard_typos": 0.75,
            "homoglyph_attack": 0.7,
            "character_substitution": 0.65,
            "phonetic_similarity": 0.6
        }
        
        base_confidence = algorithm_confidence.get(algorithm, 0.5)
        
        # Adjust based on length similarity
        len_diff = abs(len(name1) - len(name2))
        length_factor = max(0.5, 1.0 - (len_diff * 0.1))
        
        # Adjust based on edit distance
        edit_distance = self._levenshtein_distance(name1, name2)
        max_len = max(len(name1), len(name2))
        distance_factor = max(0.3, 1.0 - (edit_distance / max_len))
        
        final_confidence = base_confidence * length_factor * distance_factor
        return min(0.95, max(0.3, final_confidence))
    
    def _calculate_similarity_score(self, name1: str, name2: str) -> float:
        """Calculate similarity score between two names."""
        edit_distance = self._levenshtein_distance(name1, name2)
        max_len = max(len(name1), len(name2))
        if max_len == 0:
            return 1.0
        return 1.0 - (edit_distance / max_len)
    
    def _check_edit_distance(self, name1: str, name2: str) -> bool:
        """Check if names are similar using Levenshtein distance."""
        distance = self._levenshtein_distance(name1, name2)
        max_len = max(len(name1), len(name2))
        
        # Consider typosquatting if edit distance is small relative to length
        if max_len <= 4:
            return distance == 1
        elif max_len <= 8:
            return distance <= 2
        else:
            return distance <= 3 and distance / max_len <= 0.3
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_character_substitution(self, name1: str, name2: str) -> bool:
        """Check for common character substitutions (0->o, 1->l, etc.)."""
        substitutions = {
            '0': 'o', 'o': '0', '1': 'l', 'l': '1', '1': 'i', 'i': '1',
            'e': '3', '3': 'e', 'a': '@', '@': 'a', 's': '$', '$': 's',
            'g': '9', '9': 'g', 't': '7', '7': 't', 'b': '6', '6': 'b',
            'u': 'v', 'v': 'u', 'm': 'n', 'n': 'm', 'cl': 'd', 'rn': 'm'
        }
        
        # Generate all possible substitutions of name1 and check against name2
        def generate_substitutions(name: str) -> List[str]:
            if not name:
                return ['']
            
            first_char = name[0]
            rest_substitutions = generate_substitutions(name[1:])
            
            result = []
            for rest in rest_substitutions:
                # Original character
                result.append(first_char + rest)
                
                # Substituted characters
                for orig, sub in substitutions.items():
                    if first_char == orig:
                        result.append(sub + rest)
                    # Check multi-character substitutions
                    if len(name) >= len(orig) and name[:len(orig)] == orig:
                        remaining = name[len(orig):]
                        for rest_sub in generate_substitutions(remaining):
                            result.append(sub + rest_sub)
            
            return list(set(result))
        
        # Limit to prevent explosion
        substituted_names = generate_substitutions(name1)[:100]
        return name2 in substituted_names
    
    def _check_character_substitution_fast(self, name1: str, name2: str) -> bool:
        """Fast character substitution check without recursive generation."""
        if len(name1) != len(name2):
            return False
            
        substitutions = {
            '0': 'o', 'o': '0', '1': 'l', 'l': '1', '1': 'i', 'i': '1',
            'e': '3', '3': 'e', 'a': '@', '@': 'a', 's': '$', '$': 's',
            'g': '9', '9': 'g', 't': '7', '7': 't', 'b': '6', '6': 'b',
            'u': 'v', 'v': 'u', 'm': 'n', 'n': 'm'
        }
        
        differences = 0
        for i, (c1, c2) in enumerate(zip(name1, name2)):
            if c1 != c2:
                differences += 1
                if differences > 2:  # Max 2 substitutions for performance
                    return False
                
                # Check if this is a valid substitution
                if c1 not in substitutions or substitutions[c1] != c2:
                    if c2 not in substitutions or substitutions[c2] != c1:
                        return False
        
        return 1 <= differences <= 2
    
    def _check_character_omission(self, name1: str, name2: str) -> bool:
        """Check if name1 is name2 with characters omitted."""
        if abs(len(name1) - len(name2)) != 1:
            return False
        
        shorter, longer = (name1, name2) if len(name1) < len(name2) else (name2, name1)
        
        # Check if shorter is longer with one character removed
        for i in range(len(longer)):
            if longer[:i] + longer[i+1:] == shorter:
                return True
        
        return False
    
    def _check_character_insertion(self, name1: str, name2: str) -> bool:
        """Check if name1 is name2 with characters inserted."""
        return self._check_character_omission(name2, name1)  # Reverse check
    
    def _check_character_swapping(self, name1: str, name2: str) -> bool:
        """Check for adjacent character swaps (transposition)."""
        if len(name1) != len(name2):
            return False
        
        differences = sum(1 for a, b in zip(name1, name2) if a != b)
        
        # If exactly 2 differences, check if they're adjacent swapped characters
        if differences == 2:
            diff_positions = [i for i, (a, b) in enumerate(zip(name1, name2)) if a != b]
            if len(diff_positions) == 2 and abs(diff_positions[0] - diff_positions[1]) == 1:
                # Check if swapping fixes both positions
                i, j = diff_positions
                return name1[i] == name2[j] and name1[j] == name2[i]
        
        return False
    
    def _check_keyboard_typos(self, name1: str, name2: str) -> bool:
        """Check for keyboard layout-based typos."""
        # QWERTY keyboard adjacency map
        qwerty_adjacent = {
            'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etdf', 't': 'ryfg', 
            'y': 'tugh', 'u': 'yihj', 'i': 'uojk', 'o': 'ipkl', 'p': 'ol',
            'a': 'qwsz', 's': 'awedz', 'd': 'serfcx', 'f': 'drtgcv', 'g': 'ftyhbv',
            'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhjm', 'm': 'njk'
        }
        
        if len(name1) != len(name2):
            return False
        
        differences = 0
        for i, (c1, c2) in enumerate(zip(name1, name2)):
            if c1 != c2:
                differences += 1
                if differences > 2:  # Too many differences
                    return False
                
                # Check if characters are adjacent on keyboard
                if c1 not in qwerty_adjacent or c2 not in qwerty_adjacent.get(c1, ''):
                    if c2 not in qwerty_adjacent or c1 not in qwerty_adjacent.get(c2, ''):
                        return False
        
        return 1 <= differences <= 2
    
    def _check_homoglyph_attack(self, name1: str, name2: str) -> bool:
        """Check for visually similar characters (homoglyphs)."""
        homoglyphs = {
            'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'x': 'х',
            'y': 'у', 'i': 'і', 'j': 'ј', 'k': 'к', 'h': 'һ', 'b': 'Ь',
            'n': 'п', 'm': 'м', 'r': 'г', 's': 'ѕ', 't': 'т', 'u': 'и',
            'v': 'ѵ', 'w': 'ѡ', 'z': 'з'
        }
        
        # Normalize both names by replacing homoglyphs
        def normalize_homoglyphs(name: str) -> str:
            normalized = name
            for latin, cyrillic in homoglyphs.items():
                normalized = normalized.replace(cyrillic, latin)
            # Also check reverse mapping
            for latin, cyrillic in homoglyphs.items():
                normalized = normalized.replace(latin, cyrillic)
            return normalized
        
        normalized1 = normalize_homoglyphs(name1)
        normalized2 = normalize_homoglyphs(name2)
        
        return normalized1 == name2 or normalized2 == name1 or normalized1 == normalized2
    
    def _check_phonetic_similarity(self, name1: str, name2: str) -> bool:
        """Check phonetic similarity using simplified Soundex algorithm."""
        def soundex(name: str) -> str:
            if not name:
                return "0000"
            
            name = name.upper()
            soundex_code = name[0]  # Keep first letter
            
            # Soundex mapping
            mapping = {
                'BFPV': '1', 'CGJKQSXZ': '2', 'DT': '3',
                'L': '4', 'MN': '5', 'R': '6'
            }
            
            for char in name[1:]:
                for group, code in mapping.items():
                    if char in group:
                        if soundex_code[-1] != code:  # Avoid adjacent duplicates
                            soundex_code += code
                        break
            
            # Pad with zeros and limit to 4 characters
            soundex_code = (soundex_code + "0000")[:4]
            return soundex_code
        
        return soundex(name1) == soundex(name2) and len(name1) >= 4 and len(name2) >= 4
    
    def _detect_suspicious_patterns(self, name: str) -> bool:
        """Detect other suspicious naming patterns."""
        import re
        name_lower = name.lower()
        
        # Single character packages (except some legitimate ones)
        if re.match(r'^[a-z]$', name_lower) and name_lower not in ['q', 'x', 'y', 'z']:
            return True
        
        # Excessive numbers (6+ consecutive digits)
        if re.search(r'\d{6,}', name_lower):
            return True
        
        # Too many confusing characters
        if re.search(r'[0O1Il]{4,}', name_lower):
            return True
        
        # All numbers
        if re.match(r'^\d+$', name_lower):
            return True
        
        # Nonsensical character combinations
        if re.search(r'[qxz]{3,}', name_lower):
            return True
        
        # Mixed scripts (Latin + other)
        latin_chars = re.findall(r'[a-zA-Z]', name)
        non_latin_chars = re.findall(r'[^\x00-\x7F]', name)
        if latin_chars and non_latin_chars:
            return True
        
        # Excessive punctuation or special characters
        if re.search(r'[._-]{3,}', name_lower):
            return True
        
        return False
    
    def _is_recently_created_high_risk(self, metadata: PackageMetadata) -> bool:
        """Check if package is recently created with high-risk characteristics."""
        # This is a placeholder - in real implementation, you'd check:
        # - Publish date vs current date
        # - Low download count for age
        # - Missing or suspicious repository URL
        # - Unusual version patterns
        return False
    
    def _check_suspicious_npm_scripts(self, scripts: Dict[str, str]) -> List[Tuple[str, str]]:
        """Check for suspicious NPM scripts with enhanced detection."""
        import os
        from pathlib import Path
        
        suspicious = []
        dangerous_commands = [
            'curl', 'wget', 'nc', 'netcat', 'python', 'php', 'bash', 'sh',
            'powershell', 'cmd', 'eval', 'rm -rf', 'chmod', 'sudo', 'node'
        ]
        
        suspicious_patterns = [
            'patch', 'fix', 'security', 'update', 'install', 'setup', 
            'configure', 'apply', 'download', 'fetch', 'get'
        ]
        
        for script_name, script_content in scripts.items():
            if script_name in ['install', 'postinstall', 'preinstall', 'prepare', 'prepublish']:
                content_lower = script_content.lower()
                
                # Check for dangerous commands
                for dangerous_cmd in dangerous_commands:
                    if dangerous_cmd in content_lower:
                        suspicious.append((script_name, script_content))
                        self.logger.warning(f"Suspicious script command detected: {dangerous_cmd} in {script_name}")
                        break
                
                # Check if referenced script files exist
                if 'node ' in content_lower:
                    # Extract referenced JavaScript files
                    import re
                    js_files = re.findall(r'node\s+([^\s]+\.js)', script_content)
                    for js_file in js_files:
                        # Check if the file exists relative to package directory
                        # Note: We can't easily get package path here, so we'll flag this separately
                        if any(pattern in js_file.lower() for pattern in suspicious_patterns):
                            suspicious.append((script_name, f"{script_content} (references suspicious file: {js_file})"))
                            self.logger.warning(f"Suspicious script file reference: {js_file} in {script_name}")
                            break
        
        return suspicious

class PackageSignalAnalyzer:
    """Main analyzer that coordinates signal collection and generates LLM-ready output."""
    
    def __init__(self, opengrep_rules_path: str):
        self.opengrep_collector = OpenGrepSignalCollector(opengrep_rules_path)
        self.metadata_collector = MetadataSignalCollector()
        self.logger = logging.getLogger(__name__)
    
    def analyze_package(self, package_path: str, package_metadata: PackageMetadata, package_source: str = "local") -> AnalysisResult:
        """Perform comprehensive package analysis and return structured signals."""
        import time
        start_time = time.time()
        
        errors = []
        warnings = []
        all_signals = []
        
        self.logger.info(f"\033[1;36mStarting comprehensive analysis of {package_metadata.name}\033[0m")
        
        try:
            # Collect OpenGrep signals
            self.logger.info(f"\033[1;34mPhase 1: OpenGrep static analysis\033[0m")
            opengrep_signals = self.opengrep_collector.collect_signals(package_path, package_metadata)
            all_signals.extend(opengrep_signals)
            self.logger.info(f"\033[1;32mOpenGrep phase complete: {len(opengrep_signals)} signals\033[0m")
            
            # Collect metadata signals
            self.logger.info(f"\033[1;34mPhase 2: Metadata analysis (typosquatting, binary files, scripts)\033[0m")
            metadata_signals = self.metadata_collector.collect_signals(package_path, package_metadata)
            all_signals.extend(metadata_signals)
            self.logger.info(f"\033[1;32mMetadata phase complete: {len(metadata_signals)} signals\033[0m")
            
            # Calculate confidence and dynamic analysis recommendation
            self.logger.info(f"\033[1;34mPhase 3: Calculating analysis confidence and recommendations\033[0m")
            confidence, recommend_dynamic, dynamic_reason = self._assess_static_analysis_confidence(
                all_signals, package_metadata
            )
            self.logger.info(f"\033[1;33mAnalysis confidence: {confidence:.2f}\033[0m")
            
            # Generate LLM context
            self.logger.info(f"\033[1;34mPhase 4: Generating LLM context and IOC extraction\033[0m")
            llm_context = self._generate_llm_context(all_signals, package_metadata, package_path)
            
            processing_time = int((time.time() - start_time) * 1000)
            
            self.logger.info(f"\033[1;32mAnalysis complete! Total signals: {len(all_signals)}, Time: {processing_time}ms\033[0m")
            
            return AnalysisResult(
                package_metadata=package_metadata,
                signals=all_signals,
                static_analysis_confidence=confidence,
                recommend_dynamic_analysis=recommend_dynamic,
                dynamic_analysis_reason=dynamic_reason,
                llm_context=llm_context,
                processing_time_ms=processing_time,
                errors=errors,
                warnings=warnings,
                package_source=package_source,
                package_path=package_path
            )
            
        except Exception as e:
            self.logger.error(f"Error during package analysis: {e}")
            errors.append(str(e))
            
            return AnalysisResult(
                package_metadata=package_metadata,
                signals=all_signals,
                static_analysis_confidence=0.0,
                recommend_dynamic_analysis=True,
                dynamic_analysis_reason="Static analysis failed, dynamic analysis recommended",
                llm_context={},
                processing_time_ms=int((time.time() - start_time) * 1000),
                errors=errors,
                warnings=warnings,
                package_source=package_source,
                package_path=package_path
            )
    
    def _assess_static_analysis_confidence(self, signals: List[Signal], metadata: PackageMetadata) -> Tuple[float, bool, Optional[str]]:
        """Assess confidence in static analysis and recommend dynamic analysis if needed."""
        
        # Calculate confidence based on signal quality
        if not signals:
            return 0.3, True, "No static analysis signals found - dynamic analysis recommended for comprehensive assessment"
        
        # High confidence indicators
        high_confidence_signals = [s for s in signals if s.confidence >= 0.8 and s.severity in [Severity.HIGH, Severity.CRITICAL]]
        if high_confidence_signals:
            return 0.9, False, None
        
        # Medium confidence indicators
        medium_confidence_signals = [s for s in signals if s.confidence >= 0.6]
        if len(medium_confidence_signals) >= 3:
            return 0.7, False, None
        
        # Low confidence scenarios that need dynamic analysis
        obfuscation_signals = [s for s in signals if s.signal_type == SignalType.OBFUSCATION]
        if obfuscation_signals:
            return 0.5, True, "Code obfuscation detected - dynamic analysis needed to understand runtime behavior"
        
        behavioral_signals = [s for s in signals if s.signal_type == SignalType.BEHAVIORAL_ANOMALY]
        if behavioral_signals:
            return 0.6, True, "Behavioral anomalies detected - dynamic analysis recommended to capture runtime patterns"
        
        # Default case
        if len(signals) < 2:
            return 0.4, True, "Limited static analysis findings - dynamic analysis recommended for complete assessment"
        
        return 0.6, False, None
    
    def _generate_llm_context(self, signals: List[Signal], metadata: PackageMetadata, package_path: str) -> Dict[str, Any]:
        """Generate structured context for LLM analysis."""
        
        # Group signals by type
        signals_by_type = {}
        for signal in signals:
            signal_type = signal.signal_type.value
            if signal_type not in signals_by_type:
                signals_by_type[signal_type] = []
            signals_by_type[signal_type].append(signal.to_dict())
        
        
        # Generate threat summary
        threat_indicators = {
            'has_malware_patterns': SignalType.MALWARE_PATTERN.value in signals_by_type,
            'has_obfuscation': SignalType.OBFUSCATION.value in signals_by_type,
            'has_network_activity': SignalType.NETWORK_ACTIVITY.value in signals_by_type,
            'has_file_operations': SignalType.FILE_OPERATIONS.value in signals_by_type,
            'has_supply_chain_risk': SignalType.SUPPLY_CHAIN_RISK.value in signals_by_type,
            'has_cryptojacking': SignalType.CRYPTOJACKING.value in signals_by_type,
            'has_behavioral_anomalies': SignalType.BEHAVIORAL_ANOMALY.value in signals_by_type
        }
        
        return {
            'package_summary': {
                'name': metadata.name,
                'version': metadata.version,
                'ecosystem': metadata.ecosystem.value,
                'author': metadata.author,
                'description': metadata.description,
                'license': metadata.license,
                'repository_url': metadata.repository_url,
                'homepage_url': metadata.homepage_url,
                'publish_date': metadata.publish_date,
                'download_count': metadata.download_count,
                'weekly_download_count': metadata.weekly_download_count,
                'file_count': metadata.file_count,
                'total_size': metadata.total_size,
                'total_versions': metadata.total_versions,
                'total_dependants': metadata.total_dependants,
                'dependencies': metadata.dependencies,
                'dev_dependencies': metadata.dev_dependencies,
                'has_binary_files': self._has_binary_files(signals, package_path),
                'hooks_and_lifecycle': self._extract_hooks_and_lifecycle(metadata),
                'trust_indicators': self._extract_trust_indicators(metadata, signals, package_path)
            },
            'analysis_summary': {
                'threat_indicators': threat_indicators
            },
            'detailed_signals': signals_by_type,
            'analysis_metadata': {
                'static_analysis_coverage': self._assess_analysis_coverage(signals, metadata),
                'detection_gaps': self._identify_detection_gaps(signals, metadata)
            }
        }
    
    def _assess_analysis_coverage(self, signals: List[Signal], metadata: PackageMetadata) -> Dict[str, Any]:
        """Assess how comprehensive the static analysis coverage is."""
        coverage = {
            'code_patterns_analyzed': bool([s for s in signals if s.signal_type == SignalType.MALWARE_PATTERN]),
            'obfuscation_checked': bool([s for s in signals if s.signal_type == SignalType.OBFUSCATION]),
            'network_behavior_detected': bool([s for s in signals if s.signal_type == SignalType.NETWORK_ACTIVITY]),
            'metadata_validated': bool([s for s in signals if s.signal_type == SignalType.METADATA_ANOMALY]),
            'supply_chain_assessed': bool([s for s in signals if s.signal_type == SignalType.SUPPLY_CHAIN_RISK])
        }
        
        coverage_percentage = (sum(coverage.values()) / len(coverage)) * 100
        
        return {
            'coverage_areas': coverage,
            'overall_coverage_percentage': round(coverage_percentage, 1),
            'analysis_depth': 'comprehensive' if coverage_percentage >= 80 else 'partial'
        }
    
    def _identify_detection_gaps(self, signals: List[Signal], metadata: PackageMetadata) -> List[str]:
        """Identify gaps in detection that might require dynamic analysis."""
        gaps = []
        
        # Check for runtime behavior gaps
        if not any(s.signal_type == SignalType.BEHAVIORAL_ANOMALY for s in signals):
            gaps.append("Runtime behavioral patterns not captured in static analysis")
        
        # Check for network activity gaps
        has_network_code = metadata.ecosystem == Ecosystem.NPM and any(
            dep for dep in metadata.dependencies.keys() 
            if dep in ['http', 'https', 'axios', 'request', 'fetch']
        )
        if has_network_code and not any(s.signal_type == SignalType.NETWORK_ACTIVITY for s in signals):
            gaps.append("Network-capable dependencies detected but no network activity patterns found")
        
        # Check for cryptographic gaps
        has_crypto_deps = any(
            dep for dep in metadata.dependencies.keys()
            if 'crypto' in dep.lower() or 'hash' in dep.lower()
        )
        if has_crypto_deps and not any(s.signal_type == SignalType.CRYPTOJACKING for s in signals):
            gaps.append("Cryptographic dependencies present but no mining/crypto patterns detected")
        
        return gaps

    def format_for_llm_analysis(self, analysis_result: AnalysisResult) -> str:
        """Format analysis result as structured prompt for LLM consumption."""
        
        context = analysis_result.llm_context
        package_info = context['package_summary']
        analysis_summary = context['analysis_summary']
        
        prompt = f"""# Package Analysis Report

## Package Information
- **Name**: {package_info['name']}
- **Version**: {package_info['version']}
- **Ecosystem**: {package_info['ecosystem']}
- **Author**: {package_info['author']}
- **Description**: {package_info['description']}
- **File Count**: {package_info['file_count']}
- **Total Size**: {package_info['total_size']} bytes
- **Dependencies**: {len(package_info.get('dependencies', []))} production, {len(package_info.get('dev_dependencies', []))} dev

## Analysis Summary
- **Static Analysis Confidence**: {analysis_result.static_analysis_confidence:.2f}

### Threat Indicators Present
"""
        
        for threat_type, present in analysis_summary['threat_indicators'].items():
            if present:
                prompt += f"- ✓ {threat_type.replace('_', ' ').title()}\n"
        
        
        # Dynamic analysis recommendation
        if analysis_result.recommend_dynamic_analysis:
            prompt += f"\n## Dynamic Analysis Recommendation\n"
            prompt += f"**Recommendation**: Dynamic analysis is recommended\n"
            prompt += f"**Reason**: {analysis_result.dynamic_analysis_reason}\n"
        
        # Analysis coverage
        coverage = context['analysis_metadata']['static_analysis_coverage']
        prompt += f"\n## Static Analysis Coverage\n"
        prompt += f"- **Overall Coverage**: {coverage['overall_coverage_percentage']}%\n"
        prompt += f"- **Analysis Depth**: {coverage['analysis_depth']}\n"
        
        if context['analysis_metadata']['detection_gaps']:
            prompt += f"\n### Potential Detection Gaps\n"
            for gap in context['analysis_metadata']['detection_gaps']:
                prompt += f"- {gap}\n"
        
        # Detailed signals for context with code snippets
        prompt += f"\n## Detailed Signal Information\n"
        for signal_type, signal_list in context['detailed_signals'].items():
            if signal_list:
                prompt += f"\n### {signal_type.replace('_', ' ').title()} Signals\n"
                for signal in signal_list[:3]:  # Limit to top 3 per category
                    prompt += f"- **{signal['title']}**: {signal['description']} (Confidence: {signal['confidence']:.2f})\n"
                    
                    # Add code snippets if available
                    if signal.get('locations'):
                        for i, location in enumerate(signal['locations'][:2], 1):  # Max 2 locations per signal
                            if location.get('code_snippet'):
                                file_path = location.get('file_path', 'unknown')
                                line_start = location.get('line_start', 0)
                                line_end = location.get('line_end', 0)
                                code_snippet = location['code_snippet'].strip()
                                
                                if code_snippet:
                                    prompt += f"  - **Location {i}**: `{file_path}` (lines {line_start}-{line_end})\n"
                                    prompt += f"    ```\n    {code_snippet}\n    ```\n"
                    
                    # Add evidence if different from code snippet
                    if signal.get('evidence') and signal['evidence'] not in [loc.get('code_snippet', '') for loc in signal.get('locations', [])]:
                        prompt += f"  - **Evidence**: {signal['evidence']}\n"
                    
                    prompt += "\n"
        
        prompt += f"\n## Processing Information\n"
        prompt += f"- **Processing Time**: {analysis_result.processing_time_ms}ms\n"
        if analysis_result.errors:
            prompt += f"- **Errors**: {len(analysis_result.errors)} errors occurred during analysis\n"
        if analysis_result.warnings:
            prompt += f"- **Warnings**: {len(analysis_result.warnings)} warnings generated\n"
        
        return prompt
    
    def _extract_hooks_and_lifecycle(self, metadata: PackageMetadata) -> Dict[str, Any]:
        """Extract hooks for security analysis."""
        hooks_info = {
            'install_hooks': [],
            'has_install_scripts': False,
            'has_postinstall_scripts': False,
            'has_preinstall_scripts': False
        }
        
        if not metadata.scripts:
            return hooks_info
        
        # Categorize scripts by type
        install_related = ['install', 'postinstall', 'preinstall', 'prepare', 'prepublish', 'prepublishOnly']
        
        for script_name, script_content in metadata.scripts.items():
            script_lower = script_name.lower()
            
            # Check for install-related hooks
            if script_lower in [s.lower() for s in install_related]:
                hooks_info['install_hooks'].append({
                    'name': script_name,
                    'command': script_content,
                    'risk_level': self._assess_script_risk(script_content)
                })
                
                # Set specific hook flags
                if script_lower == 'install':
                    hooks_info['has_install_scripts'] = True
                elif script_lower == 'postinstall':
                    hooks_info['has_postinstall_scripts'] = True
                elif script_lower == 'preinstall':
                    hooks_info['has_preinstall_scripts'] = True
        
        return hooks_info
    
    def _assess_script_risk(self, script_content: str) -> str:
        """Assess the risk level of a script command."""
        if not script_content:
            return 'low'
        
        high_risk_patterns = [
            'curl', 'wget', 'download', 'eval', 'exec', 'chmod +x',
            'rm -rf', 'sudo', 'bash -c', 'sh -c', '/bin/sh', '/bin/bash'
        ]
        
        medium_risk_patterns = [
            'node -e', 'python -c', 'pip install', 'npm install -g'
        ]
        
        script_lower = script_content.lower()
        
        if any(pattern in script_lower for pattern in high_risk_patterns):
            return 'high'
        elif any(pattern in script_lower for pattern in medium_risk_patterns):
            return 'medium'
        else:
            return 'low'
    
    
    def _extract_trust_indicators(self, metadata: PackageMetadata, signals: List[Signal], package_path: str) -> Dict[str, Any]:
        """Extract trust indicators with detailed values from package metadata."""
        hooks_info = self._extract_hooks_and_lifecycle(metadata)
        
        # Check for high-severity obfuscation patterns
        obfuscation_patterns = self._check_obfuscation_patterns(signals)
        
        trust_indicators = {
            'has_repository': {
                'status': bool(metadata.repository_url),
                'value': metadata.repository_url or 'None'
            },
            'has_homepage': {
                'status': bool(metadata.homepage_url),
                'value': metadata.homepage_url or 'None'
            },
            'has_license': {
                'status': bool(metadata.license),
                'value': metadata.license or 'None'
            },
            'has_description': {
                'status': bool(metadata.description and len(metadata.description.strip()) > 10),
                'value': f"{len(metadata.description)} chars" if metadata.description else "None"
            },
            'has_author': {
                'status': bool(metadata.author and metadata.author.strip()),
                'value': metadata.author or 'None'
            },
            'recent_version': {
                'status': self._is_recent_version(metadata.version) if metadata.version else False,
                'value': metadata.version or 'None'
            },
            'repository_active': {
                'status': self._is_repository_active(metadata.repository_url) if metadata.repository_url else False,
                'value': 'Active' if self._is_repository_active(metadata.repository_url) else 'Inactive/Unknown'
            },
            'no_binary_files': self._get_binary_files_trust_info(signals, package_path),
            'install_hooks': {
                'status': len(hooks_info['install_hooks']) == 0,  # True if no install hooks (safer)
                'value': self._format_install_hooks(hooks_info['install_hooks'])
            },
            'no_obfuscated_code': {
                'status': not obfuscation_patterns['has_non_visible_chars'],
                'value': obfuscation_patterns['non_visible_chars_summary']
            },
            'no_suspicious_decoding': {
                'status': not obfuscation_patterns['has_suspicious_apis'],
                'value': obfuscation_patterns['suspicious_apis_summary']
            }
        }
        
        return trust_indicators
    
    def _check_obfuscation_patterns(self, signals: List[Signal]) -> Dict[str, Any]:
        """Check for high-severity obfuscation patterns in signals."""
        non_visible_chars_signals = []
        suspicious_api_signals = []
        
        # Define the rule IDs we're looking for (with full prefix)
        non_visible_char_rules = {
            'opengrep-rules.npm.js-non-visible-chars-in-strings',
            'opengrep-rules.npm.js-long-string-with-non-printable',
            'opengrep-rules.npm.js-long-string',  # Include original long string rule
            'opengrep-rules.npm.js-high-entropy-string',  # High entropy patterns
            'opengrep-rules.npm.js-obfuscation-high-entropy',  # High entropy obfuscation
            'opengrep-rules.npm.js-unicode-tag-characters',  # Unicode tag character obfuscation
            'opengrep-rules.npm.js-high-non-ascii-density'  # High non-ASCII density
        }
        
        suspicious_api_rules = {
            'opengrep-rules.npm.js-atob-usage',
            'opengrep-rules.npm.js-eval-atob-combo', 
            'opengrep-rules.npm.js-buffer-from-base64',
            'opengrep-rules.npm.js-hex-decoding-patterns',
            'opengrep-rules.npm.js-string-fromcharcode-obfuscation',
            'opengrep-rules.npm.js-unescape-decoding'
        }
        
        # Scan signals for obfuscation patterns
        for signal in signals:
            # Get rule_id from signal metadata
            signal_id = None
            if hasattr(signal, 'metadata') and isinstance(signal.metadata, dict):
                signal_id = signal.metadata.get('rule_id')
            if not signal_id:
                signal_id = getattr(signal, 'rule_id', None) or getattr(signal, 'id', None)
            
            if signal_id in non_visible_char_rules:
                non_visible_chars_signals.append(signal)
            elif signal_id in suspicious_api_rules:
                suspicious_api_signals.append(signal)
        
        # Create summaries
        non_visible_summary = "Clean" if not non_visible_chars_signals else \
            f"{len(non_visible_chars_signals)} obfuscated pattern(s) detected"
        
        suspicious_api_summary = "Clean" if not suspicious_api_signals else \
            f"{len(suspicious_api_signals)} suspicious decoding API(s) detected"
        
        # Add critical severity marker for high-risk combinations
        if len(non_visible_chars_signals) > 0 and len(suspicious_api_signals) > 0:
            non_visible_summary += " [CRITICAL: Combined with decoding APIs]"
            suspicious_api_summary += " [CRITICAL: Combined with obfuscated strings]"
        
        # Add special markers for extremely dangerous patterns
        eval_atob_count = sum(1 for signal in suspicious_api_signals 
                             if hasattr(signal, 'metadata') and 
                             signal.metadata.get('rule_id') == 'opengrep-rules.npm.js-eval-atob-combo')
        if eval_atob_count > 0:
            suspicious_api_summary += f" [DANGER: {eval_atob_count} eval(atob()) detected]"
        
        return {
            'has_non_visible_chars': len(non_visible_chars_signals) > 0,
            'has_suspicious_apis': len(suspicious_api_signals) > 0,
            'non_visible_chars_count': len(non_visible_chars_signals),
            'suspicious_apis_count': len(suspicious_api_signals),
            'non_visible_chars_summary': non_visible_summary,
            'suspicious_apis_summary': suspicious_api_summary,
            'has_critical_combination': len(non_visible_chars_signals) > 0 and len(suspicious_api_signals) > 0
        }
    
    def _format_install_hooks(self, install_hooks: list) -> str:
        """Format install hooks information for display."""
        if not install_hooks:
            return "None detected"
        
        hook_summaries = []
        for hook in install_hooks:
            risk_indicator = ""
            if hook['risk_level'] == 'high':
                risk_indicator = "[HIGH]"
            elif hook['risk_level'] == 'medium':
                risk_indicator = "[MED]"
            else:
                risk_indicator = "[LOW]"
            
            # Truncate long commands for display
            command = hook['command']
            if len(command) > 30:
                command = command[:27] + "..."
            
            hook_summaries.append(f"{hook['name']}: {command} {risk_indicator}")
        
        return " | ".join(hook_summaries)
    
    def _get_binary_files_trust_info(self, signals: List[Signal], package_path: str) -> Dict[str, str]:
        """Get trust indicator information about binary files."""
        binary_files = self._get_binary_files_info(signals, package_path)
        
        if not binary_files:
            return {
                'status': True,  # True = no binary files (safer)
                'value': 'No binaries detected'
            }
        
        # Format binary files information for display
        binary_summaries = []
        for binary in binary_files[:3]:  # Show max 3 files in trust indicator
            size_kb = binary['size'] // 1024 if binary['size'] > 1024 else binary['size']
            size_str = f"{size_kb}KB" if binary['size'] > 1024 else f"{binary['size']}B"
            hash_short = binary['sha256'][:8] + "..." if binary['sha256'] != "hash_calculation_failed" else "N/A"
            binary_summaries.append(f"{binary['name']} ({size_str}, {hash_short})")
        
        value = " | ".join(binary_summaries)
        if len(binary_files) > 3:
            value += f" + {len(binary_files) - 3} more"
            
        return {
            'status': False,  # False = binary files present (less secure)
            'value': value,
            'binary_files': binary_files  # Store full details for IOCs
        }
    
    def _is_repository_active(self, repository_url: str) -> bool:
        """Check if repository URL is active and accessible."""
        if not repository_url:
            return False
        
        try:
            import requests
            import time
            
            # Clean up the URL for HTTP request
            cleaned_url = repository_url
            if cleaned_url.startswith('git+'):
                cleaned_url = cleaned_url[4:]
            if cleaned_url.endswith('.git'):
                cleaned_url = cleaned_url[:-4]
            
            # Convert common git URLs to HTTP URLs
            if 'github.com' in cleaned_url:
                if cleaned_url.startswith('git@github.com:'):
                    cleaned_url = cleaned_url.replace('git@github.com:', 'https://github.com/')
                elif not cleaned_url.startswith('http'):
                    cleaned_url = 'https://github.com/' + cleaned_url.split('github.com/')[-1]
            
            # Make a HEAD request with timeout
            response = requests.head(cleaned_url, timeout=5, allow_redirects=True)
            return response.status_code < 400
            
        except Exception:
            # If we can't check the repository (network issues, etc.), return None
            # to indicate we couldn't determine the status
            return None
    
    def _is_recent_version(self, version: str) -> bool:
        """Check if version appears to be recent (basic heuristic)."""
        import re
        # Look for version patterns like 1.x.x, 2.x.x, etc. (not 0.0.x)
        version_pattern = r'^([1-9]\d*)\.\d+\.\d+'
        return bool(re.match(version_pattern, version))
    
    def _has_binary_files(self, signals: List[Signal], package_path: str) -> bool:
        """Check if the package contains binary files by analyzing signals and scanning directory."""
        binary_info = self._get_binary_files_info(signals, package_path)
        return len(binary_info) > 0
    
    def _get_binary_files_info(self, signals: List[Signal], package_path: str) -> List[Dict[str, str]]:
        """Get detailed information about binary files using content-based detection."""
        from pathlib import Path
        import logging
        import hashlib
        import string
        
        logger = logging.getLogger(__name__)
        logger.info(f"\033[1;35mScanning for binary files in package directory...\033[0m")
        
        binary_files = []
        
        # Common binary file extensions that are always binary regardless of content
        always_binary_extensions = {
            # Executables
            '.exe', '.msi', '.app', '.deb', '.rpm', '.dmg',
            # Shared libraries
            '.dll', '.so', '.dylib', '.lib', '.a',
            # Compiled code
            '.o', '.obj', '.pyc', '.pyo', '.class',
            # Archives
            '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
            # Images and media (suspicious in code packages)
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.wav', '.pdf',
            # WebAssembly and other binary formats
            '.wasm', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
            # Font files
            '.ttf', '.otf', '.woff', '.woff2', '.eot'
        }
        
        def _calculate_file_hash(file_path: Path) -> str:
            """Calculate SHA256 hash of a file."""
            try:
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    # Read file in chunks to handle large files
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(chunk)
                return sha256_hash.hexdigest()
            except Exception as e:
                logger.warning(f"Failed to calculate hash for {file_path}: {e}")
                return "hash_calculation_failed"
        
        def _is_binary_content(file_path: Path, max_check_size: int = 8192) -> tuple[bool, str]:
            """
            Determine if a file is binary based on its content.
            Returns (is_binary: bool, detection_method: str)
            """
            try:
                # Read a portion of the file for analysis
                with open(file_path, 'rb') as f:
                    chunk = f.read(max_check_size)
                
                if not chunk:
                    return False, "empty_file"  # Empty files are not binary
                
                # Method 1: Check for null bytes (strong binary indicator)
                if b'\x00' in chunk:
                    return True, "null_bytes"
                
                # Method 2: Check for excessive non-printable characters
                printable_chars = set(string.printable.encode())
                non_printable_count = sum(1 for byte in chunk if byte not in printable_chars)
                non_printable_ratio = non_printable_count / len(chunk)
                
                # If more than 30% of characters are non-printable, likely binary
                if non_printable_ratio > 0.30:
                    return True, f"non_printable_ratio_{non_printable_ratio:.2f}"
                
                # Method 3: Try to decode as UTF-8
                try:
                    chunk.decode('utf-8')
                    return False, "utf8_decodable"
                except UnicodeDecodeError:
                    # Try other common encodings
                    for encoding in ['latin-1', 'ascii']:
                        try:
                            chunk.decode(encoding)
                            return False, f"text_{encoding}"
                        except UnicodeDecodeError:
                            continue
                    
                    # If we can't decode with any common encoding, it's likely binary
                    return True, "encoding_failed"
                
            except Exception as e:
                logger.warning(f"Error checking file content for {file_path}: {e}")
                return False, "check_failed"
        
        # Scan the actual package directory for binary files
        try:
            package_dir = Path(package_path)
            if package_dir.exists() and package_dir.is_dir():
                # Skip common directories that contain non-malicious binaries
                skip_dirs = {
                    'node_modules', '.git', '__pycache__', 'venv', 'env', 
                    '.venv', 'build', 'dist', '.pytest_cache', '.mypy_cache'
                }
                
                # Recursively scan all files in the package
                for file_path in package_dir.rglob('*'):
                    if file_path.is_file():
                        # Skip files in ignored directories
                        if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                            continue
                        
                        # Skip very large files (>10MB) for performance
                        try:
                            if file_path.stat().st_size > 10 * 1024 * 1024:
                                continue
                        except OSError:
                            continue
                        
                        file_name = file_path.name.lower()
                        detection_method = None
                        
                        # First check: Always binary extensions
                        is_always_binary = any(file_name.endswith(ext) for ext in always_binary_extensions)
                        
                        if is_always_binary:
                            is_binary = True
                            detection_method = "always_binary_extension"
                        else:
                            # Content-based detection for other files
                            is_binary, detection_method = _is_binary_content(file_path)
                        
                        if is_binary:
                            logger.warning(f"\033[1;31mBinary file detected: {file_path} (method: {detection_method})\033[0m")
                            binary_files.append({
                                'name': file_path.name,
                                'path': str(file_path),
                                'size': file_path.stat().st_size,
                                'sha256': _calculate_file_hash(file_path),
                                'type': detection_method
                            })
                        
        
        except Exception as e:
            logger.error(f"Error scanning package directory {package_path}: {e}")
        
        logger.warning(f"\033[1;31mBinary file scan complete: {len(binary_files)} binary files detected\033[0m")
        
        # Remove duplicates (same path)
        seen_paths = set()
        unique_binary_files = []
        for binary_file in binary_files:
            path = binary_file['path']
            if path not in seen_paths:
                seen_paths.add(path)
                unique_binary_files.append(binary_file)
        
        return unique_binary_files
