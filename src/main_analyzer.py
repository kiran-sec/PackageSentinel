#!/usr/bin/env python3
"""
Multi-Ecosystem Package Signal Generator
Main script for analyzing npm and PyPI packages using OpenGrep rules
Generates structured signals for LLM-based malware analysis
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
import time

# Import our signal collection system
try:
    # Try relative imports first (when running as module)
    from .signal_collector import (
        PackageSignalAnalyzer, PackageMetadata, Ecosystem, 
        AnalysisResult, Signal, SignalType, Severity
    )
    from .package_fetcher import fetch_package_by_ecosystem
except ImportError:
    # Fallback to absolute imports (when running directly)
    from signal_collector import (
        PackageSignalAnalyzer, PackageMetadata, Ecosystem, 
        AnalysisResult, Signal, SignalType, Severity
    )
    from package_fetcher import fetch_package_by_ecosystem

def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('package_analysis.log')
        ]
    )

def extract_package_metadata(package_path: str, ecosystem: Ecosystem, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from package files, enhanced with remote metadata if available."""
    package_path = Path(package_path)
    
    if ecosystem == Ecosystem.NPM:
        return extract_npm_metadata(package_path, fetch_metadata)
    elif ecosystem == Ecosystem.PYPI:
        return extract_pypi_metadata(package_path, fetch_metadata)
    elif ecosystem == Ecosystem.VSIX:
        return extract_vsix_metadata(package_path, fetch_metadata)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")

def extract_npm_metadata(package_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from NPM package.json, enhanced with remote metadata if available."""
    package_json_path = package_path / "package.json"
    
    if not package_json_path.exists():
        logging.warning(f"No package.json found in {package_path}")
        return create_default_metadata(package_path, Ecosystem.NPM, fetch_metadata)
    
    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        # Calculate file statistics
        file_count, total_size = calculate_package_stats(package_path)
        
        # Use enhanced metadata if available from fetch
        enhanced_metadata = fetch_metadata.get('enhanced_metadata', {}) if fetch_metadata else {}
        
        # Prefer remote metadata over local when available
        publish_date = enhanced_metadata.get('publish_date') or None
        download_count = enhanced_metadata.get('download_count') or None
        weekly_download_count = enhanced_metadata.get('weekly_download_count') or None
        total_versions = enhanced_metadata.get('total_versions') or None
        total_dependants = enhanced_metadata.get('total_dependants') or None
        
        # Use GitHub URL from enhanced metadata if available
        repository_url = enhanced_metadata.get('github_repository_url') or get_repository_url(package_data.get('repository'))
        
        return PackageMetadata(
            ecosystem=Ecosystem.NPM,
            name=package_data.get('name', 'unknown'),
            version=package_data.get('version', '0.0.0'),
            author=str(package_data.get('author', 'unknown')),
            description=package_data.get('description', ''),
            dependencies=package_data.get('dependencies', {}),
            dev_dependencies=package_data.get('devDependencies', {}),
            scripts=package_data.get('scripts', {}),
            repository_url=repository_url,
            homepage_url=package_data.get('homepage'),
            license=package_data.get('license'),
            publish_date=publish_date,
            download_count=download_count,
            weekly_download_count=weekly_download_count,
            file_count=file_count,
            total_size=total_size,
            # Enhanced metadata fields
            total_versions=total_versions,
            total_dependants=total_dependants,
            registry_metadata=enhanced_metadata if enhanced_metadata else None
        )
    except Exception as e:
        logging.error(f"Error reading package.json: {e}")
        return create_default_metadata(package_path, Ecosystem.NPM, fetch_metadata)

def extract_pypi_metadata(package_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from Python package setup.py, setup.cfg, or pyproject.toml, enhanced with remote metadata if available."""
    
    # Try pyproject.toml first
    pyproject_path = package_path / "pyproject.toml"
    if pyproject_path.exists():
        return extract_pypi_metadata_from_pyproject(package_path, pyproject_path, fetch_metadata)
    
    # Try setup.cfg
    setup_cfg_path = package_path / "setup.cfg"
    if setup_cfg_path.exists():
        return extract_pypi_metadata_from_setup_cfg(package_path, setup_cfg_path, fetch_metadata)
    
    # Try setup.py (basic extraction)
    setup_py_path = package_path / "setup.py"
    if setup_py_path.exists():
        return extract_pypi_metadata_from_setup_py(package_path, setup_py_path, fetch_metadata)
    
    # Fallback to PKG-INFO or METADATA if available
    pkg_info_path = package_path / "PKG-INFO"
    metadata_path = package_path / "METADATA"
    if pkg_info_path.exists():
        return extract_pypi_metadata_from_pkg_info(package_path, pkg_info_path, fetch_metadata)
    elif metadata_path.exists():
        return extract_pypi_metadata_from_pkg_info(package_path, metadata_path, fetch_metadata)
    
    logging.warning(f"No Python package metadata found in {package_path}")
    return create_default_metadata(package_path, Ecosystem.PYPI, fetch_metadata)

def extract_pypi_metadata_from_pyproject(package_path: Path, pyproject_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from pyproject.toml."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # Fallback for older Python versions
        except ImportError:
            logging.error("tomllib/tomli not available for parsing pyproject.toml")
            return create_default_metadata(package_path, Ecosystem.PYPI, fetch_metadata)
    
    try:
        with open(pyproject_path, 'rb') as f:
            pyproject_data = tomllib.load(f)
        
        project = pyproject_data.get('project', {})
        file_count, total_size = calculate_package_stats(package_path)
        
        # Use enhanced metadata if available from fetch
        enhanced_metadata = fetch_metadata.get('enhanced_metadata', {}) if fetch_metadata else {}
        
        # Prefer remote metadata over local when available
        publish_date = enhanced_metadata.get('publish_date') or None
        download_count = enhanced_metadata.get('download_count') or None
        weekly_download_count = enhanced_metadata.get('weekly_download_count') or None
        total_versions = enhanced_metadata.get('total_versions') or None
        total_dependants = enhanced_metadata.get('total_dependants') or None
        
        # Use GitHub URL from enhanced metadata if available
        repository_url = enhanced_metadata.get('github_repository_url') or project.get('urls', {}).get('repository')
        
        return PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            name=project.get('name', 'unknown'),
            version=project.get('version', '0.0.0'),
            author=', '.join(author.get('name', '') for author in project.get('authors', [])),
            description=project.get('description', ''),
            dependencies={dep: "*" for dep in project.get('dependencies', [])},
            dev_dependencies={dep: "*" for dep in project.get('optional-dependencies', {}).get('dev', [])},
            scripts={},  # Would need more complex parsing
            repository_url=repository_url,
            homepage_url=project.get('urls', {}).get('homepage'),
            license=project.get('license', {}).get('text') if isinstance(project.get('license'), dict) else project.get('license'),
            publish_date=publish_date,
            download_count=download_count,
            weekly_download_count=weekly_download_count,
            file_count=file_count,
            total_size=total_size,
            # Enhanced metadata fields
            total_versions=total_versions,
            total_dependants=total_dependants,
            registry_metadata=enhanced_metadata if enhanced_metadata else None
        )
    except Exception as e:
        logging.error(f"Error reading pyproject.toml: {e}")
        return create_default_metadata(package_path, Ecosystem.PYPI, fetch_metadata)

def extract_pypi_metadata_from_setup_py(package_path: Path, setup_py_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract basic metadata from setup.py (limited parsing)."""
    try:
        with open(setup_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Basic regex-based extraction (limited but safe)
        import re
        
        name_match = re.search(r'name\s*=\s*[\'"]([^\'"]*)[\'"]', content)
        version_match = re.search(r'version\s*=\s*[\'"]([^\'"]*)[\'"]', content)
        author_match = re.search(r'author\s*=\s*[\'"]([^\'"]*)[\'"]', content)
        description_match = re.search(r'description\s*=\s*[\'"]([^\'"]*)[\'"]', content)
        
        file_count, total_size = calculate_package_stats(package_path)
        
        return PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            name=name_match.group(1) if name_match else 'unknown',
            version=version_match.group(1) if version_match else '0.0.0',
            author=author_match.group(1) if author_match else 'unknown',
            description=description_match.group(1) if description_match else '',
            dependencies={},  # Complex to extract from setup.py
            dev_dependencies={},
            scripts={},
            repository_url=None,
            homepage_url=None,
            license=None,
            publish_date=None,
            download_count=None,
            file_count=file_count,
            total_size=total_size
        )
    except Exception as e:
        logging.error(f"Error reading setup.py: {e}")
        return create_default_metadata(package_path, Ecosystem.PYPI)

def extract_pypi_metadata_from_setup_cfg(package_path: Path, setup_cfg_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from setup.cfg."""
    try:
        import configparser
        
        config = configparser.ConfigParser()
        config.read(setup_cfg_path)
        
        metadata_section = config.get('metadata', {}) if config.has_section('metadata') else {}
        file_count, total_size = calculate_package_stats(package_path)
        
        return PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            name=metadata_section.get('name', 'unknown'),
            version=metadata_section.get('version', '0.0.0'),
            author=metadata_section.get('author', 'unknown'),
            description=metadata_section.get('description', ''),
            dependencies={},  # Would need requirements parsing
            dev_dependencies={},
            scripts={},
            repository_url=metadata_section.get('url'),
            homepage_url=metadata_section.get('home_page'),
            license=metadata_section.get('license'),
            publish_date=None,
            download_count=None,
            file_count=file_count,
            total_size=total_size
        )
    except Exception as e:
        logging.error(f"Error reading setup.cfg: {e}")
        return create_default_metadata(package_path, Ecosystem.PYPI)

def extract_pypi_metadata_from_pkg_info(package_path: Path, pkg_info_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from PKG-INFO or METADATA file."""
    try:
        metadata = {}
        with open(pkg_info_path, 'r', encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key.strip()] = value.strip()
        
        file_count, total_size = calculate_package_stats(package_path)
        
        return PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            name=metadata.get('Name', 'unknown'),
            version=metadata.get('Version', '0.0.0'),
            author=metadata.get('Author', 'unknown'),
            description=metadata.get('Summary', ''),
            dependencies={},
            dev_dependencies={},
            scripts={},
            repository_url=metadata.get('Home-page'),
            homepage_url=metadata.get('Home-page'),
            license=metadata.get('License'),
            publish_date=None,
            download_count=None,
            file_count=file_count,
            total_size=total_size
        )
    except Exception as e:
        logging.error(f"Error reading PKG-INFO/METADATA: {e}")
        return create_default_metadata(package_path, Ecosystem.PYPI)

def extract_vsix_metadata(package_path: Path, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Extract metadata from VSIX extension file."""
    import zipfile
    import tempfile
    import shutil
    import json
    
    # VSIX files are ZIP archives - handle both file and directory inputs
    vsix_file = package_path
    
    # If input is a directory, look for .vsix files inside
    if package_path.is_dir():
        vsix_files = list(package_path.glob("*.vsix"))
        if not vsix_files:
            logging.warning(f"No .vsix files found in {package_path}")
            return create_default_metadata(package_path, Ecosystem.VSIX, fetch_metadata)
        vsix_file = vsix_files[0]
    
    # If input is not a directory, treat it as a direct VSIX file path
    elif package_path.is_file() and str(package_path).endswith('.vsix'):
        vsix_file = package_path
    
    else:
        logging.warning(f"Invalid VSIX input: {package_path}")
        return create_default_metadata(package_path, Ecosystem.VSIX, fetch_metadata)
    
    if not vsix_file.exists():
        logging.warning(f"VSIX file not found: {vsix_file}")
        return create_default_metadata(package_path, Ecosystem.VSIX, fetch_metadata)
    
    try:
        # Extract VSIX to temporary directory for analysis
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            with zipfile.ZipFile(vsix_file, 'r') as zip_ref:
                zip_ref.extractall(temp_path)
            
            # Look for extension manifest
            manifest_path = temp_path / "extension" / "package.json"
            if not manifest_path.exists():
                # Alternative locations
                for potential_manifest in [
                    temp_path / "package.json",
                    temp_path / "extension.vsixmanifest",
                ]:
                    if potential_manifest.exists():
                        manifest_path = potential_manifest
                        break
            
            # Parse package.json if it exists
            package_data = {}
            if manifest_path.exists() and str(manifest_path).endswith('.json'):
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        package_data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.warning(f"Error parsing {manifest_path}: {e}")
            
            # Look for extension.vsixmanifest (XML format)
            vsix_manifest_path = temp_path / "extension.vsixmanifest"
            if not package_data and vsix_manifest_path.exists():
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(vsix_manifest_path)
                    root = tree.getroot()
                    
                    # Extract basic info from VSIX manifest
                    identity = root.find('.//{http://schemas.microsoft.com/developer/vsx-schema/2011}Identity')
                    metadata = root.find('.//{http://schemas.microsoft.com/developer/vsx-schema/2011}Metadata')
                    
                    if identity is not None:
                        package_data['name'] = identity.get('Id', 'unknown')
                        package_data['version'] = identity.get('Version', '0.0.0')
                        package_data['publisher'] = identity.get('Publisher', 'unknown')
                    
                    if metadata is not None:
                        display_name = metadata.find('.//{http://schemas.microsoft.com/developer/vsx-schema/2011}DisplayName')
                        description = metadata.find('.//{http://schemas.microsoft.com/developer/vsx-schema/2011}Description')
                        
                        if display_name is not None:
                            package_data['displayName'] = display_name.text
                        if description is not None:
                            package_data['description'] = description.text
                            
                except Exception as e:
                    logging.warning(f"Error parsing VSIX manifest: {e}")
            
            # Calculate file statistics
            file_count = 0
            total_size = 0
            for root, dirs, files in os.walk(temp_path):
                file_count += len(files)
                for file in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, file))
                    except OSError:
                        pass
            
            # Use enhanced metadata if available from fetch
            enhanced_metadata = fetch_metadata.get('enhanced_metadata', {}) if fetch_metadata else {}
            
            return PackageMetadata(
                ecosystem=Ecosystem.VSIX,
                name=package_data.get('name', enhanced_metadata.get('name', 'unknown')),
                version=package_data.get('version', enhanced_metadata.get('version', '0.0.0')),
                author=package_data.get('publisher', package_data.get('author', enhanced_metadata.get('publisher', 'unknown'))),
                description=package_data.get('description', enhanced_metadata.get('description', '')),
                license=package_data.get('license', enhanced_metadata.get('license', '')),
                repository_url=package_data.get('repository', {}).get('url', '') if isinstance(package_data.get('repository'), dict) else package_data.get('repository', ''),
                homepage_url=package_data.get('homepage', enhanced_metadata.get('homepage', '')),
                dependencies=_extract_vsix_dependencies(package_data),
                dev_dependencies={},
                scripts=_extract_vsix_activation_events(package_data),
                keywords=package_data.get('keywords', package_data.get('categories', [])),
                engines=package_data.get('engines', {}),
                publish_date=enhanced_metadata.get('publish_date'),
                download_count=enhanced_metadata.get('download_count'),
                weekly_download_count=enhanced_metadata.get('weekly_download_count'),
                file_count=file_count,
                total_size=total_size,
                total_versions=enhanced_metadata.get('total_versions'),
                total_dependants=enhanced_metadata.get('total_dependants')
            )
            
    except Exception as e:
        logging.error(f"Error extracting VSIX metadata: {e}")
        return create_default_metadata(package_path, Ecosystem.VSIX, fetch_metadata)

def _extract_vsix_dependencies(package_data: dict) -> dict:
    """Extract VSIX extension dependencies."""
    dependencies = {}
    
    # Extension dependencies
    if 'extensionDependencies' in package_data:
        for dep in package_data['extensionDependencies']:
            dependencies[dep] = '*'
    
    # Extension packs
    if 'extensionPack' in package_data:
        for ext in package_data['extensionPack']:
            dependencies[ext] = '*'
    
    return dependencies

def _extract_vsix_activation_events(package_data: dict) -> dict:
    """Extract VSIX activation events as scripts equivalent."""
    scripts = {}
    
    if 'activationEvents' in package_data:
        scripts['activationEvents'] = ' && '.join(package_data['activationEvents'])
    
    if 'main' in package_data:
        scripts['main'] = package_data['main']
    
    return scripts

def create_default_metadata(package_path: Path, ecosystem: Ecosystem, fetch_metadata: Optional[Dict[str, Any]] = None) -> PackageMetadata:
    """Create default metadata when package files are not found."""
    file_count, total_size = calculate_package_stats(package_path)
    
    # Use enhanced metadata if available from fetch
    enhanced_metadata = fetch_metadata.get('enhanced_metadata', {}) if fetch_metadata else {}
    
    return PackageMetadata(
        ecosystem=ecosystem,
        name=enhanced_metadata.get('name', package_path.name),
        version=enhanced_metadata.get('latest_version', 'unknown'),
        author=enhanced_metadata.get('maintainers', 'unknown'),
        description='',
        dependencies={},
        dev_dependencies={},
        scripts={},
        repository_url=enhanced_metadata.get('github_repository_url'),
        homepage_url=None,
        license=None,
        publish_date=enhanced_metadata.get('publish_date'),
        download_count=enhanced_metadata.get('download_count'),
        weekly_download_count=enhanced_metadata.get('weekly_download_count'),
        file_count=file_count,
        total_size=total_size,
        total_versions=enhanced_metadata.get('total_versions'),
        total_dependants=enhanced_metadata.get('total_dependants'),
        registry_metadata=enhanced_metadata if enhanced_metadata else None
    )

def calculate_package_stats(package_path: Path) -> tuple[int, int]:
    """Calculate file count and total size of package."""
    file_count = 0
    total_size = 0
    
    try:
        for file_path in package_path.rglob('*'):
            if file_path.is_file():
                file_count += 1
                total_size += file_path.stat().st_size
    except Exception as e:
        logging.error(f"Error calculating package stats: {e}")
    
    return file_count, total_size

def get_repository_url(repo_data: Any) -> Optional[str]:
    """Extract repository URL from various npm package.json formats."""
    if not repo_data:
        return None
    
    if isinstance(repo_data, str):
        return repo_data
    elif isinstance(repo_data, dict):
        return repo_data.get('url')
    
    return None

def save_results(analysis_result: AnalysisResult, output_path: str, format_type: str = 'json') -> None:
    """Save analysis results to file."""
    output_path = Path(output_path)
    
    if format_type == 'json':
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_result.to_dict(), f, indent=2, ensure_ascii=False)
    elif format_type == 'llm':
        # Save LLM-formatted prompt
        analyzer = PackageSignalAnalyzer(str(Path(__file__).parent / "opengrep-rules"))
        llm_prompt = analyzer.format_for_llm_analysis(analysis_result)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(llm_prompt)
    elif format_type == 'table':
        # For table format, auto-save as JSON for programmatic access
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_result.to_dict(), f, indent=2, ensure_ascii=False)
    else:
        # Default fallback to JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_result.to_dict(), f, indent=2, ensure_ascii=False)
    
    logging.info(f"Results saved to {output_path}")

def auto_save_analysis(analysis_result: AnalysisResult, format_type: str = 'json') -> str:
    """Auto-save analysis results to analysis_output directory."""
    from datetime import datetime
    
    # Create analysis_output directory
    analysis_output_dir = Path("analysis_output")
    analysis_output_dir.mkdir(exist_ok=True)
    
    # Generate analysis filename
    package_name = analysis_result.package_metadata.name.replace("/", "_").replace("\\", "_")
    ecosystem = analysis_result.package_metadata.ecosystem.value
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extension = 'txt' if format_type == 'llm' else 'json'
    
    analysis_filename = f"{package_name}_{ecosystem}_{timestamp}.{extension}"
    analysis_path = analysis_output_dir / analysis_filename
    
    # Save the analysis
    save_results(analysis_result, str(analysis_path), format_type)
    
    return str(analysis_path)

def print_summary(analysis_result: AnalysisResult, table_width: int = None) -> None:
    """Print analysis results in 4 clean tables with customizable width."""
    
    # Get LLM context data
    llm_context = analysis_result.llm_context
    package_summary = llm_context.get('package_summary', {})
    trust_indicators = package_summary.get('trust_indicators', {})
    detailed_signals = llm_context.get('detailed_signals', {})
    
    # 1. Package Summary Table
    has_binary = package_summary.get('has_binary_files', False)
    binary_status = "\033[1;31mYes\033[0m" if has_binary else "\033[1;32mNo\033[0m"
    
    # Package source from analysis result
    package_source = analysis_result.package_source
    source_color = "\033[1;34mRemote\033[0m" if package_source == "remote" else "\033[1;37mLocal\033[0m"
    
    pkg_rows = [
        ["Name", package_summary.get('name', 'N/A')],
        ["Version", package_summary.get('version', 'N/A')],
        ["Ecosystem", package_summary.get('ecosystem', 'N/A')],
        ["Source", source_color],
        ["Author", package_summary.get('author', 'N/A')],
        ["Description", package_summary.get('description', 'N/A')[:60] + "..." if len(package_summary.get('description', '')) > 60 else package_summary.get('description', 'N/A')],
        ["License", package_summary.get('license', 'N/A')],
        ["Repository", package_summary.get('repository_url', 'N/A')],
        ["Files", f"{package_summary.get('file_count', 0)}"],
        ["Size", f"{package_summary.get('total_size', 0):,} bytes"],
        ["Dependencies", f"{len(package_summary.get('dependencies', {}))}"],
        ["Binary Files", binary_status]
    ]
    print_table("Package Summary", ["Field", "Value"], pkg_rows, table_width)
    
    # 2. Trust Indicators Table
    trust_rows = []
    for key, indicator_data in trust_indicators.items():
        display_key = key.replace('_', ' ').title()
        
        # Handle the new structure with status and value
        if isinstance(indicator_data, dict) and 'status' in indicator_data and 'value' in indicator_data:
            status = indicator_data['status']
            value = indicator_data['value']
            
            # Format status with colors
            if isinstance(status, bool):
                display_status = "\033[1;32mYes\033[0m" if status else "\033[1;31mNo\033[0m"
            else:
                display_status = str(status)
            
            # Format value for display - truncate if too long
            display_value = str(value)
            if len(display_value) > 60:
                display_value = display_value[:57] + "..."
            
            trust_rows.append([display_key, display_status, display_value])
        
        # Fallback for old format (if any remain)
        else:
            if isinstance(indicator_data, bool):
                display_status = "\033[1;32mYes\033[0m" if indicator_data else "\033[1;31mNo\033[0m"
            elif indicator_data is None:
                display_status = "\033[1;33mUnknown\033[0m"
            else:
                display_status = str(indicator_data)
            trust_rows.append([display_key, display_status, "N/A"])
    
    print_table("Trust Indicators", ["Indicator", "Status", "Value"], trust_rows, table_width)
    
    # 3. Signals Table
    signals_rows = []
    typosquatting_matches = []
    
    for signal_type, signals in detailed_signals.items():
        for signal in signals:
            # Format locations
            locations_str = ""
            if signal.get('locations'):
                location_parts = []
                for loc in signal['locations'][:2]:  # Max 2 locations
                    file_path = loc.get('file_path', 'unknown')
                    line_start = loc.get('line_start', 0)
                    line_end = loc.get('line_end', 0)
                    location_parts.append(f"{file_path}:{line_start}-{line_end}")
                locations_str = "; ".join(location_parts)
                if len(signal['locations']) > 2:
                    locations_str += f" (+{len(signal['locations'])-2} more)"
            
            signals_rows.append([
                signal_type.replace('_', ' ').title(),
                signal.get('title', 'N/A'),
                locations_str or 'N/A',
                signal.get('description', 'N/A')
            ])
            
            # Extract typosquatting matches for separate table
            if (signal_type == 'supply_chain_risk' and 
                signal.get('metadata', {}).get('matches')):
                typosquatting_matches.extend(signal['metadata']['matches'])
    
    print_table("Signals", ["Signal Type", "Title", "Locations", "Description"], signals_rows, table_width)
    
    # 3.5. Typosquatting Matches Table (if any matches found)
    if typosquatting_matches:
        match_rows = []
        for i, match in enumerate(typosquatting_matches[:10], 1):  # Top 10 matches
            match_rows.append([
                f"{i}",
                match.get('target_package', 'N/A'),
                match.get('ecosystem', 'N/A'),
                f"{match.get('download_count', 0):,}",
                match.get('algorithm', 'N/A'),
                f"{match.get('confidence', 0):.2f}"
            ])
        
        print_table("Potential Typosquatting Targets", 
                  ["#", "Target Package", "Ecosystem", "Downloads", "Detection Method", "Confidence"], 
                  match_rows, table_width)
    
    # 4. IOCs Table
    iocs_data = analysis_result.to_dict().get('iocs', {})
    iocs_rows = []
    for ioc_type, ioc_list in iocs_data.items():
        if ioc_list:  # Only show IOC types that have data
            display_type = ioc_type.replace('_', ' ').title()
            for ioc in ioc_list:
                iocs_rows.append([display_type, ioc])
            # Add empty row between different IOC types for clarity
            if ioc_list and ioc_type != list(iocs_data.keys())[-1]:
                iocs_rows.append(["", ""])
    
    print_table("IOCs (Indicators of Compromise)", ["Type", "Value"], iocs_rows, table_width)
    
    # Analysis Summary
    print(f"\n\033[1;36mAnalysis Summary\033[0m")
    print(f"   Total Signals: {len(analysis_result.signals)}")
    print(f"   Static Analysis Confidence: {analysis_result.static_analysis_confidence:.2f}")
    print(f"   Recommend Dynamic Analysis: {'YES' if analysis_result.recommend_dynamic_analysis else 'NO'}")
    if analysis_result.dynamic_analysis_reason:
        print(f"   Dynamic Analysis Reason: {analysis_result.dynamic_analysis_reason}")
    print(f"   Processing Time: {analysis_result.processing_time_ms}ms")
    
    if analysis_result.errors:
        print(f"\nErrors: {len(analysis_result.errors)}")
        for error in analysis_result.errors:
            print(f"  - {error}")

def print_table(title: str, headers: list, rows: list, max_width: int = None) -> None:
    """Print a formatted table with dynamic column sizing."""
    if not rows:
        print(f"\n\033[1;36m{title}\033[0m")
        print("   No data available")
        return
    
    # Get terminal width if max_width not specified
    if max_width is None:
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
            # Use 90% of terminal width to leave some margin
            max_width = min(200, max(120, int(terminal_width * 0.9)))
        except:
            max_width = 120  # Fallback to reasonable default
    
    # Calculate optimal column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                # Strip ANSI codes for width calculation
                cell_clean = str(cell)
                if '\033[' in cell_clean:
                    import re
                    cell_clean = re.sub(r'\033\[[0-9;]*m', '', cell_clean)
                col_widths[i] = max(col_widths[i], len(cell_clean))
    
    # Smart column width adjustment
    total_width = sum(col_widths) + len(headers) * 3 + 1
    if total_width > max_width:
        # Define column priorities and minimum widths
        if len(headers) == 4 and 'Description' in headers:  # Signals table
            min_widths = [12, 25, 20, 30]  # Signal Type, Title, Locations, Description
            priorities = [3, 2, 1, 4]      # Description gets most space
        elif len(headers) == 2 and 'Value' in headers:      # IOCs table
            min_widths = [15, 40]          # Type, Value
            priorities = [1, 2]            # Value gets more space
        else:  # Default for other tables
            min_widths = [max(10, len(h)) for h in headers]
            priorities = list(range(1, len(headers) + 1))
        
        # Apply minimum widths first
        for i in range(len(col_widths)):
            if i < len(min_widths):
                col_widths[i] = max(col_widths[i], min_widths[i])
        
        # If still too wide, reduce columns by priority (lowest priority first)
        new_total = sum(col_widths) + len(headers) * 3 + 1
        if new_total > max_width:
            excess = new_total - max_width
            # Create priority-sorted indices
            sorted_cols = sorted(range(len(priorities)), key=lambda x: priorities[x], reverse=True)
            
            # Reduce columns starting with lowest priority
            for col_idx in sorted_cols:
                if excess <= 0:
                    break
                if col_idx < len(col_widths):
                    min_width = min_widths[col_idx] if col_idx < len(min_widths) else 10
                    reduction = min(excess, col_widths[col_idx] - min_width)
                    col_widths[col_idx] -= reduction
                    excess -= reduction
    
    # Print table
    print(f"\n\033[1;36m{title}\033[0m")
    
    # Header
    header_line = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    print(header_line)
    
    header_row = "│" + "│".join(f" {headers[i]:<{col_widths[i]}} " for i in range(len(headers))) + "│"
    print(header_row)
    
    separator = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    print(separator)
    
    # Data rows with smart text wrapping
    for row in rows:
        # Handle multi-line content by splitting long cells
        max_lines = 1
        wrapped_cells = []
        
        for i, cell in enumerate(row):
            if i < len(col_widths):
                cell_str = str(cell)
                # Strip ANSI codes for length calculation
                cell_clean = cell_str
                if '\033[' in cell_clean:
                    import re
                    cell_clean = re.sub(r'\033\[[0-9;]*m', '', cell_clean)
                
                # Smart wrapping for long content
                if len(cell_clean) > col_widths[i]:
                    lines = []
                    words = cell_clean.split(' ')
                    current_line = ""
                    
                    for word in words:
                        if len(current_line + " " + word) <= col_widths[i]:
                            current_line += (" " if current_line else "") + word
                        else:
                            if current_line:
                                lines.append(current_line)
                                current_line = word
                            else:
                                # Single word longer than column, truncate
                                lines.append(word[:col_widths[i]-3] + "...")
                                current_line = ""
                    
                    if current_line:
                        lines.append(current_line)
                    
                    # Preserve color codes in original if present
                    if '\033[' in cell_str and lines:
                        # Apply original formatting to first line
                        color_match = re.search(r'\033\[[0-9;]*m', cell_str)
                        if color_match:
                            lines[0] = color_match.group() + lines[0] + "\033[0m"
                    
                    wrapped_cells.append(lines)
                    max_lines = max(max_lines, len(lines))
                else:
                    wrapped_cells.append([cell_str])
            else:
                wrapped_cells.append([""]) 
        
        # Print each line of the wrapped row
        for line_idx in range(max_lines):
            formatted_row = []
            for i, cell_lines in enumerate(wrapped_cells):
                if i < len(col_widths):
                    line_content = cell_lines[line_idx] if line_idx < len(cell_lines) else ""
                    
                    # Calculate padding accounting for ANSI codes
                    display_content = line_content
                    if '\033[' in display_content:
                        import re
                        clean_content = re.sub(r'\033\[[0-9;]*m', '', display_content)
                        padding = col_widths[i] - len(clean_content)
                    else:
                        padding = col_widths[i] - len(display_content)
                    
                    formatted_row.append(f" {display_content}{' ' * max(0, padding)} ")
            
            data_row = "│" + "│".join(formatted_row) + "│"
            print(data_row)
    
    # Footer
    footer_line = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"
    print(footer_line)

def main():
    """Main entry point for package analysis."""
    parser = argparse.ArgumentParser(
        description="Multi-Ecosystem Package Signal Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze local package directory
  python analyze.py --package ./suspicious-package --ecosystem npm
  
  # Fetch and analyze from official registry
  python analyze.py --fetch lodash --ecosystem npm --version 4.17.21
  
  # Analyze PyPI package with LLM output
  python analyze.py --fetch requests --ecosystem pypi --format llm --output analysis.txt
  
  # Verbose analysis with JSON output
  python analyze.py --package ./package --ecosystem npm --verbose --output results.json
        """
    )
    
    # Package source - either local path or fetch from registry
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('--package', '-p',
                             help='Path to local package directory to analyze')
    source_group.add_argument('--fetch', '-f',
                             help='Package name to fetch from official registry')
    
    parser.add_argument('--ecosystem', '-e', required=True, 
                       choices=['npm', 'pypi', 'vsix'],
                       help='Package ecosystem (npm, pypi, or vsix)')
    parser.add_argument('--version', 
                       default='latest',
                       help='Package version to fetch (only with --fetch, default: latest)')
    parser.add_argument('--output', '-o', 
                       help='Output file path (default: print to stdout)')
    parser.add_argument('--format', choices=['table', 'json', 'llm'], default='table',
                       help='Output format (table, json, or llm)')
    parser.add_argument('--table-width', type=int, default=None,
                       help='Maximum table width in characters (default: auto-detect terminal width)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--rules-path', 
                       default=str(Path(__file__).parent.parent / "opengrep-rules"),
                       help='Path to OpenGrep rules directory')
    parser.add_argument('--keep-downloaded', action='store_true',
                       help='Keep downloaded packages (only with --fetch)')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    try:
        # Handle package source (local path vs fetch from registry)
        package_path = None
        cleanup_needed = False
        
        if args.package:
            # Local package analysis
            package_path = Path(args.package)
            if not package_path.exists():
                logging.error(f"Package path does not exist: {package_path}")
                sys.exit(1)
            
            # For VSIX files, allow direct file input; for others, require directory
            if args.ecosystem == 'vsix':
                if not (package_path.is_dir() or (package_path.is_file() and str(package_path).endswith('.vsix'))):
                    logging.error(f"VSIX path must be a directory containing .vsix files or a .vsix file: {package_path}")
                    sys.exit(1)
            else:
                if not package_path.is_dir():
                    logging.error(f"Package path is not a directory: {package_path}")
                    sys.exit(1)
                
        elif args.fetch:
            # Fetch package from registry
            logging.info(f"Fetching {args.fetch}@{args.version} from {args.ecosystem} registry...")
            
            # Create ecosystem-specific directory for this package
            download_dir = Path("malware-samples") / args.ecosystem / f"{args.fetch}_{args.version}"
            download_dir.mkdir(parents=True, exist_ok=True)
            
            extracted_path, fetch_metadata = fetch_package_by_ecosystem(
                args.ecosystem, args.fetch, args.version, str(download_dir)
            )
            
            if not extracted_path:
                logging.error(f"Failed to fetch package: {fetch_metadata.get('error', 'Unknown error')}")
                sys.exit(1)
            
            package_path = Path(extracted_path)
            cleanup_needed = False  # Don't cleanup when storing in output directory
            
            logging.info(f"Package fetched successfully from {fetch_metadata.get('source', 'unknown')}")
            if args.verbose:
                logging.info(f"Downloaded to: {package_path}")
        
        else:
            logging.error("Either --package or --fetch must be specified")
            sys.exit(1)
        
        rules_path = Path(args.rules_path)
        if not rules_path.exists():
            logging.error(f"Rules path does not exist: {rules_path}")
            sys.exit(1)
        
        # Determine ecosystem
        if args.ecosystem == 'npm':
            ecosystem = Ecosystem.NPM
        elif args.ecosystem == 'pypi':
            ecosystem = Ecosystem.PYPI
        elif args.ecosystem == 'vsix':
            ecosystem = Ecosystem.VSIX
        else:
            logging.error(f"Unsupported ecosystem: {args.ecosystem}")
            sys.exit(1)
        
        # Extract package metadata
        logging.info(f"Extracting metadata for {ecosystem.value} package: {package_path}")
        # Pass fetch metadata if available for remote packages
        fetch_metadata_for_extraction = fetch_metadata if 'fetch_metadata' in locals() else None
        package_metadata = extract_package_metadata(str(package_path), ecosystem, fetch_metadata_for_extraction)
        
        # Initialize analyzer
        logging.info("Initializing package analyzer...")
        analyzer = PackageSignalAnalyzer(str(rules_path))
        
        # Perform analysis
        logging.info("Running comprehensive package analysis...")
        logging.info(f"Package: {package_metadata.name}@{package_metadata.version}")
        logging.info(f"Files to analyze: {package_metadata.file_count} files ({package_metadata.total_size:,} bytes)")
        # Determine package source
        package_source = "remote" if args.fetch else "local"
        
        analysis_result = analyzer.analyze_package(str(package_path), package_metadata, package_source)
        
        # Auto-save analysis to analysis_output directory
        auto_saved_path = auto_save_analysis(analysis_result, args.format)
        
        # Output results
        if args.output:
            save_results(analysis_result, args.output, args.format)
        else:
            if args.format == 'json':
                print(json.dumps(analysis_result.to_dict(), indent=2, ensure_ascii=False))
            elif args.format == 'llm':
                llm_prompt = analyzer.format_for_llm_analysis(analysis_result)
                print(llm_prompt)
            elif args.format == 'table':
                # Table output is handled in print_summary
                pass
        
        # Print summary for table format or when verbose
        if args.format == 'table' and not args.output:
            print_summary(analysis_result, args.table_width)
            print(f"\nAnalysis auto-saved to: {auto_saved_path}", file=sys.stderr)
        elif args.verbose:
            print_summary(analysis_result, args.table_width)
            print(f"\nAnalysis auto-saved to: {auto_saved_path}", file=sys.stderr)
        
        # Exit with appropriate code
        if analysis_result.errors:
            exit_code = 1
        elif analysis_result.recommend_dynamic_analysis:
            exit_code = 2  # Special exit code for dynamic analysis recommendation
        else:
            exit_code = 0
            
    except KeyboardInterrupt:
        logging.info("Analysis interrupted by user")
        exit_code = 130
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        exit_code = 1
    finally:
        # Cleanup downloaded packages if needed
        if cleanup_needed and package_path and package_path.exists():
            try:
                # Go up one level to remove the entire download directory
                download_dir = package_path.parent
                if download_dir.name.startswith('pkg_fetch_'):
                    shutil.rmtree(download_dir)
                    logging.info("Cleaned up downloaded package")
            except Exception as e:
                logging.warning(f"Failed to cleanup downloaded package: {e}")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
