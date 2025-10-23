#!/usr/bin/env python3
"""
Package Fetcher - Download packages from official repositories and mirrors
Supports npm and PyPI ecosystems with fallback mirror support
"""

import os
import json
import shutil
import tempfile
import tarfile
import zipfile
import requests
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PackageSource:
    """Configuration for a package repository source."""
    name: str
    base_url: str
    priority: int  # Lower number = higher priority
    auth_required: bool = False
    api_endpoint: Optional[str] = None

class RegistryConfig:
    """Registry configurations for different ecosystems."""
    
    NPM_SOURCES = [
        PackageSource("npm-official", "https://registry.npmjs.org/", 1),
        PackageSource("npm-taobao", "https://registry.npmmirror.com/", 2), 
        PackageSource("npm-cnpm", "https://r.cnpmjs.org/", 3),
        PackageSource("npm-yarn", "https://registry.yarnpkg.com/", 4),
        PackageSource("npm-github", "https://npm.pkg.github.com/", 5, auth_required=True),
    ]
    
    PYPI_SOURCES = [
        PackageSource("pypi-official", "https://pypi.org/", 1, api_endpoint="https://pypi.org/pypi/"),
        PackageSource("pypi-tsinghua", "https://pypi.tuna.tsinghua.edu.cn/", 2, api_endpoint="https://pypi.tuna.tsinghua.edu.cn/pypi/"),
        PackageSource("pypi-douban", "https://pypi.doubanio.com/", 3, api_endpoint="https://pypi.doubanio.com/pypi/"),
        PackageSource("pypi-aliyun", "https://mirrors.aliyun.com/pypi/", 4, api_endpoint="https://mirrors.aliyun.com/pypi/pypi/"),
        PackageSource("pypi-ustc", "https://pypi.mirrors.ustc.edu.cn/", 5, api_endpoint="https://pypi.mirrors.ustc.edu.cn/pypi/"),
    ]

class PackageFetcher:
    """Fetches packages from official repositories with mirror fallback."""
    
    def __init__(self, download_dir: Optional[str] = None):
        if download_dir:
            self.download_dir = Path(download_dir)
        else:
            self.download_dir = Path(tempfile.mkdtemp(prefix="pkg_fetch_"))
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.use_persistent_storage = bool(download_dir)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Multi-Ecosystem-Package-Analyzer/1.0'
        })
        
    def fetch_npm_package(self, package_name: str, version: str = "latest") -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Fetch npm package from registry with mirror fallback.
        
        Returns:
            Tuple of (extracted_path, metadata) or (None, error_info)
        """
        logger.info(f"Fetching npm package: {package_name}@{version}")
        
        for source in sorted(RegistryConfig.NPM_SOURCES, key=lambda x: x.priority):
            try:
                logger.debug(f"Trying npm source: {source.name}")
                
                # Get package metadata
                metadata_url = urljoin(source.base_url, package_name)
                response = self.session.get(metadata_url, timeout=30)
                
                if response.status_code == 404:
                    logger.debug(f"Package not found on {source.name}")
                    continue
                    
                response.raise_for_status()
                package_info = response.json()
                
                # Determine version to download
                if version == "latest":
                    version = package_info.get('dist-tags', {}).get('latest')
                
                if not version or version not in package_info.get('versions', {}):
                    logger.warning(f"Version {version} not found on {source.name}")
                    continue
                
                version_info = package_info['versions'][version]
                tarball_url = version_info.get('dist', {}).get('tarball')
                
                if not tarball_url:
                    logger.warning(f"No tarball URL found for {package_name}@{version} on {source.name}")
                    continue
                
                # Download and extract package
                extracted_path = self._download_and_extract_tarball(
                    tarball_url, f"{package_name}-{version}", "npm"
                )
                
                if extracted_path:
                    logger.info(f"Successfully fetched {package_name}@{version} from {source.name}")
                    
                    # Collect enhanced metadata
                    enhanced_metadata = self._collect_npm_metadata(package_name, package_info, version_info, version)
                    
                    return extracted_path, {
                        'source': source.name,
                        'package_info': version_info,
                        'full_package_info': package_info,
                        'download_url': tarball_url,
                        'enhanced_metadata': enhanced_metadata
                    }
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to fetch from {source.name}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error with {source.name}: {e}")
                continue
        
        logger.error(f"Failed to fetch {package_name}@{version} from all npm sources")
        return None, {'error': 'All npm sources failed'}
    
    def fetch_pypi_package(self, package_name: str, version: str = "latest") -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Fetch PyPI package from registry with mirror fallback.
        
        Returns:
            Tuple of (extracted_path, metadata) or (None, error_info)
        """
        logger.info(f"Fetching PyPI package: {package_name}@{version}")
        
        for source in sorted(RegistryConfig.PYPI_SOURCES, key=lambda x: x.priority):
            try:
                logger.debug(f"Trying PyPI source: {source.name}")
                
                # Get package metadata
                if source.api_endpoint:
                    metadata_url = urljoin(source.api_endpoint, f"{package_name}/json")
                else:
                    metadata_url = urljoin(source.base_url, f"pypi/{package_name}/json")
                
                response = self.session.get(metadata_url, timeout=30)
                
                if response.status_code == 404:
                    logger.debug(f"Package not found on {source.name}")
                    continue
                    
                response.raise_for_status()
                package_info = response.json()
                
                # Determine version to download
                if version == "latest":
                    version = package_info.get('info', {}).get('version')
                
                releases = package_info.get('releases', {})
                if version not in releases:
                    logger.warning(f"Version {version} not found on {source.name}")
                    continue
                
                # Find source distribution (prefer .tar.gz over .whl)
                version_files = releases[version]
                source_file = None
                
                # Prefer source distributions
                for file_info in version_files:
                    if file_info.get('packagetype') == 'sdist':
                        source_file = file_info
                        break
                
                # Fallback to wheel if no source dist
                if not source_file:
                    for file_info in version_files:
                        if file_info.get('packagetype') == 'bdist_wheel':
                            source_file = file_info
                            break
                
                if not source_file:
                    logger.warning(f"No downloadable files found for {package_name}@{version} on {source.name}")
                    continue
                
                download_url = source_file.get('url')
                if not download_url:
                    continue
                
                # Download and extract package
                extracted_path = self._download_and_extract_archive(
                    download_url, f"{package_name}-{version}", "pypi"
                )
                
                if extracted_path:
                    logger.info(f"Successfully fetched {package_name}@{version} from {source.name}")
                    
                    # Collect enhanced metadata
                    enhanced_metadata = self._collect_pypi_metadata(package_name, package_info)
                    
                    return extracted_path, {
                        'source': source.name,
                        'package_info': package_info.get('info', {}),
                        'full_package_info': package_info,
                        'file_info': source_file,
                        'download_url': download_url,
                        'enhanced_metadata': enhanced_metadata
                    }
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to fetch from {source.name}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error with {source.name}: {e}")
                continue
        
        logger.error(f"Failed to fetch {package_name}@{version} from all PyPI sources")
        return None, {'error': 'All PyPI sources failed'}
    
    def _download_and_extract_tarball(self, url: str, package_name: str, ecosystem: str) -> Optional[str]:
        """Download and extract npm tarball."""
        try:
            # Download tarball
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            
            # Save to temporary file
            tarball_path = self.download_dir / f"{package_name}.tgz"
            with open(tarball_path, 'wb') as f:
                f.write(response.content)
            
            # Extract tarball
            extract_path = self.download_dir / package_name
            extract_path.mkdir(exist_ok=True)
            
            with tarfile.open(tarball_path, 'r:gz') as tar:
                # npm packages typically have a 'package' directory in the tarball
                tar.extractall(extract_path)
                
                # Find the actual package directory
                package_dir = extract_path / "package"
                if package_dir.exists():
                    return str(package_dir)
                
                # Fallback: return the extraction directory if no 'package' subdir
                extracted_items = list(extract_path.iterdir())
                if len(extracted_items) == 1 and extracted_items[0].is_dir():
                    return str(extracted_items[0])
                
                return str(extract_path)
            
        except Exception as e:
            logger.error(f"Failed to download/extract tarball from {url}: {e}")
            return None
    
    def _download_and_extract_archive(self, url: str, package_name: str, ecosystem: str) -> Optional[str]:
        """Download and extract PyPI archive (.tar.gz or .whl)."""
        try:
            # Download archive
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            
            # Determine file type and extension
            filename = urlparse(url).path.split('/')[-1]
            archive_path = self.download_dir / filename
            
            with open(archive_path, 'wb') as f:
                f.write(response.content)
            
            # Extract archive
            extract_path = self.download_dir / package_name
            extract_path.mkdir(exist_ok=True)
            
            if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(extract_path)
            elif filename.endswith('.zip') or filename.endswith('.whl'):
                with zipfile.ZipFile(archive_path, 'r') as zip_file:
                    zip_file.extractall(extract_path)
            else:
                logger.error(f"Unsupported archive format: {filename}")
                return None
            
            # Find the actual package directory
            extracted_items = list(extract_path.iterdir())
            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                return str(extracted_items[0])
            
            return str(extract_path)
            
        except Exception as e:
            logger.error(f"Failed to download/extract archive from {url}: {e}")
            return None
    
    def _collect_npm_metadata(self, package_name: str, package_info: Dict, version_info: Dict, version: str = None) -> Dict[str, Any]:
        """Collect enhanced metadata from npm registry."""
        try:
            enhanced_metadata = {
                'download_count': None,
                'weekly_download_count': None,
                'total_versions': len(package_info.get('versions', {})),
                'total_dependants': None,
                'publish_date': package_info.get('time', {}).get(version or version_info.get('version')) or version_info.get('publishTime'),
                'github_repository_url': None,
                'latest_version': package_info.get('dist-tags', {}).get('latest'),
                'all_versions': list(package_info.get('versions', {}).keys()),
                'maintainers': package_info.get('maintainers', []),
                'keywords': version_info.get('keywords', []),
                'bugs_url': version_info.get('bugs', {}).get('url') if isinstance(version_info.get('bugs'), dict) else version_info.get('bugs')
            }
            
            # Extract GitHub repository URL
            repository = version_info.get('repository', {})
            if isinstance(repository, dict):
                repo_url = repository.get('url', '')
            elif isinstance(repository, str):
                repo_url = repository
            else:
                repo_url = ''
            
            # Normalize GitHub URL
            if repo_url:
                if 'github.com' in repo_url:
                    # Clean up various GitHub URL formats
                    if repo_url.startswith('git+'):
                        repo_url = repo_url[4:]
                    if repo_url.endswith('.git'):
                        repo_url = repo_url[:-4]
                    if repo_url.startswith('git@github.com:'):
                        repo_url = repo_url.replace('git@github.com:', 'https://github.com/')
                    elif 'github.com/' in repo_url and not repo_url.startswith('http'):
                        repo_url = 'https://github.com/' + repo_url.split('github.com/')[-1]
                    
                    enhanced_metadata['github_repository_url'] = repo_url
            
            # Try to get download counts from npm download stats API (both monthly and weekly)
            try:
                # Monthly downloads
                monthly_url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
                monthly_response = self.session.get(monthly_url, timeout=10)
                if monthly_response.status_code == 200:
                    monthly_data = monthly_response.json()
                    enhanced_metadata['download_count'] = monthly_data.get('downloads', 0)
                
                # Weekly downloads
                weekly_url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
                weekly_response = self.session.get(weekly_url, timeout=10)
                if weekly_response.status_code == 200:
                    weekly_data = weekly_response.json()
                    enhanced_metadata['weekly_download_count'] = weekly_data.get('downloads', 0)
                
                logger.debug(f"Downloads - Monthly: {enhanced_metadata['download_count']}, Weekly: {enhanced_metadata['weekly_download_count']}")
            except Exception as e:
                logger.debug(f"Failed to fetch download counts for {package_name}: {e}")
            
            # Try to get dependants count from multiple sources
            dependants_count = self._get_npm_dependants(package_name)
            if dependants_count is not None:
                enhanced_metadata['total_dependants'] = dependants_count
            
            logger.info(f"Collected enhanced npm metadata: {enhanced_metadata['total_versions']} versions, monthly downloads: {enhanced_metadata['download_count']}, weekly downloads: {enhanced_metadata['weekly_download_count']}, dependants: {enhanced_metadata['total_dependants']}")
            return enhanced_metadata
            
        except Exception as e:
            logger.warning(f"Failed to collect enhanced npm metadata: {e}")
            return {}
    
    def _get_npm_dependants(self, package_name: str) -> Optional[int]:
        """Get the number of dependants for an npm package using multiple sources."""
        # Try multiple approaches to get dependants count
        
        # Method 1: Libraries.io API
        dependants_count = self._get_dependants_from_libraries_io(package_name, 'npm')
        if dependants_count is not None:
            return dependants_count
        
        # Method 2: NPM API (unofficial endpoint)
        dependants_count = self._get_dependants_from_npm_api(package_name)
        if dependants_count is not None:
            return dependants_count
        
        # Method 3: Web scraping from npm website
        dependants_count = self._get_dependants_from_npm_web(package_name)
        if dependants_count is not None:
            return dependants_count
        
        logger.debug(f"Could not retrieve dependants count for {package_name}")
        return None
    
    def _get_dependants_from_libraries_io(self, package_name: str, platform: str) -> Optional[int]:
        """Get dependants count from Libraries.io API."""
        try:
            # Libraries.io provides comprehensive package information including dependents
            url = f"https://libraries.io/api/{platform}/{package_name}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                dependents_count = data.get('dependents_count', 0)
                logger.debug(f"Libraries.io: {package_name} has {dependents_count} dependents")
                return dependents_count
            elif response.status_code == 404:
                logger.debug(f"Package {package_name} not found on Libraries.io")
                return None
            else:
                logger.debug(f"Libraries.io API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.debug(f"Failed to get dependants from Libraries.io: {e}")
            return None
    
    def _get_dependants_from_npm_api(self, package_name: str) -> Optional[int]:
        """Get dependants count from npm API (unofficial endpoint)."""
        try:
            # Try npm's internal API that powers the dependents tab
            url = f"https://www.npmjs.com/browse/depended/{package_name}"
            headers = {
                'Accept': 'application/json',
                'User-Agent': self.session.headers.get('User-Agent')
            }
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                # Try to parse if it's JSON
                try:
                    data = response.json()
                    if 'total' in data:
                        dependents_count = data['total']
                        logger.debug(f"NPM API: {package_name} has {dependents_count} dependents")
                        return dependents_count
                except ValueError:
                    pass
            
            logger.debug(f"NPM API endpoint did not provide dependents data for {package_name}")
            return None
            
        except Exception as e:
            logger.debug(f"Failed to get dependants from npm API: {e}")
            return None
    
    def _get_dependants_from_npm_web(self, package_name: str) -> Optional[int]:
        """Get dependants count by scraping npm website."""
        try:
            import re
            
            # Get the package page with dependents tab
            url = f"https://www.npmjs.com/package/{package_name}?activeTab=dependents"
            
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                content = response.text
                
                # Look for patterns that indicate dependents count
                # NPM shows patterns like "123,456 packages depend on lodash"
                patterns = [
                    r'([\d,]+)\s+packages?\s+depend\s+on\s+' + re.escape(package_name),
                    r'Dependents\s*\(([\d,]+)\)',
                    r'"dependentsCount":\s*(\d+)',
                    r'dependents["\']?:\s*["\']?(\d+)',
                    r'([\d,]+)\s*dependents?'
                ]
                
                for pattern in patterns:
                    matches = re.search(pattern, content, re.IGNORECASE)
                    if matches:
                        count_str = matches.group(1).replace(',', '')
                        try:
                            dependents_count = int(count_str)
                            logger.debug(f"NPM Web: {package_name} has {dependents_count} dependents (via pattern: {pattern})")
                            return dependents_count
                        except ValueError:
                            continue
                
                logger.debug(f"Could not parse dependents count from NPM web page for {package_name}")
                return None
            else:
                logger.debug(f"Failed to access NPM web page for {package_name}: {response.status_code}")
                return None
            
        except Exception as e:
            logger.debug(f"Failed to scrape dependants from npm website: {e}")
            return None
    
    def _collect_pypi_metadata(self, package_name: str, package_info: Dict) -> Dict[str, Any]:
        """Collect enhanced metadata from PyPI registry."""
        try:
            info = package_info.get('info', {})
            releases = package_info.get('releases', {})
            urls = package_info.get('urls', [])
            
            enhanced_metadata = {
                'download_count': None,
                'weekly_download_count': None,
                'total_versions': len(releases),
                'total_dependants': None,
                'publish_date': None,
                'github_repository_url': None,
                'latest_version': info.get('version'),
                'all_versions': list(releases.keys()),
                'maintainers': info.get('maintainer', ''),
                'keywords': info.get('keywords', '').split(',') if info.get('keywords') else [],
                'classifier': info.get('classifiers', []),
                'project_urls': info.get('project_urls', {})
            }
            
            # Extract GitHub repository URL
            github_url = None
            
            # Check project URLs first
            project_urls = info.get('project_urls', {})
            if project_urls:
                for key, url in project_urls.items():
                    if url and 'github.com' in url.lower():
                        github_url = url
                        break
            
            # Fallback to home_page
            if not github_url:
                home_page = info.get('home_page', '')
                if home_page and 'github.com' in home_page:
                    github_url = home_page
            
            # Fallback to download_url
            if not github_url:
                download_url = info.get('download_url', '')
                if download_url and 'github.com' in download_url:
                    github_url = download_url
                    
            enhanced_metadata['github_repository_url'] = github_url
            
            # Get the most recent version's publish date
            latest_version = info.get('version')
            if latest_version and latest_version in releases:
                version_files = releases[latest_version]
                if version_files:
                    # Get upload time from the first file in the latest version
                    upload_time = version_files[0].get('upload_time')
                    if upload_time:
                        enhanced_metadata['publish_date'] = upload_time
            
            # Try to get download statistics from pypistats API (both monthly and weekly)
            try:
                # Monthly and weekly downloads from pypistats
                stats_url = f"https://pypistats.org/api/packages/{package_name}/recent"
                stats_response = self.session.get(stats_url, timeout=10)
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    data = stats_data.get('data', {})
                    enhanced_metadata['download_count'] = data.get('last_month', 0)
                    enhanced_metadata['weekly_download_count'] = data.get('last_week', 0)
                    logger.debug(f"PyPI Downloads - Monthly: {enhanced_metadata['download_count']}, Weekly: {enhanced_metadata['weekly_download_count']}")
                else:
                    logger.debug(f"Failed to get download stats for {package_name}: {stats_response.status_code}")
            except Exception as e:
                logger.debug(f"Failed to fetch download stats for {package_name}: {e}")
            
            # Try to get dependants count
            dependants_count = self._get_dependants_from_libraries_io(package_name, 'pypi')
            if dependants_count is not None:
                enhanced_metadata['total_dependants'] = dependants_count
            
            logger.info(f"Collected enhanced PyPI metadata: {enhanced_metadata['total_versions']} versions, monthly downloads: {enhanced_metadata['download_count']}, weekly downloads: {enhanced_metadata['weekly_download_count']}, GitHub: {bool(github_url)}")
            return enhanced_metadata
            
        except Exception as e:
            logger.warning(f"Failed to collect enhanced PyPI metadata: {e}")
            return {}
    
    def cleanup(self):
        """Clean up downloaded files (only if using temporary storage)."""
        if not self.use_persistent_storage and self.download_dir.exists():
            shutil.rmtree(self.download_dir)
            logger.info(f"Cleaned up download directory: {self.download_dir}")
        elif self.use_persistent_storage:
            logger.info(f"Preserved downloaded package in: {self.download_dir}")

def fetch_package_by_ecosystem(ecosystem: str, package_name: str, version: str = "latest", 
                              download_dir: Optional[str] = None) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Convenience function to fetch package by ecosystem.
    
    Args:
        ecosystem: 'npm' or 'pypi'
        package_name: Name of the package
        version: Version to fetch (default: 'latest')
        download_dir: Directory to download to (default: temp dir)
        
    Returns:
        Tuple of (extracted_path, metadata) or (None, error_info)
    """
    fetcher = PackageFetcher(download_dir)
    
    try:
        if ecosystem.lower() == 'npm':
            return fetcher.fetch_npm_package(package_name, version)
        elif ecosystem.lower() == 'pypi':
            return fetcher.fetch_pypi_package(package_name, version)
        else:
            return None, {'error': f'Unsupported ecosystem: {ecosystem}'}
    except Exception as e:
        logger.error(f"Failed to fetch {ecosystem} package {package_name}@{version}: {e}")
        return None, {'error': str(e)}

# CLI interface
def main():
    """Command-line interface for package fetcher."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Fetch packages from official repositories")
    parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Package ecosystem')
    parser.add_argument('package', help='Package name')
    parser.add_argument('--version', default='latest', help='Package version (default: latest)')
    parser.add_argument('--output', '-o', help='Output directory (default: temp dir)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Fetch package
    extracted_path, metadata = fetch_package_by_ecosystem(
        args.ecosystem, args.package, args.version, args.output
    )
    
    if extracted_path:
        print(f"✅ Successfully fetched {args.package}@{args.version}")
        print(f"📁 Extracted to: {extracted_path}")
        print(f"🔗 Source: {metadata.get('source', 'unknown')}")
        if args.verbose:
            print(f"📊 Metadata: {json.dumps(metadata, indent=2)}")
    else:
        print(f"❌ Failed to fetch {args.package}@{args.version}")
        print(f"📝 Error: {metadata.get('error', 'Unknown error')}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
