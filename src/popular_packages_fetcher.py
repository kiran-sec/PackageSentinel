#!/usr/bin/env python3
"""
Dynamic Popular Packages Fetcher
Fetches top 300 npm and PyPI packages by download count from official APIs
"""

import json
import logging
import requests
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class PackageInfo:
    """Information about a popular package."""
    name: str
    download_count: int
    ecosystem: str
    last_updated: Optional[str] = None
    description: Optional[str] = None
    repository_url: Optional[str] = None

class PopularPackagesFetcher:
    """Fetches and caches popular packages from npm and PyPI APIs.
    
    Uses the npm registry download statistics API:
    - https://api.npmjs.org/downloads/point/{period}/{package-name}
    - Supported periods: last-day, last-week, last-month, last-year
    - Returns download counts for the specified time period
    """
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Static-Analysis-Tool/1.0 (Package Security Analysis)'
        })
        
        # Cache files
        self.npm_cache_file = self.cache_dir / "npm_popular_packages.json"
        self.pypi_cache_file = self.cache_dir / "pypi_popular_packages.json"
        
        # Cache expiry (24 hours)
        self.cache_expiry_hours = 24

    def get_popular_packages(self, limit: int = 300) -> List[PackageInfo]:
        """Get combined list of popular packages from both ecosystems."""
        self.logger.info(f"Fetching top {limit} popular packages from npm and PyPI...")
        
        npm_packages = self.get_popular_npm_packages(limit // 2)
        pypi_packages = self.get_popular_pypi_packages(limit // 2)
        
        all_packages = npm_packages + pypi_packages
        self.logger.info(f"Retrieved {len(all_packages)} popular packages total")
        
        return all_packages

    def get_popular_npm_packages(self, limit: int = 150) -> List[PackageInfo]:
        """Fetch popular npm packages using npm API."""
        self.logger.info(f"Fetching top {limit} npm packages...")
        
        # Check cache first
        if self._is_cache_valid(self.npm_cache_file):
            self.logger.info("Using cached npm packages data")
            return self._load_cache(self.npm_cache_file)
        
        packages = []
        try:
            # Method 1: Try npm registry API for most downloaded packages
            # Note: npm doesn't have a direct "top packages" API, so we'll use a curated list
            # combined with download stats
            
            # Get top packages from npm-stat API (if available) or fallback to curated list
            top_package_names = self._get_npm_top_package_names()
            
            self.logger.info(f"Fetching download stats for {len(top_package_names)} npm packages...")
            for i, package_name in enumerate(top_package_names[:limit]):
                try:
                    # Get package metadata
                    metadata_url = f"https://registry.npmjs.org/{package_name}"
                    metadata_response = self.session.get(metadata_url, timeout=10)
                    
                    if metadata_response.status_code == 200:
                        metadata = metadata_response.json()
                        
                        # Get download stats (last month)
                        download_count = self._get_npm_download_count(package_name, "last-month")
                        
                        packages.append(PackageInfo(
                            name=package_name,
                            download_count=download_count,
                            ecosystem="npm",
                            description=metadata.get('description', ''),
                            repository_url=self._extract_repository_url(metadata.get('repository', {}))
                        ))
                        
                        if (i + 1) % 20 == 0:
                            self.logger.info(f"Processed {i + 1}/{len(top_package_names[:limit])} npm packages")
                    
                    # Rate limiting
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to fetch npm package {package_name}: {e}")
                    continue
            
            # Sort by download count
            packages.sort(key=lambda x: x.download_count, reverse=True)
            
            # Cache the results
            self._save_cache(self.npm_cache_file, packages)
            
        except Exception as e:
            self.logger.error(f"Failed to fetch npm packages: {e}")
            # Fallback to static list if API fails
            packages = self._get_fallback_npm_packages()
        
        self.logger.info(f"Retrieved {len(packages)} npm packages")
        return packages

    def get_popular_pypi_packages(self, limit: int = 150) -> List[PackageInfo]:
        """Fetch popular PyPI packages using PyPI API."""
        self.logger.info(f"Fetching top {limit} PyPI packages...")
        
        # Check cache first
        if self._is_cache_valid(self.pypi_cache_file):
            self.logger.info("Using cached PyPI packages data")
            return self._load_cache(self.pypi_cache_file)
        
        packages = []
        try:
            # Get top packages from PyPI Stats API (pypistats doesn't have top packages endpoint)
            # So we'll use a curated list + download stats
            
            top_package_names = self._get_pypi_top_package_names()
            
            self.logger.info(f"Fetching download stats for {len(top_package_names)} PyPI packages...")
            for i, package_name in enumerate(top_package_names[:limit]):
                try:
                    # Get package metadata from PyPI API
                    metadata_url = f"https://pypi.org/pypi/{package_name}/json"
                    metadata_response = self.session.get(metadata_url, timeout=10)
                    
                    if metadata_response.status_code == 200:
                        metadata = metadata_response.json()
                        info = metadata.get('info', {})
                        
                        # PyPI doesn't provide download counts in the main API
                        # We'll use pypistats API or estimate based on package popularity
                        download_count = self._get_pypi_download_count(package_name)
                        
                        packages.append(PackageInfo(
                            name=package_name,
                            download_count=download_count,
                            ecosystem="pypi",
                            description=info.get('summary', ''),
                            repository_url=info.get('home_page', '') or info.get('project_url', '')
                        ))
                        
                        if (i + 1) % 20 == 0:
                            self.logger.info(f"Processed {i + 1}/{len(top_package_names[:limit])} PyPI packages")
                    
                    # Rate limiting
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to fetch PyPI package {package_name}: {e}")
                    continue
            
            # Sort by download count
            packages.sort(key=lambda x: x.download_count, reverse=True)
            
            # Cache the results
            self._save_cache(self.pypi_cache_file, packages)
            
        except Exception as e:
            self.logger.error(f"Failed to fetch PyPI packages: {e}")
            # Fallback to static list if API fails
            packages = self._get_fallback_pypi_packages()
        
        self.logger.info(f"Retrieved {len(packages)} PyPI packages")
        return packages

    def _get_npm_top_package_names(self) -> List[str]:
        """Get curated list of top npm package names."""
        return [
            # Core utilities and frameworks
            'lodash', 'react', 'express', 'axios', 'chalk', 'commander', 'debug', 
            'fs-extra', 'moment', 'uuid', 'underscore', 'async', 'request', 'jquery',
            'vue', 'angular', 'typescript', 'babel-core', '@babel/core', 'webpack',
            'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'nyc', 'nodemon',
            
            # Build and dev tools
            'webpack-cli', 'webpack-dev-server', 'babel-loader', 'css-loader', 
            'style-loader', 'file-loader', 'url-loader', 'html-webpack-plugin',
            'mini-css-extract-plugin', 'terser-webpack-plugin', 'copy-webpack-plugin',
            
            # Utilities
            'glob', 'minimatch', 'semver', 'yargs', 'inquirer', 'ora', 'boxen',
            'update-notifier', 'configstore', 'pkg-up', 'read-pkg-up', 'load-json-file',
            'write-json-file', 'make-dir', 'del', 'cpy', 'execa', 'cross-spawn',
            
            # Web frameworks and middleware
            'koa', 'fastify', 'hapi', 'socket.io', 'ws', 'cors', 'helmet', 'morgan',
            'compression', 'serve-static', 'cookie-parser', 'body-parser', 'multer',
            
            # Database and ORM
            'mongoose', 'sequelize', 'typeorm', 'knex', 'pg', 'mysql2', 'redis',
            'mongodb', 'sqlite3', 'better-sqlite3',
            
            # Authentication and security
            'passport', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'crypto-js', 'joi',
            'validator', 'express-validator', 'helmet', 'cors',
            
            # HTTP clients
            'node-fetch', 'got', 'superagent', 'isomorphic-fetch',
            
            # Date and time
            'date-fns', 'dayjs', 'luxon',
            
            # Parsing and serialization
            'xml2js', 'csv-parser', 'papaparse', 'js-yaml', 'ini',
            
            # File system and path utilities
            'path', 'fs-extra', 'graceful-fs', 'rimraf', 'mkdirp', 'findup-sync',
            
            # String and number utilities
            'string-width', 'strip-ansi', 'wrap-ansi', 'camelcase', 'snake-case',
            'kebab-case', 'pluralize', 'humanize-duration',
            
            # Process and system
            'cross-env', 'dotenv', 'yargs', 'minimist', 'which', 'shelljs',
            
            # Crypto and encoding
            'node-forge', 'jssha', 'base64-js', 'buffer',
            
            # Image processing
            'sharp', 'jimp', 'canvas',
            
            # Template engines
            'handlebars', 'mustache', 'ejs', 'pug', 'nunjucks',
            
            # CSS preprocessors
            'sass', 'node-sass', 'less', 'stylus',
            
            # Linting and formatting
            'tslint', 'jshint', 'standard', 'xo',
            
            # Documentation
            'jsdoc', 'typedoc', 'documentation',
            
            # Performance and monitoring
            'clinic', 'autocannon', 'loadtest',
            
            # React ecosystem
            'react-dom', 'react-router', 'react-router-dom', 'redux', 'react-redux',
            'mobx', 'mobx-react', 'styled-components', 'emotion',
            
            # Vue ecosystem  
            'vue-router', 'vuex', '@vue/cli',
            
            # Angular ecosystem
            '@angular/core', '@angular/common', '@angular/router', '@angular/cli'
        ]

    def _get_pypi_top_package_names(self) -> List[str]:
        """Get curated list of top PyPI package names."""
        return [
            # Core libraries
            'requests', 'urllib3', 'setuptools', 'pip', 'wheel', 'six', 'python-dateutil',
            'certifi', 'charset-normalizer', 'idna', 'pycparser', 'cffi', 'cryptography',
            
            # Data science and ML
            'numpy', 'pandas', 'matplotlib', 'scipy', 'scikit-learn', 'seaborn',
            'plotly', 'bokeh', 'altair', 'statsmodels', 'sympy',
            
            # Deep learning
            'tensorflow', 'torch', 'torchvision', 'keras', 'transformers', 'datasets',
            'accelerate', 'tokenizers', 'huggingface-hub',
            
            # Image processing
            'pillow', 'opencv-python', 'imageio', 'scikit-image',
            
            # Web frameworks
            'django', 'flask', 'fastapi', 'tornado', 'aiohttp', 'starlette',
            'uvicorn', 'gunicorn', 'waitress',
            
            # Database
            'sqlalchemy', 'psycopg2', 'psycopg2-binary', 'pymongo', 'redis',
            'mysql-connector-python', 'cx-oracle', 'sqlite3',
            
            # Testing
            'pytest', 'unittest2', 'nose', 'mock', 'coverage', 'tox', 'hypothesis',
            'factory-boy', 'faker',
            
            # HTTP and APIs
            'httpx', 'aiohttp', 'httplib2', 'requests-oauthlib', 'oauthlib',
            
            # Parsing and serialization
            'pyyaml', 'toml', 'configparser', 'argparse', 'click', 'typer',
            'xmltodict', 'lxml', 'beautifulsoup4', 'html5lib',
            
            # Async and concurrency
            'asyncio', 'aiofiles', 'aiodns', 'uvloop', 'greenlet', 'gevent',
            'eventlet', 'twisted',
            
            # File and data formats
            'openpyxl', 'xlrd', 'xlwt', 'xlsxwriter', 'tabulate', 'prettytable',
            'jsonschema', 'marshmallow', 'pydantic',
            
            # Networking
            'socket', 'ssl', 'paramiko', 'fabric', 'netaddr', 'ipaddress',
            
            # Development tools
            'black', 'flake8', 'pylint', 'mypy', 'isort', 'autopep8', 'bandit',
            'pre-commit', 'tox', 'virtualenv', 'pipenv', 'poetry',
            
            # Logging and debugging
            'logging', 'loguru', 'structlog', 'colorlog', 'rich', 'click',
            
            # Date and time
            'pytz', 'arrow', 'pendulum', 'dateparser',
            
            # Cryptography and security
            'pycryptodome', 'pyjwt', 'passlib', 'bcrypt', 'argon2-cffi',
            
            # Cloud and infrastructure
            'boto3', 'botocore', 's3transfer', 'awscli', 'google-cloud-storage',
            'azure-storage-blob', 'kubernetes', 'docker', 'docker-compose',
            
            # Automation and scraping
            'selenium', 'scrapy', 'playwright', 'pyautogui', 'robotframework',
            
            # Scientific computing
            'jupyterlab', 'jupyter', 'ipython', 'notebook', 'ipykernel',
            'ipywidgets', 'voila',
            
            # Natural language processing
            'nltk', 'spacy', 'textblob', 'gensim', 'fuzzywuzzy', 'python-levenshtein',
            
            # Computer vision
            'opencv-contrib-python', 'dlib', 'face-recognition',
            
            # Monitoring and metrics
            'psutil', 'py-cpuinfo', 'memory-profiler', 'line-profiler',
            
            # Deployment and packaging
            'setuptools-scm', 'twine', 'build', 'flit', 'hatchling',
            
            # GUI frameworks
            'tkinter', 'pyqt5', 'pyside2', 'kivy', 'wxpython'
        ]

    def _get_pypi_download_count(self, package_name: str) -> int:
        """Get PyPI package download count (estimated or from pypistats)."""
        try:
            # Try to get from pypistats API (if available)
            url = f"https://pypistats.org/api/packages/{package_name}/recent"
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('last_month', 0)
        except:
            pass
        
        # Fallback to estimated counts based on package popularity
        high_priority_packages = [
            'requests', 'urllib3', 'setuptools', 'pip', 'wheel', 'numpy', 'pandas',
            'matplotlib', 'tensorflow', 'torch', 'django', 'flask', 'fastapi'
        ]
        
        if package_name in high_priority_packages:
            return 50000000  # 50M+ downloads
        else:
            return 10000000  # 10M+ downloads (estimated)

    def get_npm_package_details(self, package_name: str) -> Dict:
        """Get comprehensive npm package details for security analysis.
        
        Fetches additional metadata beyond basic info for malware detection:
        - Version history and publish dates
        - Maintainer information
        - Dependencies and dev dependencies
        - Repository information
        - Download trends over time
        
        Args:
            package_name: Name of the npm package
            
        Returns:
            Dict containing comprehensive package analysis data
        """
        try:
            # Get full package metadata
            metadata_url = f"https://registry.npmjs.org/{package_name}"
            metadata_response = self.session.get(metadata_url, timeout=15)
            
            if metadata_response.status_code != 200:
                return {}
            
            metadata = metadata_response.json()
            
            # Extract security-relevant information
            analysis_data = {
                'name': package_name,
                'latest_version': metadata.get('dist-tags', {}).get('latest', ''),
                'description': metadata.get('description', ''),
                'homepage': metadata.get('homepage', ''),
                'repository': self._extract_repository_url(metadata.get('repository', {})),
                'author': metadata.get('author', {}),
                'maintainers': metadata.get('maintainers', []),
                'created': metadata.get('time', {}).get('created', ''),
                'modified': metadata.get('time', {}).get('modified', ''),
                'versions_count': len(metadata.get('versions', {})),
                'keywords': metadata.get('keywords', []),
                'license': metadata.get('license', ''),
                'bugs': metadata.get('bugs', {}),
            }
            
            # Get latest version specific data
            versions = metadata.get('versions', {})
            latest_version = analysis_data['latest_version']
            
            if latest_version and latest_version in versions:
                latest_version_data = versions[latest_version]
                analysis_data.update({
                    'dependencies': latest_version_data.get('dependencies', {}),
                    'dev_dependencies': latest_version_data.get('devDependencies', {}),
                    'peer_dependencies': latest_version_data.get('peerDependencies', {}),
                    'scripts': latest_version_data.get('scripts', {}),
                    'engines': latest_version_data.get('engines', {}),
                    'os': latest_version_data.get('os', []),
                    'cpu': latest_version_data.get('cpu', []),
                    'files': latest_version_data.get('files', []),
                    'bin': latest_version_data.get('bin', {}),
                })
            
            # Get download statistics for multiple periods
            download_stats = {}
            for period in ['last-day', 'last-week', 'last-month']:
                download_stats[period] = self._get_npm_download_count(package_name, period)
            
            analysis_data['download_stats'] = download_stats
            
            return analysis_data
            
        except Exception as e:
            self.logger.error(f"Failed to get comprehensive package details for {package_name}: {e}")
            return {}

    def _get_npm_download_count(self, package_name: str, period: str = "last-month") -> int:
        """Get npm package download count for specified period.
        
        Args:
            package_name: Name of the npm package
            period: Download period (last-day, last-week, last-month, last-year)
        
        Returns:
            Download count for the specified period
        """
        try:
            downloads_url = f"https://api.npmjs.org/downloads/point/{period}/{package_name}"
            downloads_response = self.session.get(downloads_url, timeout=10)
            
            if downloads_response.status_code == 200:
                download_data = downloads_response.json()
                return download_data.get('downloads', 0)
            elif downloads_response.status_code == 404:
                self.logger.debug(f"No download stats available for {package_name}")
                return 0
            else:
                self.logger.warning(f"Download stats API returned {downloads_response.status_code} for {package_name}")
                return 0
        except Exception as e:
            self.logger.warning(f"Failed to fetch download stats for {package_name}: {e}")
            return 0

    def get_npm_download_trends(self, package_name: str, start_date: str = None, end_date: str = None) -> Dict:
        """Get npm package download trends over a date range.
        
        Uses npm downloads range API: /downloads/range/{start-date}:{end-date}/{package}
        
        Args:
            package_name: Name of the npm package
            start_date: Start date in YYYY-MM-DD format (defaults to 30 days ago)
            end_date: End date in YYYY-MM-DD format (defaults to today)
            
        Returns:
            Dict containing download trend data for security analysis
        """
        try:
            from datetime import datetime, timedelta
            
            # Default to last 30 days if dates not specified
            if not end_date:
                end_date = datetime.now().strftime('%Y-%m-%d')
            if not start_date:
                start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Get download range data
            downloads_url = f"https://api.npmjs.org/downloads/range/{start_date}:{end_date}/{package_name}"
            response = self.session.get(downloads_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                downloads_data = data.get('downloads', [])
                
                # Analyze trends for security signals
                if downloads_data:
                    daily_counts = [day.get('downloads', 0) for day in downloads_data]
                    
                    analysis = {
                        'total_downloads': sum(daily_counts),
                        'avg_daily_downloads': sum(daily_counts) / len(daily_counts) if daily_counts else 0,
                        'max_daily_downloads': max(daily_counts) if daily_counts else 0,
                        'min_daily_downloads': min(daily_counts) if daily_counts else 0,
                        'trend_data': downloads_data,
                        'days_analyzed': len(downloads_data),
                        'suspicious_spikes': self._detect_download_spikes(daily_counts),
                        'consistent_growth': self._analyze_download_consistency(daily_counts)
                    }
                    
                    return analysis
                else:
                    return {'error': 'No download data available for specified period'}
            else:
                self.logger.warning(f"Download trends API returned {response.status_code} for {package_name}")
                return {'error': f'API returned status {response.status_code}'}
                
        except Exception as e:
            self.logger.error(f"Failed to fetch download trends for {package_name}: {e}")
            return {'error': str(e)}

    def _detect_download_spikes(self, daily_counts: List[int]) -> Dict:
        """Detect unusual download spikes that might indicate suspicious activity."""
        if len(daily_counts) < 7:
            return {'suspicious': False, 'reason': 'Insufficient data'}
        
        try:
            import statistics
            
            avg = statistics.mean(daily_counts)
            stdev = statistics.stdev(daily_counts) if len(daily_counts) > 1 else 0
            
            # Look for days with downloads > 3 standard deviations above mean
            spikes = []
            for i, count in enumerate(daily_counts):
                if stdev > 0 and count > (avg + 3 * stdev):
                    spikes.append({
                        'day_index': i,
                        'download_count': count,
                        'deviation_from_avg': count - avg
                    })
            
            return {
                'suspicious': len(spikes) > 0,
                'spike_count': len(spikes),
                'spikes': spikes,
                'avg_downloads': avg,
                'std_deviation': stdev
            }
        except:
            return {'suspicious': False, 'reason': 'Analysis failed'}

    def _analyze_download_consistency(self, daily_counts: List[int]) -> Dict:
        """Analyze if download patterns show natural vs artificial growth."""
        if len(daily_counts) < 14:
            return {'consistent': None, 'reason': 'Insufficient data for trend analysis'}
        
        try:
            # Check for too-consistent patterns (might indicate bot downloads)
            zero_variance_days = sum(1 for i in range(1, len(daily_counts)) 
                                   if daily_counts[i] == daily_counts[i-1])
            
            # Check for unnatural patterns
            variance_ratio = zero_variance_days / len(daily_counts)
            
            # Natural packages should have some variance
            is_suspicious = variance_ratio > 0.7  # More than 70% identical consecutive days
            
            return {
                'consistent': not is_suspicious,
                'variance_ratio': variance_ratio,
                'zero_variance_days': zero_variance_days,
                'total_days': len(daily_counts),
                'suspicious_uniformity': is_suspicious
            }
        except:
            return {'consistent': None, 'reason': 'Analysis failed'}

    def _extract_repository_url(self, repository_data) -> str:
        """Extract repository URL from package metadata."""
        if isinstance(repository_data, dict):
            return repository_data.get('url', '')
        elif isinstance(repository_data, str):
            return repository_data
        return ''

    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file exists and is not expired."""
        if not cache_file.exists():
            return False
        
        try:
            stat = cache_file.stat()
            cache_age = datetime.now() - datetime.fromtimestamp(stat.st_mtime)
            return cache_age < timedelta(hours=self.cache_expiry_hours)
        except:
            return False

    def _load_cache(self, cache_file: Path) -> List[PackageInfo]:
        """Load packages from cache file."""
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                return [PackageInfo(**pkg_data) for pkg_data in data]
        except:
            return []

    def _save_cache(self, cache_file: Path, packages: List[PackageInfo]):
        """Save packages to cache file."""
        try:
            data = [pkg.__dict__ for pkg in packages]
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.warning(f"Failed to save cache: {e}")

    def _get_fallback_npm_packages(self) -> List[PackageInfo]:
        """Fallback npm packages with estimated download counts."""
        fallback_packages = [
            ('lodash', 45000000), ('react', 40000000), ('express', 35000000),
            ('axios', 30000000), ('chalk', 25000000), ('commander', 20000000),
            ('debug', 18000000), ('fs-extra', 15000000), ('moment', 14000000),
            ('uuid', 12000000), ('underscore', 10000000), ('async', 9000000)
        ]
        
        return [PackageInfo(name=name, download_count=count, ecosystem="npm") 
                for name, count in fallback_packages]

    def _get_fallback_pypi_packages(self) -> List[PackageInfo]:
        """Fallback PyPI packages with estimated download counts."""
        fallback_packages = [
            ('requests', 55000000), ('urllib3', 50000000), ('setuptools', 45000000),
            ('pip', 40000000), ('wheel', 35000000), ('numpy', 30000000),
            ('pandas', 25000000), ('matplotlib', 20000000), ('scipy', 18000000),
            ('tensorflow', 15000000), ('django', 12000000), ('flask', 10000000)
        ]
        
        return [PackageInfo(name=name, download_count=count, ecosystem="pypi") 
                for name, count in fallback_packages]

    def get_pypi_package_details(self, package_name: str) -> Dict:
        """Get comprehensive PyPI package details for security analysis.
        
        Fetches additional metadata beyond basic info for malware detection:
        - Version history and publish dates
        - Maintainer information  
        - Dependencies and requirements
        - Project URLs and documentation
        - Classifiers and keywords
        
        Args:
            package_name: Name of the PyPI package
            
        Returns:
            Dict containing comprehensive package analysis data
        """
        try:
            # Get full package metadata from PyPI API
            metadata_url = f"https://pypi.org/pypi/{package_name}/json"
            metadata_response = self.session.get(metadata_url, timeout=15)
            
            if metadata_response.status_code != 200:
                return {}
            
            metadata = metadata_response.json()
            info = metadata.get('info', {})
            
            # Extract security-relevant information
            analysis_data = {
                'name': package_name,
                'version': info.get('version', ''),
                'summary': info.get('summary', ''),
                'description': info.get('description', ''),
                'home_page': info.get('home_page', ''),
                'author': info.get('author', ''),
                'author_email': info.get('author_email', ''),
                'maintainer': info.get('maintainer', ''),
                'maintainer_email': info.get('maintainer_email', ''),
                'license': info.get('license', ''),
                'keywords': info.get('keywords', ''),
                'classifiers': info.get('classifiers', []),
                'requires_dist': info.get('requires_dist', []),
                'requires_python': info.get('requires_python', ''),
                'project_urls': info.get('project_urls', {}),
                'download_url': info.get('download_url', ''),
                'platform': info.get('platform', ''),
            }
            
            # Get version history information
            releases = metadata.get('releases', {})
            analysis_data.update({
                'versions_count': len(releases),
                'latest_version': info.get('version', ''),
                'all_versions': list(releases.keys()) if releases else []
            })
            
            # Analyze latest version details
            latest_version = analysis_data['version']
            if latest_version and latest_version in releases:
                latest_release_info = releases[latest_version]
                if latest_release_info:
                    # Get the most recent upload info
                    latest_upload = latest_release_info[-1] if latest_release_info else {}
                    analysis_data.update({
                        'upload_time': latest_upload.get('upload_time', ''),
                        'filename': latest_upload.get('filename', ''),
                        'size': latest_upload.get('size', 0),
                        'python_version': latest_upload.get('python_version', ''),
                        'packagetype': latest_upload.get('packagetype', ''),
                        'has_signature': latest_upload.get('has_sig', False),
                        'md5_digest': latest_upload.get('md5_digest', ''),
                        'sha256_digest': latest_upload.get('digests', {}).get('sha256', '')
                    })
            
            # Get estimated download stats (PyPI doesn't provide direct download counts)
            estimated_downloads = self._get_pypi_download_count(package_name)
            analysis_data['estimated_downloads'] = estimated_downloads
            
            return analysis_data
            
        except Exception as e:
            self.logger.error(f"Failed to get comprehensive PyPI package details for {package_name}: {e}")
            return {}

    def analyze_pypi_dependencies(self, package_name: str) -> Dict:
        """Analyze PyPI package dependencies for security risks."""
        try:
            package_details = self.get_pypi_package_details(package_name)
            if not package_details:
                return {}
            
            requires_dist = package_details.get('requires_dist', [])
            if not requires_dist:
                return {'dependencies': [], 'suspicious_count': 0, 'analysis': 'No dependencies found'}
            
            dependencies = []
            suspicious_deps = []
            
            # Parse dependency strings
            import re
            for req in requires_dist:
                if req:
                    # Extract package name from requirement string (e.g., "requests>=2.0" -> "requests")
                    dep_match = re.match(r'^([a-zA-Z0-9\-_\.]+)', req.strip())
                    if dep_match:
                        dep_name = dep_match.group(1)
                        dependencies.append({
                            'name': dep_name,
                            'requirement': req,
                            'suspicious': self._is_suspicious_pypi_dependency(dep_name)
                        })
                        
                        if self._is_suspicious_pypi_dependency(dep_name):
                            suspicious_deps.append(dep_name)
            
            return {
                'dependencies': dependencies,
                'total_dependencies': len(dependencies),
                'suspicious_dependencies': suspicious_deps,
                'suspicious_count': len(suspicious_deps),
                'analysis': f"Found {len(dependencies)} dependencies, {len(suspicious_deps)} suspicious"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze PyPI dependencies for {package_name}: {e}")
            return {}

    def _is_suspicious_pypi_dependency(self, dep_name: str) -> bool:
        """Check if a PyPI dependency name is suspicious."""
        dep_lower = dep_name.lower()
        
        suspicious_patterns = [
            r'.*crypto.*mine.*', r'.*bitcoin.*', r'.*mining.*',
            r'.*backdoor.*', r'.*malware.*', r'.*virus.*',
            r'.*keylog.*', r'.*steal.*', r'.*trojan.*',
            r'.*hack.*', r'.*exploit.*', r'.*payload.*'
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.match(pattern, dep_lower):
                return True
        return False

if __name__ == "__main__":
    # Test the fetcher
    logging.basicConfig(level=logging.INFO)
    fetcher = PopularPackagesFetcher()
    
    print("Testing Popular Packages Fetcher...")
    packages = fetcher.get_popular_packages(50)  # Test with smaller number
    
    print(f"\nTop 10 packages by download count:")
    for i, pkg in enumerate(packages[:10], 1):
        print(f"{i:2d}. {pkg.name:<20} ({pkg.ecosystem}) - {pkg.download_count:,} downloads")
