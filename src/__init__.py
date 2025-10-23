"""
Static Analysis Core Module
Core components for multi-ecosystem package security analysis
"""

from .signal_collector import (
    PackageSignalAnalyzer, 
    OpenGrepSignalCollector, 
    MetadataSignalCollector,
    Signal, 
    SignalType, 
    Severity, 
    PackageMetadata, 
    AnalysisResult,
    Ecosystem
)

from .popular_packages_fetcher import (
    PopularPackagesFetcher,
    PackageInfo
)

from .package_fetcher import (
    PackageFetcher,
    fetch_package_by_ecosystem,
    RegistryConfig
)


__version__ = "1.0.0"
__all__ = [
    # Signal collection
    'PackageSignalAnalyzer',
    'OpenGrepSignalCollector', 
    'MetadataSignalCollector',
    'Signal',
    'SignalType',
    'Severity',
    'PackageMetadata',
    'AnalysisResult',
    'Ecosystem',
    
    # Package fetching
    'PopularPackagesFetcher',
    'PackageInfo',
    'PackageFetcher',
    'fetch_package_by_ecosystem',
    'RegistryConfig',
    
]
