"""
Guardy - A stateless, modular, multi-layer secure file analysis and threat intelligence framework.
"""

from .analyzer import FileAnalyzer, FileAssessment
from .config import GuardConfig
from .ui.dashboard import get_dashboard_router
from .ui.report import UserReportGenerator

# Modular Developer API
from .adapters import StorageAdapter, DatabaseAdapter, LocalDiskStorageAdapter, MongoDBDatabaseAdapter
from .engines import MLAnalyzer, PolyglotDetector, ZipBombDetector, MimeChecker, SignatureVerifier, ProtocolInspector

__all__ = [
    # Core Orchestrator
    "FileAnalyzer", 
    "FileAssessment",
    "GuardConfig",
    
    # UI Connectors
    "get_dashboard_router",
    "UserReportGenerator",
    
    # Storage Adapters
    "StorageAdapter",
    "DatabaseAdapter",
    "LocalDiskStorageAdapter",
    "MongoDBDatabaseAdapter",
    
    # Modular Engines
    "MLAnalyzer",
    "PolyglotDetector",
    "ZipBombDetector",
    "MimeChecker", 
    "SignatureVerifier", 
    "ProtocolInspector"
]
