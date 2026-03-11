from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import datetime

class StorageAdapter(ABC):
    """
    Abstract Base Class for defining where the Guardy library physically saves 
    valid and quarantined file bytes. (e.g., Local Disk, AWS S3)
    """
    @abstractmethod
    async def save_safe_file(self, filename: str, file_bytes: bytes) -> str:
        """Saves a safe file and returns the URI/Path it was stored at."""
        pass

    @abstractmethod
    async def save_quarantine_file(self, filename: str, file_bytes: bytes) -> str:
        """Saves a blocked/malicious file and returns the URI/Path it was stored at."""
        pass


class DatabaseAdapter(ABC):
    """
    Abstract Base Class for defining where the Guardy library logs its telemetry.
    Implementing this allows Guardy to automatically sync the Security Dashboard UI 
    with your database.
    """
    @abstractmethod
    async def log_upload_event(self, record: Dict[str, Any]) -> None:
        """Logs an entire FileAssessment metadata record."""
        pass

    @abstractmethod
    async def fetch_system_stats(self) -> Dict[str, int]:
        """Returns aggregate stats mapping for: [total_uploads, safe_uploads, blocked_uploads, quarantined]"""
        pass

    @abstractmethod
    async def fetch_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns the most recent upload records where is_safe=False"""
        pass

    @abstractmethod
    async def fetch_user_logs(self, user_id: str) -> List[Dict[str, Any]]:
        """Returns the complete upload history for a specific user"""
        pass
