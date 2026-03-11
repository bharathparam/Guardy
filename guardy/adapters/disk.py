import os
import aiofiles
from typing import Optional
from .base import StorageAdapter

class LocalDiskStorageAdapter(StorageAdapter):
    """
    Saves approved and rejected files directly to local folders.
    """
    def __init__(self, safe_dir: str = "storage/safe", quarantine_dir: str = "storage/quarantine"):
        self.safe_dir = safe_dir
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.safe_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    async def save_safe_file(self, filename: str, file_bytes: bytes) -> str:
        filepath = os.path.join(self.safe_dir, filename)
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(file_bytes)
        return filepath

    async def save_quarantine_file(self, filename: str, file_bytes: bytes) -> str:
        filepath = os.path.join(self.quarantine_dir, filename)
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(file_bytes)
        return filepath
