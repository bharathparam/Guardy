from typing import Dict, Any, List
from .base import DatabaseAdapter

class MongoDBDatabaseAdapter(DatabaseAdapter):
    """
    Automatically tracks user histories and logs AI Telemetry 
    into a MongoDB `files` collection for the Security Dashboard.
    """
    def __init__(self, collection):
        """Pass the PyMongo/Motor initialized collection: `db['files']`"""
        self.collection = collection

    async def log_upload_event(self, record: Dict[str, Any]) -> None:
        """Insert the FileAssessment directly to Mongo."""
        try:
            # Note: For async contexts like FastAPI, `motor` is ideal, 
            # but we assume the provided collection can handle insertion.
            if hasattr(self.collection, 'insert_one_async'): # e.g., Motor
                await self.collection.insert_one_async(record)
            else: # Standard PyMount -> blocking
                self.collection.insert_one(record)
        except Exception as e:
            print(f"MongoDBAdapter insert failed: {e}")

    async def fetch_system_stats(self) -> Dict[str, int]:
        try:
            # Handle sync (pymongo) vs async (motor) seamlessly
            count_docs = self.collection.count_documents
            if __import__('inspect').iscoroutinefunction(count_docs):
                total = await count_docs({})
                safe = await count_docs({"is_safe": True})
            else:
                total = count_docs({})
                safe = count_docs({"is_safe": True})
            
            blocked = total - safe
            return {
                "total_uploads": total,
                "safe_uploads": safe,
                "blocked_uploads": blocked,
                "quarantined": blocked
            }
        except Exception:
            return {"total_uploads": 0, "safe_uploads": 0, "blocked_uploads": 0, "quarantined": 0}

    async def fetch_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        try:
            cursor = self.collection.find({"is_safe": False}).sort("timestamp", -1).limit(limit)
            
            # Handle sync vs async cursor conversion
            if hasattr(cursor, 'to_list'): # Motor async
                docs = await cursor.to_list(length=limit)
            else: # PyMongo sync 
                docs = list(cursor)
                
            for d in docs: d["_id"] = str(d["_id"])
            return docs
        except Exception:
            return []

    async def fetch_user_logs(self, user_id: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.collection.find({"user_id": user_id}).sort("timestamp", -1)
            
            # Handle sync vs async cursor conversion
            if hasattr(cursor, 'to_list'): # Motor async
                docs = await cursor.to_list(length=None)
            else: # PyMongo sync 
                docs = list(cursor)
                
            for d in docs: d["_id"] = str(d["_id"])
            return docs
        except Exception:
            return []
