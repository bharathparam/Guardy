import os
import uuid
import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import uvicorn
from cryptography.fernet import Fernet # to generate a test key

from guardy import FileAnalyzer, get_dashboard_router, UserReportGenerator

app = FastAPI(title="Backend App using Secure File Guard")

# --- 1. SET UP THE BACKEND STATE (Database & Storage) ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    db = mongo_client["guard_d_db"]
    files_collection = db["files"]
    print("Connected to MongoDB!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    # We will still run, but DB ops will fail or we can mock it.

# Create storage directories
SAFE_DIR = "storage/safe"
QUARANTINE_DIR = "storage/quarantine"
os.makedirs(SAFE_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Generate a dummy AES Encryption Key for this test
# (In production, load this securely from ENV)
ENCRYPTION_KEY = Fernet.generate_key()

# Instantiate the Stateless analyzer from our library
analyzer = FileAnalyzer()

# --- 2. DEFINE DATA FETCH CALLBACKS FOR THE LIBRARY DASHBOARD ---
async def fetch_system_stats():
    """Callback for the dashboard to get aggregate stats."""
    try:
        total = files_collection.count_documents({})
        safe = files_collection.count_documents({"is_safe": True})
        blocked = total - safe
        return {
            "total_uploads": total,
            "safe_uploads": safe,
            "blocked_uploads": blocked,
            "quarantined": blocked
        }
    except Exception:
        # Fallback if MongoDB is offline for testing
        return {"total_uploads": 0, "safe_uploads": 0, "blocked_uploads": 0, "quarantined": 0}

async def fetch_recent_alerts():
    """Callback for the dashboard to get recent flagged uploads."""
    try:
        docs = list(files_collection.find({"is_safe": False}).sort("timestamp", -1).limit(10))
        # Convert _id to string for template rendering
        alerts = []
        for d in docs:
            d["_id"] = str(d["_id"])
            alerts.append(d)
        return alerts
    except Exception:
        return []

# --- 3. MOUNT THE DASHBOARD ---
# The library provides the UI, the backend provides the data!
dashboard_router = get_dashboard_router(fetch_system_stats, fetch_recent_alerts)
app.include_router(dashboard_router)


# --- 4. CREATE THE UPLOAD ENDPOINT ---
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    user_id: str = Form("anonymous")
):
    try:
        # Read the file bytes into memory
        file_bytes = await file.read()
        
        # (Optional) Fetch user history to feed into the AI Engine
        user_history = []
        try:
            history_cursor = files_collection.find({"user_id": user_id}).sort("timestamp", -1).limit(50)
            user_history = [{"file_size": doc["size"]} for doc in history_cursor]
        except Exception:
            pass

        # === THE CORE SECURE FILE GUARD LIBRARY MAGIC ===
        assessment = analyzer.analyze_file(
            file_bytes=file_bytes,
            filename=file.filename,
            user_history_data=user_history,
            encryption_key=ENCRYPTION_KEY # Request encryption
        )
        
        # === BACKEND DECISION MAKING ===
        
        # 1. Determine where to save it
        store_dir = SAFE_DIR if assessment.is_safe else QUARANTINE_DIR
        stored_filename = f"{uuid.uuid4().hex}_{file.filename}"
        file_path = os.path.join(store_dir, stored_filename)
        
        # 2. Save the ENCRYPTED bytes to disk
        # (If we didn't use encryption_key above, we would save original file_bytes)
        bytes_to_save = assessment.encrypted_bytes if assessment.encrypted_bytes else file_bytes
        with open(file_path, "wb") as f:
            f.write(bytes_to_save)
            
        # 3. Save metadata to MongoDB
        record = {
            "user_id": user_id,
            "original_filename": file.filename,
            "stored_filename": stored_filename,
            "storage_path": file_path,
            "is_safe": assessment.is_safe,
            "risk_score": assessment.risk_score,
            "reasons": assessment.reasons,
            "detected_mime": assessment.detected_mime,
            "sha256_hash": assessment.sha256_hash,
            "size": len(file_bytes),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        
        try:
            files_collection.insert_one(record)
        except Exception as e:
            print(f"Warning: Failed to save to DB: {e}")
            
        # 4. Return response to user
        if not assessment.is_safe:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "BLOCKED",
                    "message": "Upload rejected due to security policies.",
                    "reasons": assessment.reasons
                }
            )
            
        return {"status": "SUCCESS", "message": "File uploaded safely.", "file_id": stored_filename}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/report/{user_id}")
async def get_user_report(user_id: str):
    """Example of using the UserReportGenerator from the library."""
    try:
        docs = list(files_collection.find({"user_id": user_id}))
        report = UserReportGenerator.generate_report(user_id, docs)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
