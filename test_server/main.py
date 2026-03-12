import os
import uuid
import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from pymongo import MongoClient
import uvicorn
from cryptography.fernet import Fernet # to generate a test key

from guardy import FileAnalyzer, get_dashboard_router, UserReportGenerator
from guardy.config import GuardConfig

app = FastAPI(title="Backend App using Secure File Guard")

# --- 1. SET UP THE BACKEND STATE (Database & Storage) ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# --- In-Memory Fallback ---
use_mock_db = False
mock_files_collection = []

try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    # Force a connection check
    mongo_client.server_info()
    db = mongo_client["guard_d_db"]
    files_collection = db["files"]
    print("Connected to MongoDB!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}. Using in-memory fallback for testing.")
    use_mock_db = True

# Create storage directories
SAFE_DIR = "storage/safe"
QUARANTINE_DIR = "storage/quarantine"
os.makedirs(SAFE_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Generate a dummy AES Encryption Key for this test
ENCRYPTION_KEY = Fernet.generate_key()

# Construct a custom configuration to showcase the library's flexibility
custom_config = GuardConfig(
    max_safe_entropy=7.8,         # Standard strict entropy
    weight_mime_spoofing=0.5,     # Aggressively block extension spoofing for easy testing
    max_ai_anomaly_score=0.5,     # Catch even minor AI behavioral deviations
    rejection_risk_threshold=0.50 # Return strict threshold to actually block dummy payload threats
)

# Instantiate the Stateless analyzer from our library
analyzer = FileAnalyzer(config=custom_config)

# --- 2. DEFINE DATA FETCH CALLBACKS FOR THE LIBRARY DASHBOARD ---
async def fetch_system_stats():
    """Callback for the dashboard to get aggregate stats."""
    if use_mock_db:
        total = len(mock_files_collection)
        safe = sum(1 for f in mock_files_collection if f.get("is_safe"))
        blocked = total - safe
        return {
            "total_uploads": total,
            "safe_uploads": safe,
            "blocked_uploads": blocked,
            "quarantined": blocked
        }

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
        return {"total_uploads": 0, "safe_uploads": 0, "blocked_uploads": 0, "quarantined": 0}

async def fetch_recent_alerts():
    """Callback for the dashboard to get recent flagged uploads."""
    if use_mock_db:
        alerts = [f for f in mock_files_collection if not f.get("is_safe")]
        alerts.reverse() # newest first
        return alerts[:10]

    try:
        docs = list(files_collection.find({"is_safe": False}).sort("timestamp", -1).limit(10))
        alerts = []
        for d in docs:
            d["_id"] = str(d["_id"])
            alerts.append(d)
        return alerts
    except Exception:
        return []

async def fetch_user_logs(user_id: str):
    """Callback for the dashboard to get all upload logs for a specific user."""
    if use_mock_db:
        logs = [f for f in mock_files_collection if f.get("user_id") == user_id]
        logs.reverse() # newest first
        return logs

    try:
        docs = list(files_collection.find({"user_id": user_id}).sort("timestamp", -1))
        logs = []
        for d in docs:
            d["_id"] = str(d["_id"])
            logs.append(d)
        return logs
    except Exception:
        return []

async def generate_llm_report(user_id: str):
    """
    Callback for the dashboard to generate an LLM report.
    In a real system, you would call OpenAI, Anthropic, or an open-source model here.
    """
    import asyncio
    # Simulate LLM Network latency
    await asyncio.sleep(2)
    
    logs = await fetch_user_logs(user_id)
    total_logs = len(logs)
    blocked_logs = sum(1 for log in logs if not log.get("is_safe", True))
    
    # Mock LLM Output
    markdown = f"""
### 🛡️ Analyst Report for `{user_id}`

Based on the chronological analysis of **{total_logs}** records, the AI Threat Engine provides the following findings:

- **Incident Summary:** `{user_id}` has initiated **{total_logs}** total uploads, of which **{blocked_logs}** were successfully isolated and quarantined.
- **Pattern Tracking:** 
  - The behavior profile of this subject often violates Entropy standards for raw file structure.
  - The payload vectors frequently indicate spoofed MIME headers vs the actual underlying byte structure.

**LLM Recommendation:** 
> _"Immediately restrict POST permissions across the gateway API for `{user_id}` until a manual code review of the payload at `{QUARANTINE_DIR}` is completed."_
    """
    return markdown

# --- 3. MOUNT THE DASHBOARD ---
# The library provides the UI, the backend provides the data!
dashboard_router = get_dashboard_router(
    get_system_stats=fetch_system_stats, 
    get_recent_alerts=fetch_recent_alerts,
    get_user_logs=fetch_user_logs,
    generate_llm_report=generate_llm_report
)
app.include_router(dashboard_router)

# Enable CORS for frontend development
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
            if use_mock_db:
                # Provide dummy data that looks very different from the current upload to trigger anomaly
                user_history = [
                    {"file_size": 1024, "mime_type": "text/plain", "entropy": 3.0, "upload_hour": 10},
                    {"file_size": 2048, "mime_type": "text/plain", "entropy": 3.1, "upload_hour": 10},
                    {"file_size": 1500, "mime_type": "text/plain", "entropy": 3.2, "upload_hour": 11},
                    {"file_size": 1800, "mime_type": "text/plain", "entropy": 3.0, "upload_hour": 10}
                ]
            else:
                history_cursor = files_collection.find({"user_id": user_id}).sort("timestamp", -1).limit(50)
                user_history = [{
                    "file_size": doc.get("size", 0),
                    "mime_type": doc.get("detected_mime", ""),
                    "entropy": doc.get("entropy", 0.0),
                    "upload_hour": doc.get("upload_hour", 12)
                } for doc in history_cursor]
        except Exception:
            pass

        # Extract Protocol Metadata for Layer 1 Deep Inspection
        file_metadata = {
            "filename": file.filename,
            "size": file.size,
            "headers": dict(file.headers)
        }

        # === THE CORE SECURE FILE GUARD LIBRARY MAGIC ===
        # Executing the 5-Layer Deep Inspection Engine
        assessment = analyzer.analyze_file(
            file_bytes=file_bytes,
            filename=file.filename,
            user_history_data=user_history,
            encryption_key=ENCRYPTION_KEY, # Request encryption
            file_metadata=file_metadata
        )
        
        # Calculate these again here just to save them in our database representation
        from guardy.threat.ai_anomaly import calculate_entropy
        current_entropy = calculate_entropy(file_bytes)
        current_hour = datetime.datetime.utcnow().hour
        
        # === BACKEND DECISION MAKING ===
        
        # 1. Determine where to save it
        store_dir = SAFE_DIR if assessment.is_safe else QUARANTINE_DIR
        stored_filename = f"{uuid.uuid4().hex}_{file.filename}"
        file_path = os.path.join(store_dir, stored_filename)
        
        # 2. Save the ENCRYPTED bytes to disk
        bytes_to_save = assessment.encrypted_bytes if assessment.encrypted_bytes else file_bytes
        with open(file_path, "wb") as f:
            f.write(bytes_to_save)
            
        # 3. Save metadata to MongoDB (or mock)
        record = {
            "user_id": user_id,
            "original_filename": file.filename,
            "stored_filename": stored_filename,
            "storage_path": file_path,
            "is_safe": assessment.is_safe,
            "risk_score": assessment.risk_score,
            "reasons": assessment.reasons,
            "detected_mime": assessment.detected_mime,
            "entropy": current_entropy,
            "upload_hour": current_hour,
            "sha256_hash": assessment.sha256_hash,
            "size": len(file_bytes),
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "ai_telemetry": assessment.ai_telemetry
        }
        
        try:
            if use_mock_db:
                mock_files_collection.append(record)
            else:
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
