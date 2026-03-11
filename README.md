# 🛡️ Guardy

**Guardy** is a stateless, modular, multi-layer secure file analysis and threat intelligence framework for Python backends. 
It performs deep protocol inspection, binary structure analysis, Polyglot detection, and natively pipes unknown byte-streams into a **PyTorch Neural Network (ByteCNN)** and a **Scikit-Learn Isolation Forest** for advanced malicious behavior detection.

Designed to be utterly framework-agnostic. Use it with FastAPI, Flask, Django, or custom TCP sockets.

---

## 🚀 Features

- **Stateless & Memory Safe**: Analyzes files entirely in-memory using chunks. It never writes malicious bytes to your server's disk without your explicit instruction.
- **5-Layer Deep Inspection**:
  1. Protocol & Header Validation
  2. Binary Structure Analysis (PDF, JPEG, etc.)
  3. Polyglot / Embedded Script Detection
  4. Zip Bomb & Compression Bomb Defense
  5. Cryptographic Hashing & Entropy Analysis
- **Stage 2 AI Threat Engine**: Runs byte-tensors through an advanced PyTorch `ByteCNN` trained on malware structure, combined with statistical `IsolationForest` anomaly algorithms.
- **Security Operations Dashboard**: Instantly mounts an interactive HTML/JS UI reporting dashboard directly to your application with single-line FastAPI router integration.
- **Built-in Storage Adapters**: Plug-and-play `LocalDiskStorageAdapter` and `MongoDBDatabaseAdapter` instances that instantly sync the ML outputs to your Dashboard without boilerplate.

---

## 📦 Installation

```bash
pip install guardy
```

### Optional ML Dependencies
If you wish to utilize the PyTorch `ByteCNN` Stage 2 Threat Engine:
```bash
pip install torch scikit-learn
```

---

## 🛠️ Quickstart (Using Built-In Adapters)

Guardy allows you to pass database and disk adapters directly into the `FileAnalyzer`. It will handle saving the file, encrypting it, logging the exact AI telemetry, and keeping the dashboard in sync automatically.

```python
import asyncio
from guardy import FileAnalyzer
from guardy.adapters import LocalDiskStorageAdapter, MongoDBDatabaseAdapter
from pymongo import MongoClient

# 1. Setup Data Syncs
mongo_client = MongoClient("mongodb://localhost:27017")
db_adapter = MongoDBDatabaseAdapter(mongo_client["guard_db"]["files"])
disk_adapter = LocalDiskStorageAdapter(safe_dir="./safe", quarantine_dir="./blocked")

# 2. Instantiate Guardy
guardy = FileAnalyzer(
    storage_adapter=disk_adapter,
    database_adapter=db_adapter
)

async def handle_upload(user_id: str, filename: str, raw_bytes: bytes):
    # Executes the 5-Layer scan, runs PyTorch, saves to disk, and logs to Mongo!
    assessment = await guardy.analyze_and_execute(
        file_bytes=raw_bytes, 
        filename=filename,
        user_id=user_id
    )
    
    if assessment.is_safe:
        print(f"File stored safely!")
    else:
        print(f"Threat Blocked! Score: {assessment.risk_score}")
        print(f"Reasons: {assessment.reasons}")

# Run it
asyncio.run(handle_upload("user_123", "test.txt", b"Hello World"))
```

---

## 🧩 Modular API: Using Engines Independently

You don't have to use the overarching `FileAnalyzer` orchestrator if you only want specific capabilities. Guardy exposes every security layer as a standalone, callable class!

```python
from guardy import MLAnalyzer, ZipBombDetector, MimeChecker

# 1. Just want to use the PyTorch Network?
ml = MLAnalyzer(device='cpu')
result = ml.analyze_bytes(malicious_bytes, "virus.exe")
print(f"AI Risk: {result['final_risk']}")

# 2. Just want to check for Zip Bombs?
is_bomb = ZipBombDetector.scan_archive(zip_bytes, "application/zip", max_ratio=50.0)

# 3. Just want real Mime type extraction?
true_mime = MimeChecker.get_mime_type(unknown_bytes)
```

---

## 📊 Mounting the Security Dashboard

Guardy natively ships with an aesthetic UI displaying interactive `Chart.js` Risk Score timelines, AI Telemetry metadata, and LLM Analysis integrations.

If you are using FastAPI and the built-in `DatabaseAdapter`, mounting it takes 1 line of code:

```python
from fastapi import FastAPI
from guardy import get_dashboard_router

app = FastAPI()

# Just pass your adapter's fetch functions!
dashboard = get_dashboard_router(
    get_system_stats=db_adapter.fetch_system_stats,
    get_recent_alerts=db_adapter.fetch_recent_alerts,
    get_user_logs=db_adapter.fetch_user_logs
)

app.include_router(dashboard)
# Navigate to http://localhost:8000/security-dashboard
```
