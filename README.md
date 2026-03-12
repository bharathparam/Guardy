# 🛡️ Guardy 2.0

> **A stateless, modular, multi-layer secure file analysis and threat intelligence framework for Python.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/badge/install-pip%20install%20guardy-blue)](https://pypi.org/)

---

Guardy is a **drop-in file security middleware** for Python backends. It wraps your file upload endpoint with a 5-layer deep inspection pipeline — blocking polyglots, MIME spoofing, zip bombs, malicious payloads, and AI-detected anomalies before they ever touch your storage.

It ships with a **beautiful real-time security dashboard** out of the box, complete with user activity reports, SHA-256 file signatures, AI telemetry, and threat analytics — all mountable on any FastAPI app in under 10 lines.

---

## ✨ Features

| Layer | What It Does |
|-------|-------------|
| 🔍 **MIME Inspector** | Detects file type from raw bytes, catches extension spoofing |
| 🧬 **Signature Verifier** | Checks magic bytes against known malicious patterns |
| 💣 **Zip Bomb Detector** | Uncovers decompression bombs and nested archives |
| 🦠 **Polyglot Detector** | Finds files valid in multiple formats simultaneously |
| 🤖 **AI Anomaly Engine** | Dual-model PyTorch CNN + IsolationForest byte analysis |
| 📊 **Live Dashboard** | Real-time threat monitoring, charts, user reports, and analyst AI |
| 🔐 **AES Encryption** | All file data encrypted in-memory during analysis |
| 🗄️ **Adapter Pattern** | Pluggable storage (local disk, S3) and database (MongoDB, custom) |

---

## 📦 Installation

```bash
pip install guardy
```

> **System dependency required for MIME detection:**
> ```bash
> # macOS
> brew install libmagic
>
> # Ubuntu/Debian
> sudo apt-get install libmagic1
>
> # Windows
> pip install python-magic-bin
> ```

---

## ⚡ Quickstart

### Basic — protect a single upload endpoint

```python
from fastapi import FastAPI, UploadFile
from guardy import FileAnalyzer, GuardConfig

app = FastAPI()
analyzer = FileAnalyzer(GuardConfig())

@app.post("/upload")
async def upload_file(file: UploadFile):
    content = await file.read()
    result = analyzer.analyze(content, file.filename)

    if not result.is_safe:
        return {"status": "BLOCKED", "reasons": result.reasons, "risk": result.risk_score}
    
    # Safe — save your file here
    return {"status": "SAFE", "filename": file.filename}
```

---

## 🔧 Full Integration Example (FastAPI + MongoDB + Dashboard)

This pattern lets you drop the Guardy dashboard into any existing FastAPI app:

```python
from fastapi import FastAPI, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from guardy import FileAnalyzer, GuardConfig, get_dashboard_router
from guardy import LocalDiskStorageAdapter, MongoDBDatabaseAdapter
import datetime, os

# --- 1. CONFIGURE GUARDY ---
config = GuardConfig(
    rejection_risk_threshold=0.50,   # Block anything over 50% risk
    max_entropy=7.8,                 # Flag high-entropy payloads
    max_file_size=50 * 1024 * 1024,  # 50 MB max
    quarantine_enabled=True,
)

analyzer   = FileAnalyzer(config)
storage    = LocalDiskStorageAdapter(safe_dir="./storage/safe", quarantine_dir="./storage/quarantine")
db         = MongoDBDatabaseAdapter(os.environ["MONGO_URI"], "guardy_db", "upload_logs")

app = FastAPI(title="My Secure App")

# --- 2. YOUR SECURE UPLOAD ENDPOINT ---
@app.post("/upload")
async def upload(file: UploadFile, user_id: str = Form("anonymous")):
    content = await file.read()
    result  = analyzer.analyze(content, file.filename)

    log = {
        "user_id":           user_id,
        "original_filename": file.filename,
        "is_safe":           result.is_safe,
        "risk_score":        result.risk_score,
        "reasons":           result.reasons,
        "sha256_hash":       result.sha256_hash,
        "detected_mime":     result.detected_mime,
        "entropy":           result.entropy,
        "size":              len(content),
        "ai_telemetry":      result.ai_telemetry,
        "timestamp":         datetime.datetime.utcnow().isoformat(),
    }
    await db.save_log(log)

    if result.is_safe:
        await storage.save_safe(content, file.filename)
        return {"status": "SAFE", "risk_score": result.risk_score}
    else:
        await storage.quarantine(content, file.filename)
        return {"status": "BLOCKED", "reasons": result.reasons, "risk_score": result.risk_score}

# --- 3. MOUNT THE GUARDY DASHBOARD ---
async def fetch_stats():
    all_logs = await db.get_all_logs()
    safe  = sum(1 for l in all_logs if l.get("is_safe"))
    return {"total_uploads": len(all_logs), "safe_uploads": safe, "blocked_uploads": len(all_logs) - safe}

async def fetch_alerts():
    return await db.get_recent_logs(limit=50)

async def fetch_user_logs(user_id: str):
    return await db.get_user_logs(user_id)

async def generate_report(user_id: str):
    from guardy import UserReportGenerator
    logs = await fetch_user_logs(user_id)
    return UserReportGenerator.generate_report(user_id, logs)

dashboard = get_dashboard_router(
    get_system_stats=fetch_stats,
    get_recent_alerts=fetch_alerts,
    get_user_logs=fetch_user_logs,
    generate_llm_report=generate_report,
)
app.include_router(dashboard)
```

**Dashboard will be available at:**
- `http://localhost:8000/` — Security dashboard
- `http://localhost:8000/user/{user_id}` — Individual user profile & analyst report
- `http://localhost:8000/generate-report/{user_id}` — POST, generates full analyst report

---

## ⚙️ Configuration Reference (`GuardConfig`)

```python
from guardy import GuardConfig

config = GuardConfig(
    # --- Risk Thresholds ---
    rejection_risk_threshold = 0.50,  # 0.0–1.0. Files over this are BLOCKED
    max_ai_anomaly_score     = 0.50,  # AI anomaly score ceiling
    max_entropy              = 7.8,   # Max Shannon entropy (7.0–8.0)
    max_file_size            = 52428800,  # 50 MB in bytes

    # --- Detection Weights (all weights sum influence the risk_score) ---
    weight_mime_spoofing     = 0.40,  # Increase to aggressively block extension spoofing
    weight_malware_signature = 0.50,
    weight_zip_bomb          = 0.50,
    weight_polyglot          = 0.35,
    weight_ai_anomaly        = 0.30,

    # --- Blocked File Extensions (add custom ones) ---
    blocked_extensions = {".exe", ".bat", ".sh", ".ps1", ".vbs", ".js"},

    # --- Quarantine ---
    quarantine_enabled = True,
)
```

---

## 📊 FileAssessment Result Object

Every `analyzer.analyze()` call returns a `FileAssessment` with:

```python
result = analyzer.analyze(file_bytes, "report.pdf")

result.is_safe          # bool — True if file passed all checks
result.risk_score       # float 0.0–1.0 — overall threat score
result.reasons          # list[str] — human-readable threat reasons
result.sha256_hash      # str — full SHA-256 signature of the file
result.detected_mime    # str — actual MIME type from magic bytes
result.entropy          # float — Shannon byte entropy
result.ai_telemetry     # dict — {"cnn_score": float, "anomaly_score": float}
result.file_size        # int — file size in bytes
```

---

## 🗄️ Storage & Database Adapters

### Built-in Adapters

```python
from guardy import LocalDiskStorageAdapter, MongoDBDatabaseAdapter

# Local disk storage
storage = LocalDiskStorageAdapter(
    safe_dir="./storage/safe",
    quarantine_dir="./storage/quarantine"
)

# MongoDB
db = MongoDBDatabaseAdapter(
    mongo_uri="mongodb://localhost:27017",
    db_name="guardy_db",
    collection_name="upload_logs"
)
```

### Custom Adapter (implement the interface)

```python
from guardy import StorageAdapter, DatabaseAdapter

class MyS3StorageAdapter(StorageAdapter):
    async def save_safe(self, content: bytes, filename: str) -> str:
        # Upload to S3
        ...
    async def quarantine(self, content: bytes, filename: str) -> str:
        # Move to quarantine bucket
        ...

class MySQLDatabaseAdapter(DatabaseAdapter):
    async def save_log(self, log: dict) -> None:
        # Insert into your DB
        ...
    async def get_recent_logs(self, limit: int = 50) -> list:
        ...
    async def get_user_logs(self, user_id: str) -> list:
        ...
```

---

## 🖥️ Running the Example Test Server

A complete reference implementation lives in `test_server/`:

```bash
# Install dependencies
cd test_server
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e ..           # Install guardy from source

# Set your MongoDB URI
export MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net"

# Start the server
python main.py
```

Open `http://localhost:8000` to see the live security dashboard.

**Test it from CLI:**
```bash
# Upload a safe file
curl -X POST http://localhost:8000/upload \
  -F "file=@/path/to/safe.pdf" \
  -F "user_id=alice"

# Upload a spoofed file (PNG with .exe extension)
curl -X POST http://localhost:8000/upload \
  -F "file=@/path/to/malicious.png;type=application/octet-stream;filename=payload.exe" \
  -F "user_id=attacker"
```

---

## 🏗️ Architecture

```
guardy/
├── analyzer.py          # Core 5-layer pipeline orchestrator
├── config.py            # GuardConfig — all tunable thresholds
├── adapters/            # StorageAdapter & DatabaseAdapter interfaces + built-ins
├── engines/             # Individual detection engines (MIME, Signature, ZipBomb, Polyglot, AI)
├── models/              # Trained PyTorch CNN (.pth) + IsolationForest (.pkl)
├── inspection/          # Protocol-level inspectors
├── threat/              # Threat signature definitions
├── encryption/          # AES in-memory file encryption
├── validation/          # Pre-flight validators
└── ui/
    ├── dashboard.py     # FastAPI router factory (get_dashboard_router)
    ├── report.py        # UserReportGenerator
    ├── templates/       # Jinja2 HTML templates (dashboard, user_detail)
    └── static/          # CSS / JS assets
```

---

## � Security Pipeline

Every uploaded file passes through these layers in sequence:

```
File Upload
    │
    ▼
[Layer 1] Extension Check  ──► Blocked extension? → REJECT
    │
    ▼
[Layer 2] MIME Inspection  ──► Extension ≠ actual bytes? → PENALIZE
    │
    ▼
[Layer 3] Magic Signature  ──► Matches malware patterns? → PENALIZE
    │
    ▼
[Layer 4] Structural Check ──► Zip bomb / Polyglot? → PENALIZE
    │
    ▼
[Layer 5] AI Analysis      ──► Anomaly / CNN score anomaly? → PENALIZE
    │
    ▼
[Aggregator] risk_score > threshold? → BLOCK & QUARANTINE : SAFE STORAGE
```

---

## � Requirements

```
Python >= 3.8
fastapi >= 0.100.0
python-multipart >= 0.0.6
python-magic >= 0.4.27
scikit-learn >= 1.3.0
cryptography >= 41.0.0
pydantic >= 2.0.0
numpy >= 1.24.0
torch >= 2.0.0
jinja2 >= 3.1.2
aiofiles >= 23.0.0
```

---

## � License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙌 Contributing

PRs are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

<div align="center">
  Built with ❤️ — <strong>Guardy 2.0</strong>
</div>
