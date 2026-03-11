"""
config.py – Central configuration for guardy.threat.ml.

All paths, hyperparameters, and constants live here so that every
other module can import from a single source of truth.
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Root directories
# ---------------------------------------------------------------------------
ROOT_DIR   = Path(__file__).resolve().parent.parent.parent   # project root (guardy)
ML_DIR     = Path(__file__).resolve().parent          # guardy.threat.ml/
DATASET_DIR = ROOT_DIR / "dataset"
MODEL_DIR   = ROOT_DIR / "models"

# Local dataset sub-directories (safe / malicious)
LOCAL_SAFE_DIR      = DATASET_DIR / "safe"
LOCAL_MALICIOUS_DIR = DATASET_DIR / "malicious"

# ---------------------------------------------------------------------------
# Model save paths
# ---------------------------------------------------------------------------
CNN_MODEL_PATH         = MODEL_DIR / "byte_cnn_model.pth"
CNN_TORCHSCRIPT_PATH   = MODEL_DIR / "byte_cnn_model_scripted.pt"
ANOMALY_MODEL_PATH     = MODEL_DIR / "anomaly_model.pkl"

# ---------------------------------------------------------------------------
# Byte-level preprocessing
# ---------------------------------------------------------------------------
MAX_BYTES      = 4096   # bytes read per file
BYTE_VOCAB_SIZE = 256   # valid byte values: 0-255
PAD_VALUE       = 0     # zero-padding for short files

# ---------------------------------------------------------------------------
# CNN hyper-parameters
# ---------------------------------------------------------------------------
CNN_EMBED_DIM   = 64    # embedding dimension for each byte
CNN_CHANNELS    = [128, 256]   # out-channels for conv layers
CNN_KERNEL_SIZE = 8
CNN_HIDDEN_DIM  = 256
CNN_DROPOUT     = 0.4

CNN_LEARNING_RATE = 1e-3
CNN_BATCH_SIZE    = 64
CNN_EPOCHS        = 20
CNN_TRAIN_SPLIT   = 0.8   # fraction used for training

# ---------------------------------------------------------------------------
# Anomaly Detection hyper-parameters (IsolationForest)
# ---------------------------------------------------------------------------
ANOMALY_N_ESTIMATORS   = 100
ANOMALY_CONTAMINATION  = 0.05   # expected fraction of outliers in train set
ANOMALY_RANDOM_STATE   = 42
ANOMALY_MAX_SAMPLES    = "auto"

# ---------------------------------------------------------------------------
# Risk score combination weights
# ---------------------------------------------------------------------------
CNN_WEIGHT     = 0.6
ANOMALY_WEIGHT = 0.4

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s – %(message)s"

# ---------------------------------------------------------------------------
# Dataset download URLs / mirrors
# ---------------------------------------------------------------------------
DATASET_SOURCES = {
    # EMBER: metadata-only open mirror (raw binaries require separate agreement)
    "ember": {
        "description": "EMBER 2018 malware feature dataset (LightGBM features + metadata)",
        "url": "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
        "local_dir": DATASET_DIR / "ember",
    },
    # Malimg – PNG image-based malware dataset (visualised byte plots)
    "malimg": {
        "description": "Malimg malware image dataset",
        "url": "https://polybox.ethz.ch/index.php/s/SB51sCQCjqzR9vx/download",
        "local_dir": DATASET_DIR / "malimg",
    },
    # GovDocs1 – large collection of benign US-government documents
    "govdocs1": {
        "description": "GovDocs1 benign document dataset (subset)",
        "url": "https://digitalcorpora.org/corpora/files/govdocs1/zipfiles/",
        "local_dir": DATASET_DIR / "govdocs1",
    },
    # Open Images – benign image files
    "open_images": {
        "description": "Open Images V7 subset (benign images)",
        "url": "https://storage.googleapis.com/openimages/web/download_v7.html",
        "local_dir": DATASET_DIR / "open_images",
    },
}

# Ensure essential directories exist at import time
for _d in [DATASET_DIR, MODEL_DIR, LOCAL_SAFE_DIR, LOCAL_MALICIOUS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)
