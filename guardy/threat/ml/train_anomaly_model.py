"""
train_anomaly_model.py – Train the Anomaly Detection Model (Model 2).

Strategy
--------
* Isolation Forest is trained ONLY on benign/safe files.
* Anomaly score = P(file is anomalous) ∈ [0, 1].
  - scikit-learn's IsolationForest.decision_function() returns a raw score
    where more-negative means more anomalous.  We normalise this to [0, 1].
* The calibrated threshold is stored inside the pickled object.

Output
------
  models/anomaly_model.pkl  – serialised sklearn pipeline (scaler + IsoForest)

Usage
-----
python -m guardy.threat.ml.train_anomaly_model
# or
from guardy.threat.ml.train_anomaly_model import train_anomaly
train_anomaly()
"""

import logging
import pickle
import sys
from pathlib import Path
from typing import List, Optional, Union

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

from guardy.threat.ml.config import (
    ANOMALY_CONTAMINATION,
    ANOMALY_MAX_SAMPLES,
    ANOMALY_MODEL_PATH,
    ANOMALY_N_ESTIMATORS,
    ANOMALY_RANDOM_STATE,
    LOG_FORMAT,
    LOG_LEVEL,
    MAX_BYTES,
)
from guardy.threat.ml.byte_preprocessor import BytePreprocessor
from guardy.threat.ml.dataset_loader import DatasetLoader

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _byte_statistics(arr: np.ndarray) -> np.ndarray:
    """
    Extract a compact statistical feature vector from a raw byte array.

    Features (total = 256 + 7 = 263 dimensions):
      - 256-bin byte frequency histogram (normalised)
      - Mean, std, entropy, zero-fraction, printable-fraction,
        high-byte-fraction, byte-range

    Parameters
    ----------
    arr : np.ndarray  shape (MAX_BYTES,), dtype uint8

    Returns
    -------
    np.ndarray of shape (263,), dtype float32
    """
    # 256-bin histogram (normalised)
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    hist_f  = hist.astype(np.float32) / max(arr.size, 1)

    # Shannon entropy
    p    = hist_f + 1e-12
    entr = float(-np.sum(p * np.log2(p)))

    # Scalar statistics
    mean         = float(arr.mean())
    std          = float(arr.std())
    zero_frac    = float((arr == 0).mean())
    printable    = float(((arr >= 32) & (arr <= 126)).mean())
    high_byte    = float((arr > 127).mean())
    byte_range   = float(int(arr.max()) - int(arr.min()))

    scalars = np.array(
        [mean, std, entr, zero_frac, printable, high_byte, byte_range],
        dtype=np.float32,
    )
    return np.concatenate([hist_f, scalars])   # (263,)


def build_feature_matrix(
    file_paths: List[Union[str, Path]],
    desc:       str = "Extracting features",
) -> np.ndarray:
    """
    Convert a list of file paths into a 2-D feature matrix.

    Returns
    -------
    np.ndarray of shape (N, 263), dtype float32
    """
    bp = BytePreprocessor()
    rows = []
    for fp in tqdm(file_paths, desc=desc, unit="file", leave=False):
        arr  = bp.file_to_array(fp)
        feat = _byte_statistics(arr)
        rows.append(feat)
    if not rows:
        return np.empty((0, 263), dtype=np.float32)
    return np.stack(rows, axis=0)


# ---------------------------------------------------------------------------
# Scoring helper
# ---------------------------------------------------------------------------

def decision_to_score(raw_scores: np.ndarray) -> np.ndarray:
    """
    Map IsolationForest raw decision scores → [0, 1] anomaly probability.

    IsolationForest.decision_function() returns:
      - Positive values (around +0.5) for inliers
      - Negative values for outliers

    We map this monotonically to [0, 1] so that 1 = highly anomalous.
    """
    # Clip to avoid extreme values in edge cases
    clipped = np.clip(raw_scores, -1.0, 1.0)
    # Invert and scale: inliers (near +0.5) → near 0;  outliers → near 1
    return (1.0 - (clipped + 1.0) / 2.0).astype(np.float32)


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------

def train_anomaly(
    safe_paths: Optional[List[Union[str, Path]]] = None,
    download:   bool = True,
) -> Pipeline:
    """
    Train and save the IsolationForest anomaly model.

    Parameters
    ----------
    safe_paths : list of Path, optional
        Benign file paths.  If None, DatasetLoader is used.
    download : bool
        Whether to trigger dataset downloads before training.

    Returns
    -------
    sklearn.pipeline.Pipeline  (StandardScaler + IsolationForest)
    """
    # ---- Data --------------------------------------------------------
    if safe_paths is None:
        loader = DatasetLoader()
        if download:
            loader.download_all()
        safe_paths = loader.load_benign_only()

    if not safe_paths:
        logger.error(
            "No benign files found! Please populate dataset/safe/ or enable remote datasets."
        )
        sys.exit(1)

    logger.info("Building feature matrix from %d benign files …", len(safe_paths))
    X = build_feature_matrix(safe_paths, desc="Benign features")
    logger.info("Feature matrix shape: %s", X.shape)

    # ---- Pipeline ----------------------------------------------------
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iso_forest", IsolationForest(
            n_estimators  = ANOMALY_N_ESTIMATORS,
            contamination = ANOMALY_CONTAMINATION,
            max_samples   = ANOMALY_MAX_SAMPLES,
            random_state  = ANOMALY_RANDOM_STATE,
            n_jobs        = -1,
            verbose       = 0,
        )),
    ])

    logger.info("Fitting IsolationForest …")
    with tqdm(total=1, desc="IsolationForest fit", unit="model") as pbar:
        pipeline.fit(X)
        pbar.update(1)

    # Quick self-assessment on training data
    raw_scores  = pipeline.named_steps["iso_forest"].decision_function(
        pipeline.named_steps["scaler"].transform(X)
    )
    pred_labels = pipeline.predict(X)         # +1 = inlier, -1 = outlier
    inlier_frac = (pred_labels == 1).mean()
    logger.info(
        "Training self-check: %.1f%% of benign samples classified as inliers (expected ≥ %.1f%%)",
        inlier_frac * 100,
        (1.0 - ANOMALY_CONTAMINATION) * 100,
    )

    # ---- Save --------------------------------------------------------
    ANOMALY_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(ANOMALY_MODEL_PATH, "wb") as fh:
        pickle.dump(pipeline, fh, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("Anomaly model saved → %s", ANOMALY_MODEL_PATH)

    return pipeline


# ---------------------------------------------------------------------------
# Inference helper (used by predict.py)
# ---------------------------------------------------------------------------

def load_anomaly_model() -> Pipeline:
    """Load and return the saved anomaly detection pipeline."""
    if not ANOMALY_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Anomaly model not found at {ANOMALY_MODEL_PATH}. "
            "Run train_anomaly_model.py first."
        )
    with open(ANOMALY_MODEL_PATH, "rb") as fh:
        return pickle.load(fh)


def score_file(pipeline: Pipeline, file_path: Union[str, Path]) -> float:
    """
    Return anomaly score ∈ [0, 1] for a single file.
    0 = normal / benign, 1 = highly anomalous.
    """
    bp   = BytePreprocessor()
    arr  = bp.file_to_array(file_path)
    feat = _byte_statistics(arr).reshape(1, -1)

    scaler    = pipeline.named_steps["scaler"]
    iso_model = pipeline.named_steps["iso_forest"]
    X_scaled  = scaler.transform(feat)
    raw       = iso_model.decision_function(X_scaled)   # (1,)
    score     = float(decision_to_score(raw)[0])
    return score


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train IsolationForest anomaly detector")
    parser.add_argument("--no-download", action="store_true", help="Skip dataset download")
    args = parser.parse_args()

    train_anomaly(download=not args.no_download)
