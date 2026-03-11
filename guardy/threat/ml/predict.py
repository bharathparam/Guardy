"""
predict.py – Unified inference interface for the guardy.threat.ml AI layer.

Both models are loaded once and cached.  For each file analysed the module:
  1. Reads first 4096 bytes (BytePreprocessor).
  2. Runs ByteCNN  → cnn_score  ∈ [0, 1]
  3. Runs IsolationForest → anomaly_score ∈ [0, 1]
  4. Combines:  final_risk = 0.6 * cnn_score + 0.4 * anomaly_score

Return schema
-------------
{
    "cnn_score":     float,   # 0=benign, 1=malicious (CNN)
    "anomaly_score": float,   # 0=normal, 1=anomalous (IsoForest)
    "final_risk":    float,   # weighted combination
    "file":          str,     # absolute path to analysed file
    "error":         str,     # present only if an error occurred
}

Usage
-----
from guardy.threat.ml.predict import FileAnalyzer

analyzer = FileAnalyzer()
report   = analyzer.analyze("/path/to/suspicious.exe")
print(report)
"""

import logging
from pathlib import Path
from typing import Dict, Optional, Union

import numpy as np
import torch

from guardy.threat.ml.config import (
    ANOMALY_WEIGHT,
    CNN_MODEL_PATH,
    CNN_TORCHSCRIPT_PATH,
    CNN_WEIGHT,
    LOG_FORMAT,
    LOG_LEVEL,
    MAX_BYTES,
)
from guardy.threat.ml.byte_preprocessor import BytePreprocessor
from guardy.threat.ml.train_anomaly_model import (
    _byte_statistics,
    decision_to_score,
    load_anomaly_model,
)

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CNN loader
# ---------------------------------------------------------------------------

def _load_cnn(device: torch.device):
    """
    Load ByteCNN for inference.

    Preference order:
      1. TorchScript (production, no class definition needed)
      2. State-dict checkpoint (requires ByteCNN class, development mode)
    """
    if CNN_TORCHSCRIPT_PATH.exists():
        logger.info("Loading TorchScript CNN → %s", CNN_TORCHSCRIPT_PATH)
        model = torch.jit.load(str(CNN_TORCHSCRIPT_PATH), map_location=device)
        model.eval()
        return model

    if CNN_MODEL_PATH.exists():
        logger.info("Loading CNN state-dict → %s", CNN_MODEL_PATH)
        from guardy.threat.ml.train_byte_cnn import ByteCNN
        model = ByteCNN()
        model.load_state_dict(
            torch.load(CNN_MODEL_PATH, map_location=device)
        )
        model.to(device)
        model.eval()
        return model

    raise FileNotFoundError(
        f"No CNN model found at {CNN_TORCHSCRIPT_PATH} or {CNN_MODEL_PATH}.\n"
        "Run  python -m guardy.threat.ml.train_byte_cnn  to train it first."
    )


# ---------------------------------------------------------------------------
# FileAnalyzer
# ---------------------------------------------------------------------------

class FileAnalyzer:
    """
    Production-ready file risk analyser.

    Both models are loaded lazily on first use and then cached for the
    lifetime of the object – suitable for server-side reuse.

    Parameters
    ----------
    cnn_weight     : float  – weight for CNN score  (default 0.6)
    anomaly_weight : float  – weight for anomaly score (default 0.4)
    device         : str | None  – 'cuda', 'cpu', or None (auto-detect)
    """

    def __init__(
        self,
        cnn_weight:     float = CNN_WEIGHT,
        anomaly_weight: float = ANOMALY_WEIGHT,
        device:         Optional[str] = None,
    ):
        self.cnn_weight     = cnn_weight
        self.anomaly_weight = anomaly_weight

        if device is None:
            self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self._device = torch.device(device)

        self._preprocessor    = BytePreprocessor()
        self._cnn_model       = None   # lazy
        self._anomaly_pipeline = None  # lazy

    # ------------------------------------------------------------------
    # Lazy loaders
    # ------------------------------------------------------------------

    @property
    def cnn_model(self):
        if self._cnn_model is None:
            self._cnn_model = _load_cnn(self._device)
        return self._cnn_model

    @property
    def anomaly_pipeline(self):
        if self._anomaly_pipeline is None:
            self._anomaly_pipeline = load_anomaly_model()
        return self._anomaly_pipeline

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _cnn_score(self, raw_bytes: bytes) -> float:
        """Run ByteCNN and return malicious probability ∈ [0, 1]."""
        arr    = self._preprocessor.bytes_to_array(raw_bytes)
        tensor = torch.from_numpy(arr.astype(np.int64)).unsqueeze(0).to(self._device)
        with torch.no_grad():
            logits = self.cnn_model(tensor)           # (1, 2)
            prob   = torch.softmax(logits, dim=-1)
            score  = float(prob[0, 1].item())         # malicious class
        return score

    def _anomaly_score(self, raw_bytes: bytes) -> float:
        """Run IsolationForest and return anomaly score ∈ [0, 1]."""
        arr  = self._preprocessor.bytes_to_array(raw_bytes)
        feat = _byte_statistics(arr).reshape(1, -1)

        scaler    = self.anomaly_pipeline.named_steps["scaler"]
        iso_model = self.anomaly_pipeline.named_steps["iso_forest"]
        X_sc      = scaler.transform(feat)
        raw       = iso_model.decision_function(X_sc)   # (1,)
        return float(decision_to_score(raw)[0])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_bytes(self, raw_bytes: bytes, filename: str) -> Dict[str, object]:
        """
        Analyse in-memory bytes and return a risk report.

        Parameters
        ----------
        raw_bytes : bytes
        filename: str

        Returns
        -------
        dict with keys: file, cnn_score, anomaly_score, final_risk[, error]
        """
        result: Dict[str, object] = {"file": filename}

        if len(raw_bytes) == 0:
            result["error"] = f"Empty file bytes provided for {filename}"
            logger.error(result["error"])
            return result

        try:
            cnn_score     = self._cnn_score(raw_bytes)
        except Exception as exc:
            logger.warning("CNN scoring failed for %s: %s", filename, exc)
            cnn_score     = 0.5   # neutral fallback

        try:
            anomaly_score = self._anomaly_score(raw_bytes)
        except Exception as exc:
            logger.warning("Anomaly scoring failed for %s: %s", filename, exc)
            anomaly_score = 0.5   # neutral fallback

        final_risk = self.cnn_weight * cnn_score + self.anomaly_weight * anomaly_score

        result["cnn_score"]     = round(cnn_score,     6)
        result["anomaly_score"] = round(anomaly_score, 6)
        result["final_risk"]    = round(final_risk,    6)

        logger.info(
            "Analysis [%s]: cnn=%.4f  anomaly=%.4f  risk=%.4f",
            filename, cnn_score, anomaly_score, final_risk,
        )
        return result

    def analyze_batch(self, file_paths, show_progress: bool = True) -> list:
        """
        Analyse multiple files and return a list of risk reports.

        Parameters
        ----------
        file_paths    : iterable of str | Path
        show_progress : bool

        Returns
        -------
        list[dict]
        """
        from tqdm import tqdm

        paths   = list(file_paths)
        reports = []
        iterator = tqdm(paths, desc="Analyzing files", unit="file") if show_progress else paths
        for fp in iterator:
            reports.append(self.analyze(fp))
        return reports


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Analyze a file with the guardy.threat.ml AI layer")
    parser.add_argument("file", nargs="+", help="Path(s) to file(s) to analyze")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    analyzer = FileAnalyzer()
    results  = analyzer.analyze_batch(args.file)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(
                f"File        : {r.get('file')}\n"
                f"CNN score   : {r.get('cnn_score', 'n/a')}\n"
                f"Anomaly     : {r.get('anomaly_score', 'n/a')}\n"
                f"Final risk  : {r.get('final_risk', 'n/a')}\n"
                f"{'-'*40}"
            )
