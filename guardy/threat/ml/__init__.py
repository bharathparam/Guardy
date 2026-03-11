"""
guardy.threat.ml – AI-based detection layer for the Secure File Validation Library.

Public API
----------
from guardy.threat.ml.predict import FileAnalyzer
analyzer = FileAnalyzer()
report   = analyzer.analyze("/path/to/file.exe")
# report -> {"cnn_score": float, "anomaly_score": float, "final_risk": float}
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("guardy.threat.ml")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["predict", "train_byte_cnn", "train_anomaly_model",
           "byte_preprocessor", "dataset_loader", "config"]
