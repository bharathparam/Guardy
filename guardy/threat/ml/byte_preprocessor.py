"""
byte_preprocessor.py – Raw byte extraction and tensor conversion.

All files are treated identically:
  1. Open in binary mode.
  2. Read at most MAX_BYTES (4096) bytes.
  3. Zero-pad if the file is shorter.
  4. Return as a numpy array of dtype uint8.

PyTorch helpers convert these arrays to LongTensors suitable for an
embedding layer (byte values 0-255).

Usage
-----
from guardy.threat.ml.byte_preprocessor import BytePreprocessor

bp = BytePreprocessor()
arr   = bp.file_to_array("/path/to/file")   # np.ndarray, shape (4096,)
tensor = bp.file_to_tensor("/path/to/file") # torch.LongTensor, shape (4096,)

X, y = bp.build_dataset(safe_paths, malicious_paths)  # np arrays
"""

import logging
from pathlib import Path
from typing import List, Optional, Tuple, Union

import numpy as np

from guardy.threat.ml.config import MAX_BYTES, PAD_VALUE

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core preprocessor
# ---------------------------------------------------------------------------

class BytePreprocessor:
    """
    Converts arbitrary files to fixed-length byte arrays.

    Parameters
    ----------
    max_bytes : int
        Maximum number of bytes to read from each file.  Default: 4096.
    pad_value : int
        Value used to zero-pad shorter files.  Default: 0.
    """

    def __init__(self, max_bytes: int = MAX_BYTES, pad_value: int = PAD_VALUE):
        self.max_bytes = max_bytes
        self.pad_value = pad_value

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def read_bytes(self, file_path: Union[str, Path]) -> bytes:
        """Read up to *max_bytes* from *file_path*."""
        file_path = Path(file_path)
        try:
            with open(file_path, "rb") as fh:
                return fh.read(self.max_bytes)
        except (OSError, PermissionError) as exc:
            logger.warning("Cannot read %s: %s – returning empty bytes.", file_path, exc)
            return b""

    def bytes_to_array(self, raw: bytes) -> np.ndarray:
        """
        Convert a raw bytes object to a zero-padded numpy uint8 array of
        length *max_bytes*.
        """
        arr = np.frombuffer(raw, dtype=np.uint8)
        # Truncate (should already be at most max_bytes, but be safe)
        arr = arr[: self.max_bytes]
        # Zero-pad if shorter
        if len(arr) < self.max_bytes:
            pad_len = self.max_bytes - len(arr)
            arr = np.concatenate([arr, np.full(pad_len, self.pad_value, dtype=np.uint8)])
        return arr  # shape: (max_bytes,)

    # ------------------------------------------------------------------
    # File-level API
    # ------------------------------------------------------------------

    def file_to_array(self, file_path: Union[str, Path]) -> np.ndarray:
        """
        Return a fixed-length numpy array for the given file.

        Returns
        -------
        np.ndarray of dtype uint8, shape (max_bytes,)
        """
        raw = self.read_bytes(file_path)
        return self.bytes_to_array(raw)

    def file_to_tensor(self, file_path: Union[str, Path]):
        """
        Return a PyTorch LongTensor suitable for an embedding layer.

        Returns
        -------
        torch.Tensor of dtype long, shape (max_bytes,)
        """
        try:
            import torch
        except ImportError as exc:
            raise ImportError("PyTorch is required for file_to_tensor.") from exc

        arr = self.file_to_array(file_path)
        return torch.from_numpy(arr.astype(np.int64))

    # ------------------------------------------------------------------
    # Dataset-level API
    # ------------------------------------------------------------------

    def build_arrays(
        self,
        file_paths: List[Union[str, Path]],
        desc: str = "Processing files",
    ) -> np.ndarray:
        """
        Batch-convert a list of file paths to a 2-D numpy array.

        Parameters
        ----------
        file_paths : list of path-like
        desc : str
            Label shown in the tqdm progress bar.

        Returns
        -------
        np.ndarray of shape (N, max_bytes), dtype uint8
        """
        from tqdm import tqdm

        arrays = []
        for fp in tqdm(file_paths, desc=desc, unit="file", leave=False):
            arrays.append(self.file_to_array(fp))
        if not arrays:
            return np.empty((0, self.max_bytes), dtype=np.uint8)
        return np.stack(arrays, axis=0)  # (N, max_bytes)

    def build_dataset(
        self,
        safe_paths:      List[Union[str, Path]],
        malicious_paths: List[Union[str, Path]],
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build ``(X, y)`` arrays from safe and malicious file lists.

        Labels:  0 = safe,  1 = malicious

        Returns
        -------
        X : np.ndarray, shape (N, max_bytes), dtype uint8
        y : np.ndarray, shape (N,), dtype int64
        """
        logger.info(
            "Building dataset: %d safe + %d malicious files",
            len(safe_paths),
            len(malicious_paths),
        )

        X_safe = self.build_arrays(safe_paths,      desc="Safe files")
        X_mal  = self.build_arrays(malicious_paths, desc="Malicious files")

        y_safe = np.zeros(len(X_safe), dtype=np.int64)
        y_mal  = np.ones(len(X_mal),  dtype=np.int64)

        if X_safe.size == 0 and X_mal.size == 0:
            raise ValueError("No files were loaded. Check your dataset paths.")
        if X_safe.size == 0:
            X = X_mal
            y = y_mal
        elif X_mal.size == 0:
            X = X_safe
            y = y_safe
        else:
            X = np.concatenate([X_safe, X_mal], axis=0)
            y = np.concatenate([y_safe, y_mal], axis=0)

        logger.info("Dataset shape: X=%s, y=%s", X.shape, y.shape)
        return X, y

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def array_to_tensor(self, arr: np.ndarray):
        """Convert a uint8 (N, max_bytes) numpy array to a LongTensor."""
        try:
            import torch
            return torch.from_numpy(arr.astype(np.int64))
        except ImportError as exc:
            raise ImportError("PyTorch is required.") from exc
