"""
dataset_loader.py – Dataset acquisition and local loading for guardy.threat.ml.

Supported dataset sources
-------------------------
* EMBER 2018  – malware feature dataset (PE files; raw bytes extracted)
* Malimg      – malware visualised as grayscale PNG images
* GovDocs1    – benign US-government documents (subset ZIP files)
* Open Images – benign images (subset via TFRecord / fiftyone)
* Local dir   – dataset/safe/  and  dataset/malicious/

Usage
-----
from guardy.threat.ml.dataset_loader import DatasetLoader

loader = DatasetLoader()
loader.download_all()                      # fetch all remote datasets
safe_paths, mal_paths = loader.load_all()  # list[Path], list[Path]
"""

import io
import logging
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List, Tuple, Optional

import requests
from tqdm import tqdm

from guardy.threat.ml.config import (
    DATASET_SOURCES,
    LOCAL_SAFE_DIR,
    LOCAL_MALICIOUS_DIR,
    DATASET_DIR,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _download_file(url: str, dest_path: Path, desc: str = "") -> Path:
    """Stream-download *url* to *dest_path* with a tqdm progress bar."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading %s → %s", url, dest_path)

    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        with open(dest_path, "wb") as fh, tqdm(
            desc=desc or dest_path.name,
            total=total,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            leave=False,
        ) as bar:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)
                bar.update(len(chunk))
    logger.info("Download complete: %s", dest_path)
    return dest_path


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    """Extract tar / zip archives."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    logger.info("Extracting %s → %s", archive_path, dest_dir)
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        with tarfile.open(archive_path) as tf:
            tf.extractall(dest_dir)
    elif name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
    else:
        logger.warning("Unknown archive format: %s – skipping extraction", archive_path)
    logger.info("Extraction complete: %s", dest_dir)


def _collect_files(directory: Path, extensions: Optional[List[str]] = None) -> List[Path]:
    """Recursively collect files from *directory*, optionally filtered by extension."""
    if not directory.exists():
        return []
    files: List[Path] = []
    for p in directory.rglob("*"):
        if p.is_file():
            if extensions is None or p.suffix.lower() in extensions:
                files.append(p)
    return files


# ---------------------------------------------------------------------------
# Per-dataset downloaders
# ---------------------------------------------------------------------------

class _EMBERDownloader:
    """
    EMBER 2018 dataset downloader.

    The EMBER dataset contains pre-extracted LightGBM features + raw byte
    arrays packed in JSONL format.  We download the compressed archive,
    extract it, and collect the raw PE byte files (if present) or use the
    feature JSON files as a proxy source.

    Note: The raw binary mirror may require a data-usage agreement.  This
    implementation points to the official Elastic mirror; fall back to
    feature-only mode when raw bytes are unavailable.
    """

    NAME = "ember"

    def __init__(self):
        cfg = DATASET_SOURCES[self.NAME]
        self.url       = cfg["url"]
        self.local_dir = Path(cfg["local_dir"])
        self._archive  = self.local_dir / "ember_dataset_2018_2.tar.bz2"

    @property
    def is_downloaded(self) -> bool:
        return self.local_dir.exists() and any(self.local_dir.iterdir())

    def download(self) -> None:
        if self.is_downloaded:
            logger.info("EMBER already present – skipping download.")
            return
        try:
            _download_file(self.url, self._archive, desc="EMBER dataset")
            _extract_archive(self._archive, self.local_dir)
            self._archive.unlink(missing_ok=True)
        except Exception as exc:
            logger.error("EMBER download failed: %s", exc)
            logger.info("Place EMBER files manually under %s", self.local_dir)

    def get_malicious_paths(self) -> List[Path]:
        # EMBER stores samples in train_features_*.jsonl + train_labels_*.jsonl
        # Raw binary paths if extracted:
        paths = _collect_files(self.local_dir / "train", [".exe", ".dll", ".bin"])
        if not paths:
            paths = _collect_files(self.local_dir, [".exe", ".dll", ".bin"])
        logger.info("EMBER malicious files found: %d", len(paths))
        return paths

    def get_benign_paths(self) -> List[Path]:
        return []  # EMBER is malware-focussed; benign samples need label filter


class _MalimgDownloader:
    """
    Malimg dataset downloader.

    Malimg contains malware families visualised as greyscale PNG images.
    Each image IS the raw byte layout of the binary → we treat them as
    byte sources.
    """

    NAME = "malimg"

    def __init__(self):
        cfg = DATASET_SOURCES[self.NAME]
        self.url       = cfg["url"]
        self.local_dir = Path(cfg["local_dir"])
        self._archive  = self.local_dir / "malimg.zip"

    @property
    def is_downloaded(self) -> bool:
        return self.local_dir.exists() and any(self.local_dir.iterdir())

    def download(self) -> None:
        if self.is_downloaded:
            logger.info("Malimg already present – skipping download.")
            return
        try:
            _download_file(self.url, self._archive, desc="Malimg dataset")
            _extract_archive(self._archive, self.local_dir)
            self._archive.unlink(missing_ok=True)
        except Exception as exc:
            logger.error("Malimg download failed: %s", exc)
            logger.info("Place Malimg files manually under %s", self.local_dir)

    def get_malicious_paths(self) -> List[Path]:
        paths = _collect_files(self.local_dir, [".png", ".bmp", ".jpg"])
        logger.info("Malimg malicious files found: %d", len(paths))
        return paths

    def get_benign_paths(self) -> List[Path]:
        return []


class _GovDocs1Downloader:
    """
    GovDocs1 benign document dataset downloader.

    GovDocs1 hosts ~1 million US-government documents.  For practical use
    we download a small subset (thread 000.zip).
    """

    NAME = "govdocs1"
    # Download a single thread ZIP as a representative subset
    SUBSET_URL = "https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/000.zip"

    def __init__(self):
        cfg = DATASET_SOURCES[self.NAME]
        self.local_dir = Path(cfg["local_dir"])
        self._archive  = self.local_dir / "govdocs1_000.zip"

    @property
    def is_downloaded(self) -> bool:
        return self.local_dir.exists() and any(self.local_dir.iterdir())

    def download(self) -> None:
        if self.is_downloaded:
            logger.info("GovDocs1 already present – skipping download.")
            return
        try:
            _download_file(self.SUBSET_URL, self._archive, desc="GovDocs1 subset")
            _extract_archive(self._archive, self.local_dir)
            self._archive.unlink(missing_ok=True)
        except Exception as exc:
            logger.error("GovDocs1 download failed: %s", exc)
            logger.info("Place GovDocs1 files manually under %s", self.local_dir)

    def get_benign_paths(self) -> List[Path]:
        paths = _collect_files(self.local_dir)
        logger.info("GovDocs1 benign files found: %d", len(paths))
        return paths

    def get_malicious_paths(self) -> List[Path]:
        return []


class _OpenImagesDownloader:
    """
    Open Images V7 downloader (small subset via direct URL list).

    Downloads a curated list of benign JPEG images from the Open Images CDN,
    avoiding the need for the full fiftyone / TFRecord pipeline.
    """

    NAME = "open_images"
    # A publicly hosted CSV with image URLs from the Open Images validation set
    INDEX_URL = (
        "https://storage.googleapis.com/openimages/2018_04/validation/validation-images-boxable.csv"
    )
    MAX_IMAGES = 500  # cap for practical purposes

    def __init__(self):
        cfg = DATASET_SOURCES[self.NAME]
        self.local_dir = Path(cfg["local_dir"])

    @property
    def is_downloaded(self) -> bool:
        return self.local_dir.exists() and len(list(self.local_dir.rglob("*.jpg"))) >= 10

    def download(self) -> None:
        if self.is_downloaded:
            logger.info("Open Images already present – skipping download.")
            return
        self.local_dir.mkdir(parents=True, exist_ok=True)

        try:
            import csv

            logger.info("Fetching Open Images index …")
            resp = requests.get(self.INDEX_URL, timeout=60)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            reader = csv.DictReader(lines)
            urls = [row["OriginalURL"] for row in reader if row.get("OriginalURL")]
            urls = urls[: self.MAX_IMAGES]

            logger.info("Downloading %d Open Images samples …", len(urls))
            for idx, url in enumerate(tqdm(urls, desc="Open Images", unit="img")):
                try:
                    r = requests.get(url, timeout=15)
                    r.raise_for_status()
                    ext = url.split(".")[-1].split("?")[0][:4]
                    out = self.local_dir / f"img_{idx:05d}.{ext}"
                    out.write_bytes(r.content)
                except Exception as img_exc:
                    logger.debug("Failed to download image %s: %s", url, img_exc)
        except Exception as exc:
            logger.error("Open Images download failed: %s", exc)
            logger.info("Place image files manually under %s", self.local_dir)

    def get_benign_paths(self) -> List[Path]:
        paths = _collect_files(self.local_dir, [".jpg", ".jpeg", ".png", ".bmp", ".gif"])
        logger.info("Open Images benign files found: %d", len(paths))
        return paths

    def get_malicious_paths(self) -> List[Path]:
        return []


# ---------------------------------------------------------------------------
# Main DatasetLoader
# ---------------------------------------------------------------------------

class DatasetLoader:
    """
    Unified interface to download and load all supported datasets.

    Parameters
    ----------
    use_local : bool
        Whether to include files from dataset/safe/ and dataset/malicious/.
    use_ember : bool
        Whether to download / use the EMBER dataset.
    use_malimg : bool
        Whether to download / use the Malimg dataset.
    use_govdocs1 : bool
        Whether to download / use the GovDocs1 dataset.
    use_open_images : bool
        Whether to download / use the Open Images dataset.
    """

    def __init__(
        self,
        use_local:       bool = True,
        use_ember:       bool = True,
        use_malimg:      bool = True,
        use_govdocs1:    bool = True,
        use_open_images: bool = True,
    ):
        self.use_local       = use_local
        self.use_ember       = use_ember
        self.use_malimg      = use_malimg
        self.use_govdocs1    = use_govdocs1
        self.use_open_images = use_open_images

        self._downloaders = {}
        if use_ember:
            self._downloaders["ember"] = _EMBERDownloader()
        if use_malimg:
            self._downloaders["malimg"] = _MalimgDownloader()
        if use_govdocs1:
            self._downloaders["govdocs1"] = _GovDocs1Downloader()
        if use_open_images:
            self._downloaders["open_images"] = _OpenImagesDownloader()

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def download_all(self) -> None:
        """Download all enabled remote datasets if not already present."""
        logger.info("Starting dataset downloads …")
        for name, dl in self._downloaders.items():
            logger.info("Processing dataset: %s", name)
            dl.download()
        logger.info("All dataset downloads finished.")

    def load_all(self) -> Tuple[List[Path], List[Path]]:
        """
        Return ``(safe_paths, malicious_paths)``.

        Each entry is a :class:`pathlib.Path` pointing to a file whose first
        4096 bytes will be used for training.
        """
        safe: List[Path]      = []
        malicious: List[Path] = []

        # ---- Local directories ----------------------------------------
        if self.use_local:
            local_safe = _collect_files(LOCAL_SAFE_DIR)
            local_mal  = _collect_files(LOCAL_MALICIOUS_DIR)
            logger.info(
                "Local dataset: %d safe, %d malicious", len(local_safe), len(local_mal)
            )
            safe.extend(local_safe)
            malicious.extend(local_mal)

        # ---- Remote datasets ------------------------------------------
        for name, dl in self._downloaders.items():
            mal  = dl.get_malicious_paths()
            ben  = dl.get_benign_paths()
            logger.info("Dataset [%s]: %d malicious, %d benign", name, len(mal), len(ben))
            malicious.extend(mal)
            safe.extend(ben)

        logger.info(
            "Total: %d safe files, %d malicious files", len(safe), len(malicious)
        )
        return safe, malicious

    def load_benign_only(self) -> List[Path]:
        """Return only benign file paths (used for anomaly model training)."""
        safe, _ = self.load_all()
        return safe

    def load_malicious_only(self) -> List[Path]:
        """Return only malicious file paths."""
        _, malicious = self.load_all()
        return malicious
