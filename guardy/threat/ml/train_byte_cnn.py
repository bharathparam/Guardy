"""
train_byte_cnn.py – Train the Fast Byte-Level CNN Classifier (Model 1).

Architecture
------------
  Input  : LongTensor (batch, 4096)  – byte values 0-255
  Embed  : Embedding(256, embed_dim) → (batch, 4096, embed_dim)
  Conv1  : Conv1d(embed_dim, 128, kernel=8) + ReLU + MaxPool(4)
  Conv2  : Conv1d(128, 256, kernel=8) + ReLU + MaxPool(4)
  Conv3  : Conv1d(256, 256, kernel=8) + ReLU + AdaptiveMaxPool(64)
  Flatten: (batch, 256*64)
  FC1    : Linear → 256, GELU, Dropout(0.4)
  FC2    : Linear → 2  (logits for [benign, malicious])

Loss    : CrossEntropyLoss
Optimizer: Adam

Outputs
-------
  models/byte_cnn_model.pth          – state-dict checkpoint
  models/byte_cnn_model_scripted.pt  – TorchScript for production

Usage
-----
python -m guardy.threat.ml.train_byte_cnn
# or
from guardy.threat.ml.train_byte_cnn import train
train()
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, random_split
from tqdm import tqdm

from guardy.threat.ml.config import (
    CNN_BATCH_SIZE,
    CNN_CHANNELS,
    CNN_DROPOUT,
    CNN_EMBED_DIM,
    CNN_EPOCHS,
    CNN_HIDDEN_DIM,
    CNN_KERNEL_SIZE,
    CNN_LEARNING_RATE,
    CNN_MODEL_PATH,
    CNN_TORCHSCRIPT_PATH,
    CNN_TRAIN_SPLIT,
    BYTE_VOCAB_SIZE,
    MAX_BYTES,
    LOG_FORMAT,
    LOG_LEVEL,
)
from guardy.threat.ml.byte_preprocessor import BytePreprocessor
from guardy.threat.ml.dataset_loader import DatasetLoader

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model definition
# ---------------------------------------------------------------------------

class ByteCNN(nn.Module):
    """
    Byte-level 1-D CNN malware classifier.

    Parameters
    ----------
    vocab_size  : int   – number of distinct byte values (256)
    embed_dim   : int   – embedding dimension per byte
    channels    : list  – out-channels for conv layers
    kernel_size : int   – convolution kernel width
    hidden_dim  : int   – FC hidden layer width
    dropout     : float – dropout probability
    seq_len     : int   – input sequence length (4096)
    """

    def __init__(
        self,
        vocab_size:  int   = BYTE_VOCAB_SIZE,
        embed_dim:   int   = CNN_EMBED_DIM,
        channels     = CNN_CHANNELS,
        kernel_size: int   = CNN_KERNEL_SIZE,
        hidden_dim:  int   = CNN_HIDDEN_DIM,
        dropout:     float = CNN_DROPOUT,
        seq_len:     int   = MAX_BYTES,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        ch_in = embed_dim
        conv_layers = []
        pool_layers = []
        for ch_out in channels:
            conv_layers.append(
                nn.Sequential(
                    nn.Conv1d(ch_in, ch_out, kernel_size=kernel_size, padding=kernel_size // 2),
                    nn.BatchNorm1d(ch_out),
                    nn.GELU(),
                )
            )
            pool_layers.append(nn.MaxPool1d(kernel_size=4, stride=4))
            ch_in = ch_out

        self.convs  = nn.ModuleList(conv_layers)
        self.pools  = nn.ModuleList(pool_layers)
        self.global_pool = nn.AdaptiveMaxPool1d(64)

        flat_dim = channels[-1] * 64
        self.classifier = nn.Sequential(
            nn.Linear(flat_dim, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len)  dtype=long
        emb = self.embedding(x)          # (batch, seq_len, embed_dim)
        emb = emb.permute(0, 2, 1)       # (batch, embed_dim, seq_len)

        out = emb
        for conv, pool in zip(self.convs, self.pools):
            out = conv(out)
            out = pool(out)

        out = self.global_pool(out)       # (batch, channels[-1], 64)
        out = out.flatten(1)              # (batch, channels[-1]*64)
        return self.classifier(out)       # (batch, 2)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Return malicious probability (scalar per sample)."""
        logits = self.forward(x)
        return torch.softmax(logits, dim=-1)[:, 1]


# ---------------------------------------------------------------------------
# Training helpers
# ---------------------------------------------------------------------------

def _make_dataloaders(
    X: np.ndarray,
    y: np.ndarray,
    train_split: float = CNN_TRAIN_SPLIT,
    batch_size:  int   = CNN_BATCH_SIZE,
):
    """Split (X, y) into train/val DataLoaders."""
    X_t = torch.from_numpy(X.astype(np.int64))
    y_t = torch.from_numpy(y.astype(np.int64))
    dataset = TensorDataset(X_t, y_t)

    n_train = int(len(dataset) * train_split)
    n_val   = len(dataset) - n_train
    train_ds, val_ds = random_split(dataset, [n_train, n_val])

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,  num_workers=0, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, num_workers=0)
    return train_loader, val_loader


def _run_epoch(
    model:      ByteCNN,
    loader:     DataLoader,
    criterion:  nn.Module,
    optimizer:  Optional[torch.optim.Optimizer],
    device:     torch.device,
    is_train:   bool,
):
    """Single training or validation epoch. Returns (avg_loss, accuracy)."""
    model.train(is_train)
    total_loss   = 0.0
    correct = total = 0

    ctx = torch.enable_grad() if is_train else torch.no_grad()
    phase_name = "Train" if is_train else "Val  "

    with ctx:
        for Xb, yb in loader:
            Xb, yb = Xb.to(device), yb.to(device)
            logits = model(Xb)
            loss   = criterion(logits, yb)

            if is_train:
                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
                optimizer.step()

            total_loss += loss.item() * len(yb)
            preds    = logits.argmax(dim=1)
            correct += (preds == yb).sum().item()
            total   += len(yb)

    avg_loss = total_loss / max(total, 1)
    accuracy = correct / max(total, 1)
    return avg_loss, accuracy


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------

def train(
    safe_paths=None,
    malicious_paths=None,
    epochs:      int   = CNN_EPOCHS,
    batch_size:  int   = CNN_BATCH_SIZE,
    lr:          float = CNN_LEARNING_RATE,
    download:    bool  = True,
):
    """
    Train the ByteCNN model.

    Parameters
    ----------
    safe_paths, malicious_paths :
        Lists of Path objects.  If None, the DatasetLoader is used.
    epochs, batch_size, lr :
        Training hyper-parameters.
    download : bool
        Whether to trigger dataset downloads before training.
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Using device: %s", device)

    # ---- Data --------------------------------------------------------
    if safe_paths is None or malicious_paths is None:
        loader = DatasetLoader()
        if download:
            loader.download_all()
        safe_paths, malicious_paths = loader.load_all()

    bp = BytePreprocessor()
    X, y = bp.build_dataset(safe_paths, malicious_paths)

    if len(X) == 0:
        logger.error("No data found! Please populate dataset/safe/ and dataset/malicious/.")
        sys.exit(1)

    train_loader, val_loader = _make_dataloaders(X, y, batch_size=batch_size)
    logger.info(
        "Train batches: %d | Val batches: %d", len(train_loader), len(val_loader)
    )

    # ---- Model, loss, optimiser -------------------------------------
    model     = ByteCNN().to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # ---- Training loop ----------------------------------------------
    best_val_acc = 0.0
    CNN_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    epoch_bar = tqdm(range(1, epochs + 1), desc="Epochs", unit="epoch")
    for epoch in epoch_bar:
        train_loss, train_acc = _run_epoch(model, train_loader, criterion, optimizer, device, is_train=True)
        val_loss,   val_acc   = _run_epoch(model, val_loader,   criterion, None,      device, is_train=False)
        scheduler.step()

        epoch_bar.set_postfix(
            train_loss=f"{train_loss:.4f}",
            train_acc=f"{train_acc:.3f}",
            val_loss=f"{val_loss:.4f}",
            val_acc=f"{val_acc:.3f}",
        )
        logger.info(
            "Epoch %03d/%03d  train_loss=%.4f  train_acc=%.3f  val_loss=%.4f  val_acc=%.3f",
            epoch, epochs, train_loss, train_acc, val_loss, val_acc,
        )

        # Save best checkpoint
        if val_acc >= best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), CNN_MODEL_PATH)
            logger.info("✔ Saved best model (val_acc=%.3f) → %s", best_val_acc, CNN_MODEL_PATH)

    logger.info("Training complete. Best val_acc: %.3f", best_val_acc)

    # ---- TorchScript export -----------------------------------------
    logger.info("Exporting TorchScript model …")
    model.eval()
    model.load_state_dict(torch.load(CNN_MODEL_PATH, map_location=device))
    example_input = torch.zeros(1, MAX_BYTES, dtype=torch.long).to(device)
    scripted = torch.jit.trace(model, example_input)
    scripted.save(str(CNN_TORCHSCRIPT_PATH))
    logger.info("TorchScript saved → %s", CNN_TORCHSCRIPT_PATH)

    return model


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train ByteCNN malware classifier")
    parser.add_argument("--epochs",     type=int,   default=CNN_EPOCHS,        help="Number of epochs")
    parser.add_argument("--batch-size", type=int,   default=CNN_BATCH_SIZE,    help="Batch size")
    parser.add_argument("--lr",         type=float, default=CNN_LEARNING_RATE, help="Learning rate")
    parser.add_argument("--no-download", action="store_true",                  help="Skip dataset download")
    args = parser.parse_args()

    train(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        download=not args.no_download,
    )
