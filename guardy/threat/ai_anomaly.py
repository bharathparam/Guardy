from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest
import numpy as np
import math
from datetime import datetime

def calculate_entropy(file_bytes: bytes) -> float:
    """Calculates the Shannon entropy of file bytes. Scale is 0.0 to 8.0."""
    if not file_bytes:
        return 0.0
    entropy = 0.0
    byte_counts = [0] * 256
    for b in file_bytes:
        byte_counts[b] += 1
    length = len(file_bytes)
    for count in byte_counts:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log(p, 2)
    return entropy

class AIAnomalyEngine:
    def __init__(self):
        # Increased contamination slightly as we have more features now
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
        # Mime map to categorize text strings into an integer feature
        self.mime_map = {}
        self.mime_counter = 1

    def _get_mime_id(self, mime_str: str) -> int:
        if mime_str not in self.mime_map:
            self.mime_map[mime_str] = self.mime_counter
            self.mime_counter += 1
        return self.mime_map[mime_str]

    def _extract_features(self, record: Dict[str, Any]) -> List[float]:
        """
        Extracts a multi-dimensional feature vector.
        Expects: file_size (int), mime_type (str), entropy (float), hour (int)
        """
        size = float(record.get("file_size", 0))
        mime_id = float(self._get_mime_id(record.get("mime_type", "unknown")))
        entropy = float(record.get("entropy", 0.0))
        hour = float(record.get("upload_hour", 12)) # fallback to noon
        
        # We perform rudimentary scaling physically to keep IsolationForest balanced. 
        # In a massive prod system we would use MinMaxScaler from sklearn.
        return [
            size / 1_000_000.0, # Scale down MBs
            mime_id,            # Int categorical
            entropy,            # 0.0 - 8.0
            hour / 24.0         # 0.0 - 1.0
        ]

    def train(self, historical_data: List[Dict[str, Any]]):
        """
        Trains the AI on historical user data provided by the backend.
        `historical_data` should be a list of dictionaries:
        [
            {"file_size": 120500, "mime_type": "image/jpeg", "entropy": 4.5, "upload_hour": 14},
            ...
        ]
        """
        if not historical_data or len(historical_data) < 3:
            # Not enough data to make a statistically significant Isolation Forest
            self.is_trained = False
            return

        features = [self._extract_features(d) for d in historical_data]
        self.model.fit(features)
        self.is_trained = True

    def evaluate(self, current_data: Dict[str, Any]) -> float:
        """
        Returns an anomaly score from 0.0 to 1.0.
        0.0 = completely normal
        1.0 = highly anomalous
        """
        if not self.is_trained:
            return 0.0

        features = [self._extract_features(current_data)]
        scores = self.model.score_samples(features)
        
        # Scale score
        outlier_score = -scores[0]
        normalized = max(0.0, min(1.0, (outlier_score + 0.5) / 1.0))
        return normalized
