"""
ML Model Inference Service
Loads the trained Random Forest model and makes predictions on file features.
Falls back gracefully if the model file is missing.
"""

import os
import math
import pickle
from collections import Counter
from pathlib import Path

import numpy as np

from config import get_settings
from utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()

_model = None


def _load_model():
    global _model
    model_path = Path(settings.ml_model_path)
    if not model_path.is_absolute():
        # Resolve relative to backend directory
        model_path = Path(__file__).parent.parent / model_path
    if model_path.exists():
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
        logger.info(f"ML model loaded from {model_path}")
    else:
        logger.warning(f"ML model not found at {model_path}. Using heuristic fallback.")


_load_model()


def calculate_entropy(data: bytes) -> float:
    """
    Shannon entropy of a byte sequence.
    High entropy (> 7.0) suggests compressed or encrypted content.
    """
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    return round(entropy, 4)


def _extension_to_int(ext: str) -> int:
    HIGH_RISK = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".jar", ".apk", ".dll"}
    MEDIUM_RISK = {".zip", ".rar", ".7z", ".iso", ".dmg", ".msi", ".sh", ".py"}
    if ext.lower() in HIGH_RISK:
        return 2
    elif ext.lower() in MEDIUM_RISK:
        return 1
    return 0


def extract_features(file_bytes: bytes, filename: str) -> np.ndarray:
    ext = os.path.splitext(filename)[-1]
    features = np.array([
        len(file_bytes),
        calculate_entropy(file_bytes),
        _extension_to_int(ext),
    ]).reshape(1, -1)
    return features


def predict(file_bytes: bytes, filename: str) -> tuple[str, float]:
    """
    Predict whether a file is malicious.
    Returns (label, confidence) where label is "malicious" or "safe".
    """
    features = extract_features(file_bytes, filename)

    if _model is not None:
        try:
            label_int = int(_model.predict(features)[0])
            confidence = float(_model.predict_proba(features)[0][label_int])
            label = "malicious" if label_int == 1 else "safe"
            return label, confidence
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")

    return _heuristic_predict(file_bytes, filename)


def _heuristic_predict(file_bytes: bytes, filename: str) -> tuple[str, float]:
    ext = os.path.splitext(filename)[-1].lower()
    entropy = calculate_entropy(file_bytes)
    size = len(file_bytes)

    risk = 0
    HIGH_RISK_EXTS = {".exe", ".bat", ".scr", ".vbs", ".ps1"}

    if ext in HIGH_RISK_EXTS:
        risk += 40
    if entropy > 7.5:
        risk += 30
    if size < 50_000 and ext in HIGH_RISK_EXTS:
        risk += 20

    if risk >= 60:
        return "malicious", min(risk / 100, 0.95)
    return "safe", max(1 - risk / 100, 0.6)
