"""
predictor.py — ML inference for Project Kavach (Sentinel).

Loads the binary and family models, runs predictions against incoming
feature vectors.  All constants imported from config.py.
"""

import pickle
import os
from typing import Dict, List, Any, Union

import numpy as np
import pandas as pd

from config import (
    MODEL_PATH,
    ENCODER_PATH,
    FAMILY_MODEL_PATH,
    FAMILY_ENCODER_PATH,
    FEATURES,
    CONFIDENCE_THRESHOLD,
    HIGH_CONFIDENCE_THRESHOLD,
)
from logging_utils import get_logger

logger = get_logger('predictor')

# ── Load binary model + encoder ───────────────────────────────────────────────
try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(ENCODER_PATH, 'rb') as f:
        encoder = pickle.load(f)
    logger.info("Binary model loaded — labels: %s", encoder.classes_)
except FileNotFoundError:
    raise RuntimeError("Model not found.  Run: python retrain.py first")

# ── Load family model (optional) ─────────────────────────────────────────────
try:
    with open(FAMILY_MODEL_PATH, 'rb') as f:
        family_model = pickle.load(f)
    with open(FAMILY_ENCODER_PATH, 'rb') as f:
        family_encoder = pickle.load(f)
    logger.info("Family model loaded — families: %s", family_encoder.classes_)
except FileNotFoundError:
    family_model = None
    family_encoder = None
    logger.warning("Family model not found — run retrain.py")


def predict(features: Dict[str, Union[int, float]]) -> Dict[str, Any]:
    """
    Run binary (+ optional family) prediction on a feature vector.

    Args:
        features: dict whose keys match ``config.FEATURES``.

    Returns:
        Dict with keys: label, confidence, ransomware_probability,
        is_ransomware, high_confidence, threshold_used, family,
        family_confidence.
    """
    missing: List[str] = [f for f in FEATURES if f not in features]
    if missing:
        logger.warning("Missing features (defaulting to 0): %s", missing)

    values = [features.get(f, 0) for f in FEATURES]
    X: pd.DataFrame = pd.DataFrame([values], columns=FEATURES)

    # ── Binary prediction ─────────────────────────────────────────────────
    prediction: int = int(model.predict(X)[0])
    probability: np.ndarray = model.predict_proba(X)[0]

    label: str = encoder.inverse_transform([prediction])[0]
    confidence: float = round(float(max(probability)) * 100, 2)
    ransomware_prob: float = round(float(probability[1]) * 100, 2)
    is_ransomware: bool = (
        label == 'Ransomware' and confidence >= CONFIDENCE_THRESHOLD
    )

    # ── Family prediction (only when ransomware detected) ─────────────────
    family_label: str = 'Unknown'
    family_confidence: float = 0.0

    if is_ransomware and family_model is not None and family_encoder is not None:
        fam_pred: int = int(family_model.predict(X)[0])
        fam_prob: np.ndarray = family_model.predict_proba(X)[0]
        family_label = family_encoder.inverse_transform([fam_pred])[0]
        family_confidence = round(float(max(fam_prob)) * 100, 2)

    # ── Structured log ────────────────────────────────────────────────────
    if label == 'Ransomware':
        logger.warning(
            "\U0001f6a8 RANSOMWARE DETECTED — %.1f%% confidence", confidence,
        )
        if family_label not in ('Unknown', 'Benign'):
            logger.warning(
                "\U0001f50d Family: %s — %.1f%% confidence",
                family_label, family_confidence,
            )
    else:
        logger.info("\u2705 Benign — %.1f%% confidence", confidence)

    return {
        'label':                  label,
        'confidence':             confidence,
        'ransomware_probability': ransomware_prob,
        'is_ransomware':          is_ransomware,
        'high_confidence':        confidence >= HIGH_CONFIDENCE_THRESHOLD,
        'threshold_used':         CONFIDENCE_THRESHOLD,
        'family':                 family_label,
        'family_confidence':      family_confidence,
    }