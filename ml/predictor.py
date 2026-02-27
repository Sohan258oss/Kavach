import pickle
import os
import numpy as np
import pandas as pd

# ── Load binary model and encoder ──────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
model_path   = os.path.join(BASE_DIR, 'model.pkl')
encoder_path = os.path.join(BASE_DIR, 'encoder.pkl')

try:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(encoder_path, 'rb') as f:
        encoder = pickle.load(f)
    print("[AI] Binary model loaded successfully")
    print(f"[AI] Known labels: {encoder.classes_}")
except FileNotFoundError:
    raise RuntimeError("Model not found. Run: python retrain.py first")

# ── Load family model ──────────────────────────────────────────────────────────
family_model_path   = os.path.join(BASE_DIR, 'model_family.pkl')
family_encoder_path = os.path.join(BASE_DIR, 'encoder_family.pkl')

try:
    with open(family_model_path, 'rb') as f:
        family_model = pickle.load(f)
    with open(family_encoder_path, 'rb') as f:
        family_encoder = pickle.load(f)
    print("[AI] Family model loaded successfully")
    print(f"[AI] Known families: {family_encoder.classes_}")
except FileNotFoundError:
    family_model   = None
    family_encoder = None
    print("[AI] Family model not found — run retrain.py")

# ── Features — must match retrain.py and feature_extractor.py exactly ──────────
FEATURES = [
    'file_events_per_sec',
    'rename_count',
    'delete_count',
    'create_count',
    'avg_entropy',
    'max_entropy',
    'high_entropy_ratio',
    'avg_cpu',
    'avg_open_files',
    'suspicious_ext_count',
    'unique_extensions',
    'rename_ratio',
    'delete_ratio'
]

CONFIDENCE_THRESHOLD = 55.0

def predict(features: dict) -> dict:
    """
    Takes a dict of behavioral features, returns prediction.
    features: dict with keys matching FEATURES list
    """
    # ── Warn about missing features ──
    missing = [f for f in FEATURES if f not in features]
    if missing:
        print(f"[AI WARNING] Missing features defaulting to 0: {missing}")

    # ── Build input vector ──
    values = [features.get(f, 0) for f in FEATURES]
    X      = pd.DataFrame([values], columns=FEATURES)

    # ── Binary prediction ──
    prediction  = model.predict(X)[0]
    probability = model.predict_proba(X)[0]

    label           = encoder.inverse_transform([prediction])[0]
    confidence      = round(max(probability) * 100, 2)
    ransomware_prob = round(probability[1] * 100, 2)
    is_ransomware   = (label == 'Ransomware') and (confidence >= CONFIDENCE_THRESHOLD)

    # ── Family prediction (only if ransomware detected) ──
    family_label      = 'Unknown'
    family_confidence = 0.0

    if is_ransomware and family_model and family_encoder:
        fam_pred          = family_model.predict(X)[0]
        fam_prob          = family_model.predict_proba(X)[0]
        family_label      = family_encoder.inverse_transform([fam_pred])[0]
        family_confidence = round(max(fam_prob) * 100, 2)

    # ── Console output ──
    if label == 'Ransomware':
        print(f"[AI] 🚨 RANSOMWARE DETECTED — {confidence}% confidence")
        if family_label != 'Unknown' and family_label != 'Benign':
            print(f"[AI] 🔍 Family: {family_label} — {family_confidence}% confidence")
    else:
        print(f"[AI] ✅ Benign — {confidence}% confidence")

    return {
        'label':              label,
        'confidence':         confidence,
        'ransomware_probability': ransomware_prob,
        'is_ransomware':      is_ransomware,
        'high_confidence':    confidence >= 90.0,
        'threshold_used':     CONFIDENCE_THRESHOLD,
        'family':             family_label,
        'family_confidence':  family_confidence
    }