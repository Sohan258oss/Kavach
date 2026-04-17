"""
train_model.py — Train the binary ransomware classifier.

FEATURES list imported from config.py (single source of truth).
"""

import os
import pickle
from typing import List

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Allow running standalone (python ml/train_model.py) or from project root
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config import FEATURES, ML_DIR

FEATURES_LIST: List[str] = list(FEATURES)


def generate_training_data(n_samples: int = 5000) -> pd.DataFrame:
    np.random.seed(42)
    rows: list = []

    # ── BENIGN ────────────────────────────────────────────────────────────
    for _ in range(n_samples // 2):
        rows.append({
            'file_events_per_sec':  np.random.randint(1, 15),
            'rename_count':         np.random.randint(0, 3),
            'delete_count':         np.random.randint(0, 2),
            'create_count':         np.random.randint(0, 8),
            'avg_entropy':          np.random.uniform(0.0, 5.0),
            'max_entropy':          np.random.uniform(0.0, 6.0),
            'high_entropy_ratio':   np.random.uniform(0.0, 0.05),
            'avg_cpu':              np.random.uniform(0.0, 20.0),
            'avg_open_files':       np.random.uniform(0.0, 20.0),
            'suspicious_ext_count': 0,
            'unique_extensions':    np.random.randint(1, 10),
            'rename_ratio':         np.random.uniform(0.0, 0.08),
            'delete_ratio':         np.random.uniform(0.0, 0.05),
            'label': 'Benign',
        })

    # ── RANSOMWARE ────────────────────────────────────────────────────────
    for _ in range(n_samples // 2):
        rename_count: int = np.random.randint(20, 100)
        rows.append({
            'file_events_per_sec':  np.random.randint(30, 150),
            'rename_count':         rename_count,
            'delete_count':         np.random.randint(0, 15),
            'create_count':         np.random.randint(0, 5),
            'avg_entropy':          np.random.uniform(0.5, 4.0),
            'max_entropy':          np.random.uniform(7.0, 8.0),
            'high_entropy_ratio':   np.random.uniform(0.05, 0.5),
            'avg_cpu':              np.random.uniform(1.0, 30.0),
            'avg_open_files':       np.random.uniform(5.0, 30.0),
            'suspicious_ext_count': np.random.randint(15, 100),
            'unique_extensions':    np.random.randint(1, 4),
            'rename_ratio':         np.random.uniform(0.5, 1.0),
            'delete_ratio':         np.random.uniform(0.0, 0.2),
            'label': 'Ransomware',
        })

    df: pd.DataFrame = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == '__main__':
    print("[*] Generating training data …")
    df = generate_training_data(5000)
    print(f"[*] Dataset: {df.shape[0]} rows")
    print(f"[*] Class distribution:\n{df['label'].value_counts()}")

    X = df[FEATURES_LIST]
    y = (df['label'] == 'Ransomware').astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    print(f"\n[*] Training on {len(X_train)} samples …")
    model = RandomForestClassifier(
        n_estimators=200, random_state=42, n_jobs=-1,
        class_weight='balanced', max_depth=15, min_samples_split=5,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n=== Model Performance ===")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware']))

    acc: float = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    importances = pd.Series(
        model.feature_importances_, index=FEATURES_LIST,
    ).sort_values(ascending=False)
    print("\n=== Feature Importance ===")
    print(importances)

    # ── Save ──
    model_path: str = os.path.join(ML_DIR, 'model.pkl')
    encoder_path: str = os.path.join(ML_DIR, 'encoder.pkl')

    with open(model_path, 'wb') as f:
        pickle.dump(model, f)

    le = LabelEncoder()
    le.fit(['Benign', 'Ransomware'])
    with open(encoder_path, 'wb') as f:
        pickle.dump(le, f)

    print(f"\n[+] Model  saved → {model_path}")
    print(f"[+] Encoder saved → {encoder_path}")

    # ── Sanity check ──
    print("\n=== Sanity Check ===")
    test_sample = pd.DataFrame([{
        'file_events_per_sec': 60, 'rename_count': 50,
        'delete_count': 0, 'create_count': 0,
        'avg_entropy': 1.3, 'max_entropy': 7.8,
        'high_entropy_ratio': 0.1667, 'avg_cpu': 5.0,
        'avg_open_files': 10.0, 'suspicious_ext_count': 60,
        'unique_extensions': 2, 'rename_ratio': 0.8333,
        'delete_ratio': 0.0,
    }])
    pred = model.predict(test_sample)[0]
    prob = model.predict_proba(test_sample)[0]
    label = 'Ransomware' if pred == 1 else 'Benign'
    confidence = round(max(prob) * 100, 2)
    print(f"Simulation input → {label} | Confidence: {confidence}%")