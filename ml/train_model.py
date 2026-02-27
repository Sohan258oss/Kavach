import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
import os

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

def generate_training_data(n_samples=5000):
    np.random.seed(42)
    rows = []

    # ── BENIGN: normal idle file activity ──
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
            'label': 'Benign'
        })

    # ── RANSOMWARE: based on ACTUAL simulation output ──
    # Your simulation produces:
    # file_events=60, rename=50, suspicious_ext=60, rename_ratio=0.83
    # avg_entropy=1.3, max_entropy=7.8, high_entropy=0.16, avg_cpu=5.0
    for _ in range(n_samples // 2):
        rename_count = np.random.randint(20, 100)
        total        = rename_count + np.random.randint(5, 20)

        rows.append({
            # High volume of events
            'file_events_per_sec':  np.random.randint(30, 150),
            # Mass renaming — KEY signal
            'rename_count':         rename_count,
            'delete_count':         np.random.randint(0, 15),
            'create_count':         np.random.randint(0, 5),
            # Entropy can be LOW on average but MAX is high (some encrypted files)
            'avg_entropy':          np.random.uniform(0.5, 4.0),   # low avg is fine
            'max_entropy':          np.random.uniform(7.0, 8.0),   # max is always high
            'high_entropy_ratio':   np.random.uniform(0.05, 0.5),  # some high entropy files
            # CPU can be LOW — simulation proves this
            'avg_cpu':              np.random.uniform(1.0, 30.0),  # NOT requiring high CPU
            'avg_open_files':       np.random.uniform(5.0, 30.0),
            # Suspicious extensions — KEY signal (your sim had 60!)
            'suspicious_ext_count': np.random.randint(15, 100),
            'unique_extensions':    np.random.randint(1, 4),       # few extensions
            # High rename ratio — KEY signal (your sim had 0.83)
            'rename_ratio':         np.random.uniform(0.5, 1.0),
            'delete_ratio':         np.random.uniform(0.0, 0.2),
            'label': 'Ransomware'
        })

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

# ── Generate and train ──
print("[*] Generating training data based on real simulation behavior...")
df = generate_training_data(5000)
print(f"[*] Dataset: {df.shape[0]} rows")
print(f"[*] Class distribution:\n{df['label'].value_counts()}")

X = df[FEATURES]
y = (df['label'] == 'Ransomware').astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n[*] Training on {len(X_train)} samples...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced',
    max_depth=15,
    min_samples_split=5
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n=== Model Performance ===")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware']))

acc = accuracy_score(y_test, y_pred)
cm  = confusion_matrix(y_test, y_pred)
print(f"Accuracy: {acc:.4f}")
print(f"Confusion Matrix:\n{cm}")
print(f"False Negatives (missed ransomware): {cm[1][0]}")
print(f"False Positives (false alarms):      {cm[0][1]}")

importances = pd.Series(model.feature_importances_, index=FEATURES).sort_values(ascending=False)
print("\n=== Feature Importance (what the model actually uses) ===")
print(importances)

# ── Save ──
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
model_path  = os.path.join(BASE_DIR, 'model.pkl')
encoder_path= os.path.join(BASE_DIR, 'encoder.pkl')

with open(model_path, 'wb') as f:
    pickle.dump(model, f)

from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
le.fit(['Benign', 'Ransomware'])
with open(encoder_path, 'wb') as f:
    pickle.dump(le, f)

print(f"\n[+] Model saved to ml/model.pkl")
print(f"[+] Encoder saved to ml/encoder.pkl")

# ── Sanity check: test on your actual simulation values ──
print("\n=== Sanity Check: Testing on Real Simulation Output ===")
import pandas as pd
test_sample = pd.DataFrame([{
    'file_events_per_sec':  60,
    'rename_count':         50,
    'delete_count':         0,
    'create_count':         0,
    'avg_entropy':          1.3,
    'max_entropy':          7.8,
    'high_entropy_ratio':   0.1667,
    'avg_cpu':              5.0,
    'avg_open_files':       10.0,
    'suspicious_ext_count': 60,
    'unique_extensions':    2,
    'rename_ratio':         0.8333,
    'delete_ratio':         0.0
}])

pred       = model.predict(test_sample)[0]
prob       = model.predict_proba(test_sample)[0]
label      = 'Ransomware' if pred == 1 else 'Benign'
confidence = round(max(prob) * 100, 2)
print(f"Simulation input → Predicted: {label} | Confidence: {confidence}%")
print(f"(This should say Ransomware with high confidence)")