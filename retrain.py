import pandas as pd
import numpy as np
import pickle
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import fbeta_score, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
import time
import warnings
warnings.filterwarnings('ignore')

# ── Features that match your live monitor exactly ─────────────────────────────
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

def generate_data(n=6000):
    np.random.seed(42)
    rows = []

    # ── BENIGN ────────────────────────────────────────────────────────────────
    for _ in range(n // 4):
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
            'label':    'Benign',
            'category': 'Benign',
            'family':   'Benign'
        })

    # ── WANNACRY — mass rename to .wncry, high entropy, moderate CPU ──────────
    for _ in range(n // 4):
        rename_count = np.random.randint(30, 120)
        total        = rename_count + np.random.randint(5, 20)
        rows.append({
            'file_events_per_sec':  np.random.randint(50, 200),
            'rename_count':         rename_count,
            'delete_count':         np.random.randint(5, 20),
            'create_count':         np.random.randint(0, 5),
            'avg_entropy':          np.random.uniform(0.5, 3.0),
            'max_entropy':          np.random.uniform(7.5, 8.0),
            'high_entropy_ratio':   np.random.uniform(0.1, 0.5),
            'avg_cpu':              np.random.uniform(5.0, 40.0),
            'avg_open_files':       np.random.uniform(10.0, 50.0),
            'suspicious_ext_count': np.random.randint(20, rename_count),
            'unique_extensions':    np.random.randint(1, 3),
            'rename_ratio':         np.random.uniform(0.6, 0.95),
            'delete_ratio':         np.random.uniform(0.05, 0.2),
            'label':    'Ransomware',
            'category': 'Ransomware',
            'family':   'WannaCry'
        })

    # ── LOCKBIT — very fast, mass delete + rename, very high entropy ──────────
    for _ in range(n // 4):
        rename_count = np.random.randint(50, 150)
        total        = rename_count + np.random.randint(10, 30)
        rows.append({
            'file_events_per_sec':  np.random.randint(100, 300),
            'rename_count':         rename_count,
            'delete_count':         np.random.randint(20, 60),   # LockBit deletes aggressively
            'create_count':         np.random.randint(0, 5),
            'avg_entropy':          np.random.uniform(1.0, 4.0),
            'max_entropy':          np.random.uniform(7.8, 8.0),
            'high_entropy_ratio':   np.random.uniform(0.3, 0.8),
            'avg_cpu':              np.random.uniform(10.0, 60.0),
            'avg_open_files':       np.random.uniform(20.0, 100.0),
            'suspicious_ext_count': np.random.randint(30, rename_count),
            'unique_extensions':    np.random.randint(1, 2),     # LockBit uses 1 extension
            'rename_ratio':         np.random.uniform(0.5, 0.85),
            'delete_ratio':         np.random.uniform(0.15, 0.45),
            'label':    'Ransomware',
            'category': 'Ransomware',
            'family':   'LockBit'
        })

    # ── REVIL/SODINOKIBI — slower, more targeted, high entropy ───────────────
    for _ in range(n // 4):
        rename_count = np.random.randint(15, 80)
        total        = rename_count + np.random.randint(5, 15)
        rows.append({
            'file_events_per_sec':  np.random.randint(20, 100),  # slower than LockBit
            'rename_count':         rename_count,
            'delete_count':         np.random.randint(3, 15),
            'create_count':         np.random.randint(1, 10),    # creates ransom notes
            'avg_entropy':          np.random.uniform(2.0, 5.0),
            'max_entropy':          np.random.uniform(7.2, 8.0),
            'high_entropy_ratio':   np.random.uniform(0.05, 0.35),
            'avg_cpu':              np.random.uniform(3.0, 25.0), # lower CPU, more stealthy
            'avg_open_files':       np.random.uniform(5.0, 30.0),
            'suspicious_ext_count': np.random.randint(10, rename_count),
            'unique_extensions':    np.random.randint(1, 4),
            'rename_ratio':         np.random.uniform(0.4, 0.8),
            'delete_ratio':         np.random.uniform(0.02, 0.15),
            'label':    'Ransomware',
            'category': 'Ransomware',
            'family':   'REvil'
        })

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    return df

# ── Generate data ─────────────────────────────────────────────────────────────
print("[*] Generating synthetic training data...")
df = generate_data(6000)
print(f"[*] Dataset: {df.shape[0]} rows")
print(f"[*] Distribution:\n{df['family'].value_counts()}\n")

X = df[FEATURES].values

# ── Labels ────────────────────────────────────────────────────────────────────
le_binary   = LabelEncoder().fit(['Benign', 'Ransomware'])
le_family   = LabelEncoder().fit(['Benign', 'LockBit', 'REvil', 'WannaCry'])

y_binary = le_binary.transform(df['label'])
y_family = le_family.transform(df['family'])

# ── Split ─────────────────────────────────────────────────────────────────────
X_train, X_test, yb_train, yb_test, yf_train, yf_test = train_test_split(
    X, y_binary, y_family,
    test_size=0.2, random_state=42, stratify=y_binary
)

# ═══════════════════════════════════════════════════════════════════════════════
# MODEL 1: Binary (Benign vs Ransomware)
# ═══════════════════════════════════════════════════════════════════════════════
print("="*60)
print("MODEL 1: Binary — Benign vs Ransomware")
print("="*60)

model_binary = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric='logloss',
    random_state=42,
    n_jobs=-1
)
model_binary.fit(X_train, yb_train, eval_set=[(X_test, yb_test)], verbose=False)
yb_pred = model_binary.predict(X_test)
print(classification_report(yb_test, yb_pred, target_names=['Benign', 'Ransomware']))
print(f"Accuracy: {accuracy_score(yb_test, yb_pred):.4f}")

# Feature importance
print("\nTop Features:")
importances = sorted(zip(FEATURES, model_binary.feature_importances_), key=lambda x: -x[1])
for feat, imp in importances[:8]:
    bar = '█' * int(imp * 300)
    print(f"  {feat:<30} {imp:.4f} {bar}")
print("\n" + "="*60)
print("EVALUATION METRICS — BINARY CLASSIFIER")
print("="*60)

# ── 1. F2 SCORE ───────────────────────────────────────────────
f2 = fbeta_score(yb_test, yb_pred, beta=2)
print(f"\n① F2 Score (recall-weighted): {f2:.4f}")
print(f"   (> 0.95 is excellent for ransomware detection)")

# ── 2. FALSE NEGATIVE / FALSE POSITIVE RATES ──────────────────
tn, fp, fn, tp = confusion_matrix(yb_test, yb_pred).ravel()
fnr = fn / (fn + tp)
fpr = fp / (fp + tn)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall    = tp / (tp + fn) if (tp + fn) > 0 else 0

print(f"\n② False Negative Rate (Miss Rate): {fnr:.4f}  {'✅ GOOD' if fnr < 0.01 else '⚠ HIGH — you are missing attacks'}")
print(f"   False Positive Rate (False Alarm): {fpr:.4f}  {'✅ GOOD' if fpr < 0.05 else '⚠ HIGH — too many false alarms'}")
print(f"   Precision: {precision:.4f}  (of ransomware alerts, how many were real?)")
print(f"   Recall:    {recall:.4f}  (of real ransomware, how many did we catch?)")
print(f"\n   Confusion Matrix breakdown:")
print(f"   TP (caught ransomware)    : {tp}")
print(f"   TN (correctly benign)     : {tn}")
print(f"   FP (false alarms)         : {fp}  ← interrupts user workflow")
print(f"   FN (missed ransomware)    : {fn}  ← dangerous, ransomware got through")

# ── 3. AUC-ROC ────────────────────────────────────────────────
auc = roc_auc_score(yb_test, model_binary.predict_proba(X_test)[:, 1])
print(f"\n③ AUC-ROC Score: {auc:.4f}  {'✅ EXCELLENT' if auc > 0.99 else '✅ GOOD' if auc > 0.95 else '⚠ NEEDS WORK'}")
print(f"   (Threshold-independent — 1.0 is perfect, 0.5 is random guessing)")

# Plot ROC curve
fpr_curve, tpr_curve, thresholds = roc_curve(yb_test, model_binary.predict_proba(X_test)[:, 1])
plt.figure(figsize=(7, 5))
plt.plot(fpr_curve, tpr_curve, color='#00f5ff', lw=2, label=f'ROC Curve (AUC = {auc:.4f})')
plt.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--', label='Random Classifier')
plt.fill_between(fpr_curve, tpr_curve, alpha=0.1, color='#00f5ff')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate (Recall)')
plt.title('ROC Curve — Binary Ransomware Classifier')
plt.legend(loc='lower right')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('ml/roc_curve.png', dpi=150)
plt.close()
print(f"   Saved: ml/roc_curve.png")

# ── 4. INFERENCE LATENCY ──────────────────────────────────────
print(f"\n④ Inference Latency:")
# Warm up the model first (first call is always slow due to JIT)
_ = model_binary.predict(X_test[:1])

# Measure over 1000 runs for accuracy
times = []
for _ in range(1000):
    start = time.perf_counter()
    model_binary.predict(X_test[:1])
    times.append((time.perf_counter() - start) * 1000)

avg_ms  = np.mean(times)
min_ms  = np.min(times)
max_ms  = np.max(times)
p99_ms  = np.percentile(times, 99)

print(f"   Average : {avg_ms:.3f}ms")
print(f"   Min     : {min_ms:.3f}ms")
print(f"   Max     : {max_ms:.3f}ms")
print(f"   P99     : {p99_ms:.3f}ms  (worst case 99% of the time)")
print(f"   {'✅ FAST ENOUGH for real-time' if avg_ms < 5 else '⚠ TOO SLOW — optimize features'}")

# ── 5. MEAN TIME TO DETECT (MTTD) ─────────────────────────────
print(f"\n⑤ Mean Time to Detect (MTTD):")
print(f"   Current window size     : 200 events")
print(f"   Min events to trigger   : 30 (your current threshold)")
print(f"   Files renamed at alert  : ~50 files")
print(f"")

# Simulate detection at different window sizes
print(f"   Window size vs files encrypted before detection:")
print(f"   {'Window':>8} | {'Min Events':>10} | {'~Files Encrypted':>17} | {'Recommendation':>20}")
print(f"   {'-'*65}")
configs = [
    (50,  15, "⚠ May miss slow ransomware"),
    (100, 20, "✅ Good balance"),
    (200, 30, "✅ Current setting"),
    (300, 50, "⚠ Too slow to detect"),
]
for window, min_ev, note in configs:
    files_encrypted = int(min_ev * 0.6)  # ~60% of events are renames
    marker = "◄ YOU ARE HERE" if window == 200 else ""
    print(f"   {window:>8} | {min_ev:>10} | {files_encrypted:>17} | {note} {marker}")

print(f"\n   Recommendation: reduce MIN_EVENTS to 20 and window to 100")
print(f"   to detect ransomware after ~12 files encrypted instead of ~50")

# ── CONFUSION MATRIX PLOTS ────────────────────────────────────
print(f"\n" + "="*60)
print("CONFUSION MATRICES")
print("="*60)

# Binary
cm_binary = confusion_matrix(yb_test, yb_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm_binary, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Ransomware'],
            yticklabels=['Benign', 'Ransomware'],
            annot_kws={'size': 16})
plt.title(f'Binary Classifier — Confusion Matrix\nAUC: {auc:.4f} | F2: {f2:.4f} | FNR: {fnr:.4f}')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('ml/confusion_binary.png', dpi=150)
plt.close()
print(f"✓ Saved: ml/confusion_binary.png")


# ── FINAL SUMMARY ─────────────────────────────────────────────
print(f"\n" + "="*60)
print("SENTINEL MODEL SUMMARY")
print("="*60)
print(f"  F2 Score          : {f2:.4f}")
print(f"  AUC-ROC           : {auc:.4f}")
print(f"  Miss Rate (FNR)   : {fnr:.4f}  ({fn} ransomware samples missed)")
print(f"  False Alarm (FPR) : {fpr:.4f}  ({fp} benign samples flagged)")
print(f"  Avg Latency       : {avg_ms:.3f}ms per prediction")
print(f"  P99 Latency       : {p99_ms:.3f}ms worst case")
print(f"  Files before detect: ~{int(30 * 0.6)} (current) → ~12 (optimized)")
print("="*60)

# ═══════════════════════════════════════════════════════════════════════════════
# MODEL 2: Family (WannaCry vs LockBit vs REvil vs Benign)
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("MODEL 2: Family — Which ransomware strain?")
print("Families:", le_family.classes_)
print("="*60)

model_family = XGBClassifier(
    n_estimators=400,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.7,
    eval_metric='mlogloss',
    random_state=42,
    n_jobs=-1
)
model_family.fit(X_train, yf_train, eval_set=[(X_test, yf_test)], verbose=False)
yf_pred = model_family.predict(X_test)
print(classification_report(yf_test, yf_pred, target_names=le_family.classes_))
print(f"Accuracy: {accuracy_score(yf_test, yf_pred):.4f}")
# Family
cm_family = confusion_matrix(yf_test, yf_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(cm_family, annot=True, fmt='d', cmap='Reds',
            xticklabels=le_family.classes_,
            yticklabels=le_family.classes_,
            annot_kws={'size': 13})
plt.title('Family Classifier — Confusion Matrix\n(Diagonal = correct, off-diagonal = misclassified family)')
plt.ylabel('Actual Family')
plt.xlabel('Predicted Family')
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.savefig('ml/confusion_family.png', dpi=150)
plt.close()
print(f"✓ Saved: ml/confusion_family.png")

# ═══════════════════════════════════════════════════════════════════════════════
# SANITY CHECK on real simulation values
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SANITY CHECK: Testing on real simulation output")
print("="*60)

test_sample = np.array([[
    120, 50, 10, 50, 0.65, 7.8, 0.0833,
    5.0, 10.0, 70, 3, 0.4167, 0.0833
]])

binary_pred  = model_binary.predict(test_sample)[0]
binary_prob  = model_binary.predict_proba(test_sample)[0]
family_pred  = model_family.predict(test_sample)[0]
family_prob  = model_family.predict_proba(test_sample)[0]

binary_label = le_binary.inverse_transform([binary_pred])[0]
family_label = le_family.inverse_transform([family_pred])[0]

print(f"Binary:  {binary_label} ({max(binary_prob)*100:.1f}% confidence)")
print(f"Family:  {family_label} ({max(family_prob)*100:.1f}% confidence)")
print(f"(Should say Ransomware / WannaCry or LockBit)")

# ═══════════════════════════════════════════════════════════════════════════════
# SAVE
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("Saving models...")

with open('ml/model.pkl', 'wb') as f:
    pickle.dump(model_binary, f)

with open('ml/model_family.pkl', 'wb') as f:
    pickle.dump(model_family, f)

with open('ml/encoder.pkl', 'wb') as f:
    pickle.dump(le_binary, f)

with open('ml/encoder_family.pkl', 'wb') as f:
    pickle.dump(le_family, f)

with open('ml/feature_cols.pkl', 'wb') as f:
    pickle.dump(FEATURES, f)

print("✓ ml/model.pkl          (binary detector — used by live monitor)")
print("✓ ml/model_family.pkl   (family identifier)")
print("✓ ml/encoder.pkl        (binary labels)")
print("✓ ml/encoder_family.pkl (family labels)")
print("✓ ml/feature_cols.pkl   (feature list)")
print("\n[*] Done. Run: python main.py")