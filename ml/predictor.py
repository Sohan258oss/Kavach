import pickle
import os
import numpy as np
import pandas as pd
# Load model and encoder once when imported
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
encoder_path = os.path.join(os.path.dirname(__file__), 'encoder.pkl')

with open(model_path, 'rb') as f:
    model = pickle.load(f)

with open(encoder_path, 'rb') as f:
    encoder = pickle.load(f)

FEATURES = [
    'registry_read', 'registry_write', 'registry_delete', 'registry_total',
    'network_threats', 'network_dns', 'network_http', 'network_connections',
    'processes_malicious', 'processes_suspicious', 'processes_monitored',
    'total_processes', 'files_malicious', 'files_suspicious', 'files_text',
    'files_unknown', 'dlls_calls', 'apis'
]

def predict(features: dict) -> dict:
    """
    Takes a dict of behavioral features, returns prediction.
    features: dict with keys matching FEATURES list
    """
    print(f"[AI] Analyzing features: {features}")
    values = [features.get(f, 0) for f in FEATURES]
    X = pd.DataFrame([values], columns=FEATURES)
    
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    
    label = encoder.inverse_transform([prediction])[0]
    confidence = round(max(probability) * 100, 2)
    
    return {
        'label': label,
        'confidence': confidence,
        'is_ransomware': label == 'Malware'
    }