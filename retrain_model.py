#!/usr/bin/env python3
import numpy as np
import joblib
import json
import os
import sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif

print("[*] Starting model retraining...")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

np.random.seed(42)
n_samples = 10000

feature_names = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Down/Up Ratio'
]

print(f"[*] Feature count: {len(feature_names)}")

# Normal traffic
X_normal = np.random.normal(loc=[
    500000, 10, 5, 500, 300, 100, 40, 70, 20, 80, 30, 55, 15,
    1000, 20, 0.01, 0.005, 0.05, 0.001, 0.5
], scale=[
    100000, 5, 3, 100, 80, 30, 10, 15, 5, 25, 8, 10, 4,
    500, 10, 0.005, 0.003, 0.02, 0.0005, 0.2
], size=(n_samples, 20))

# Anomalous traffic
X_anomaly = np.random.normal(loc=[
    1000000, 1000, 2, 1500, 100, 1500, 1400, 1450, 50, 100, 50, 75, 10,
    50000, 500, 0.0001, 0.00001, 0.001, 0.000001, 0.01
], scale=[
    200000, 200, 1, 200, 20, 100, 100, 100, 20, 10, 5, 5, 2,
    10000, 50, 0.0001, 0.00001, 0.001, 0.0000001, 0.01
], size=(int(n_samples * 0.1), 20))

X = np.vstack([X_normal, X_anomaly])
print(f"[*] Training data: {X.shape}")

# Train scaler
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
print(f"[+] Scaler trained: expects {scaler.n_features_in_} features")

# Selector
selector = SelectKBest(f_classif, k=20)
y = np.array([0]*n_samples + [1]*int(n_samples*0.1))
X_selected = selector.fit_transform(X_scaled, y)

# Model
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
model.fit(X_selected)
print("[+] Model trained")

# Save files
paths = {
    'model': os.path.join(MODEL_DIR, 'idrs_if_model.pkl'),
    'scaler': os.path.join(MODEL_DIR, 'idrs_scaler.pkl'),
    'selector': os.path.join(MODEL_DIR, 'idrs_selector.pkl'),
    'features': os.path.join(MODEL_DIR, 'idrs_features.json')
}

joblib.dump(model, paths['model'])
joblib.dump(scaler, paths['scaler'])
joblib.dump(selector, paths['selector'])

with open(paths['features'], 'w') as f:
    json.dump({'features': feature_names}, f)

# Verify
print("\n[+] Files saved:")
for name, path in paths.items():
    size = os.path.getsize(path)
    print(f"    {name}: {path} ({size} bytes)")

# Double-check scaler
loaded_scaler = joblib.load(paths['scaler'])
print(f"\n[+] Verification: Loaded scaler expects {loaded_scaler.n_features_in_} features")
print("[+] Done!")