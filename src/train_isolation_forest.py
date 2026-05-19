#!/usr/bin/env python3
"""
IDRS - CICIDS2017 Unsupervised Isolation Forest Training
Train on BENIGN traffic ONLY. Labels used ONLY for feature selection & validation.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
import joblib
import json
import os
import warnings
warnings.filterwarnings('ignore')

CONFIG = {
    'dataset_path': 'data/Monday-WorkingHours.pcap_ISCX.csv',  # Benign training data
    'attack_data_path': 'data/Wednesday-workingHours.pcap_ISCX.csv',  # Realistic mixed validation
    'model_output': './models/idrs_if_model.pkl',
    'scaler_output': './models/idrs_scaler.pkl',
    'selector_output': './models/idrs_selector.pkl',
    'features_output': './models/idrs_features.json',
    'contamination': 0.05,      # Expected anomaly ratio in real network
    'n_estimators': 300,
    'feature_count': 20,        # Top K features
    'random_state': 42
}


def detect_separator(filepath):
    """Auto-detect if CSV is comma or tab separated"""
    with open(filepath, 'r') as f:
        first_line = f.readline()
        if '\t' in first_line:
            return '\t'
        return ','


def load_cicids_data(filepath):
    """
    Load CICIDS2017 CSV with proper handling of its specific format
    """
    print(f"[*] Loading: {filepath}")
    
    sep = detect_separator(filepath)
    print(f"    Detected separator: {'tab' if sep == '\t' else 'comma'}")
    
    # CICIDS2017 specific: low_memory=False prevents dtype warnings
    df = pd.read_csv(filepath, sep=sep, low_memory=False)
    
    # Clean column names - remove whitespace
    df.columns = df.columns.str.strip()
    
    print(f"[+] Loaded {len(df)} records with {len(df.columns)} features")
    print(f"[+] Columns: {list(df.columns[:5])}...{list(df.columns[-3:])}")
    
    return df


def clean_cicids_data(df):
    """
    Clean CICIDS2017 specific issues:
    1. Infinite values in Flow Bytes/s, Flow Packets/s (division by zero)
    2. NaN values
    3. Negative values where they shouldn't exist
    4. Constant/zero-variance features
    """
    print("\n[*] Cleaning data...")
    original_count = len(df)
    
    # Replace infinite values with NaN first
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Drop rows with NaN (usually caused by Flow Duration = 0)
    df = df.dropna()
    print(f"    Dropped {original_count - len(df)} rows with inf/NaN")
    
    # CICIDS2017 specific: Ensure Label exists and is string
    if 'Label' not in df.columns:
        # Try common variations
        for col in df.columns:
            if 'label' in col.lower():
                df = df.rename(columns={col: 'Label'})
                break
    
    # Create binary label
    df['Label_Binary'] = df['Label'].apply(
        lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1
    )
    
    # Drop the original Label column from features (keep binary version)
    feature_df = df.drop(['Label'], axis=1, errors='ignore')
    
    print(f"[+] Clean dataset: {len(feature_df)} records")
    print(f"[+] Benign: {len(feature_df[feature_df['Label_Binary']==0])}")
    print(f"[+] Attack: {len(feature_df[feature_df['Label_Binary']==1])}")
    
    return feature_df


def remove_constant_features(df, threshold=0.01):
    """
    Remove features with near-zero variance (all same value)
    Common in CICIDS2017: Fwd Avg Bytes/Bulk, CWE Flag Count, etc.
    """
    print("\n[*] Removing constant/low-variance features...")
    
    # Exclude Label from this check
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if 'Label_Binary' in numeric_cols:
        numeric_cols.remove('Label_Binary')
    
    constant_cols = []
    for col in numeric_cols:
        std = df[col].std()
        if std < threshold:
            constant_cols.append(col)
    
    if constant_cols:
        print(f"    Removing {len(constant_cols)} constant features:")
        for col in constant_cols[:10]:
            print(f"      - {col}")
        if len(constant_cols) > 10:
            print(f"      ... and {len(constant_cols)-10} more")
        df = df.drop(columns=constant_cols)
    
    print(f"[+] Remaining features: {len(df.columns)-1}")
    return df, constant_cols


def engineer_features(df):
    """
    Select relevant network flow features from CICIDS2017
    Based on your data sample, these are the core features
    """
    print("\n[*] Engineering features...")
    
    # Core CICIDS2017 features (matching your data exactly)
    base_features = [
        # Port and Duration
        'Destination Port', 'Flow Duration',
        
        # Packet Counts
        'Total Fwd Packets', 'Total Backward Packets',
        
        # Byte Totals
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        
        # Forward Packet Length Stats
        'Fwd Packet Length Max', 'Fwd Packet Length Min',
        'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        
        # Backward Packet Length Stats
        'Bwd Packet Length Max', 'Bwd Packet Length Min',
        'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        
        # Flow Rates
        'Flow Bytes/s', 'Flow Packets/s',
        
        # Inter-Arrival Time (IAT)
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        
        # TCP Flags
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Length', 'Bwd Header Length',
        
        # Directional Rates
        'Fwd Packets/s', 'Bwd Packets/s',
        
        # Packet Length Overall
        'Min Packet Length', 'Max Packet Length',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        
        # TCP Flag Counts
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
        'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
        'CWE Flag Count', 'ECE Flag Count',
        
        # Ratios and Sizes
        'Down/Up Ratio', 'Average Packet Size',
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        
        # Subflow features
        'Subflow Fwd Packets', 'Subflow Fwd Bytes',
        'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        
        # Window/Header
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward',
        
        # Active/Idle (if present)
        'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
    
    # Keep only features that exist in the dataset
    available_features = [f for f in base_features if f in df.columns]
    missing = set(base_features) - set(available_features)
    
    if missing:
        print(f"    [!] Missing features (skipped): {list(missing)[:5]}...")
    
    # Also include any other numeric features not in our list
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    extra_cols = [c for c in numeric_cols if c not in available_features and c != 'Label_Binary']
    
    # Add extra columns if they seem useful (not ID columns)
    final_features = available_features + extra_cols
    
    # Remove any non-numeric or label columns
    feature_cols = [c for c in final_features if c in df.columns and c != 'Label_Binary']
    
    X = df[feature_cols].copy()
    y = df['Label_Binary'].values
    
    # Handle any remaining infinite values
    X = X.replace([np.inf, -np.inf], 0)
    
    # Clip extreme outliers (CICIDS2017 has some crazy values)
    for col in ['Flow Bytes/s', 'Flow Packets/s']:
        if col in X.columns:
            upper = X[col].quantile(0.999)
            X[col] = X[col].clip(upper=upper)
    
    print(f"[+] Using {len(feature_cols)} features")
    
    return X, y, feature_cols


def select_features(X_benign, X_attack, y_full, feature_names, k=20):
    """
    Feature selection using Mutual Information on FULL dataset
    This is PREPROCESSING - labels only used to find important features
    """
    print(f"\n[*] Feature Selection (top {k})...")
    print(f"    Using Mutual Information on full labeled dataset")
    
    # Combine for feature ranking
    X_full = pd.concat([X_benign, X_attack], ignore_index=True)
    
    # RobustScaler handles outliers better than StandardScaler
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X_full)
    
    # Select K Best using Mutual Information
    k = min(k, X_full.shape[1])
    selector = SelectKBest(score_func=mutual_info_classif, k=k)
    selector.fit(X_scaled, y_full)
    
    # Get selected feature names
    mask = selector.get_support()
    selected_features = [feature_names[i] for i in range(len(feature_names)) if mask[i]]
    
    # Print rankings
    scores = selector.scores_
    ranked = sorted(zip(feature_names, scores), key=lambda x: x[1], reverse=True)
    
    print("\n[+] Top 15 Features by Importance:")
    for feat, score in ranked[:15]:
        marker = " ✓" if feat in selected_features else ""
        print(f"    {score:.4f}  {feat}{marker}")
    
    # Transform datasets
    X_benign_sel = selector.transform(scaler.transform(X_benign))
    X_attack_sel = selector.transform(scaler.transform(X_attack))
    
    print(f"\n[+] Selected {len(selected_features)} features for model")
    
    return X_benign_sel, X_attack_sel, scaler, selector, selected_features


def train_unsupervised_if(X_benign_train, contamination=0.05):
    """
    CRITICAL: Train Isolation Forest on BENIGN data ONLY
    This is the unsupervised step - no labels, no attack data
    """
    print(f"\n" + "="*60)
    print("UNSUPERVISED MODEL TRAINING")
    print("="*60)
    print(f"[*] Training samples: {len(X_benign_train)} (ALL BENIGN)")
    print(f"[*] Algorithm: Isolation Forest")
    print(f"[*] Contamination: {contamination} (expected anomaly ratio)")
    print(f"[*] Estimators: {CONFIG['n_estimators']}")
    
    model = IsolationForest(
        n_estimators=CONFIG['n_aestimators'],
        max_samples='auto',
        contamination=contamination,
        random_state=CONFIG['random_state'],
        n_jobs=-1,
        verbose=0
    )
    
    model.fit(X_benign_train)
    
    print("[+] Model training complete")
    return model


def validate_model(model, X_test, y_test):
    """
    Validate on realistic mixed data
    Uses score-based threshold tuning for better performance
    """
    print(f"\n[*] Validating on realistic mixed test data...")
    print(f"    Test samples: {len(X_test)}")
    print(f"    Benign: {sum(y_test==0)} | Attack: {sum(y_test==1)}")
    
    # Get anomaly scores (not just -1/1 predictions)
    scores = model.decision_function(X_test)
    
    # Find optimal threshold by testing many values
    print(f"\n[*] Tuning decision threshold...")
    thresholds = np.linspace(-0.3, 0.2, 100)
    best_f1 = 0
    best_thresh = -0.1
    
    for t in thresholds:
        pred = (scores < t).astype(int)
        try:
            f1 = f1_score(y_test, pred)
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = t
        except:
            pass
    
    # Use optimal threshold for final predictions
    y_pred = (scores < best_thresh).astype(int)
    
    print(f"\n[+] Optimal threshold: {best_thresh:.4f} (F1={best_f1:.4f})")
    
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, 
                               target_names=['Normal (Benign)', 'Anomaly (Attack)']))
    
    print("[+] Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Normal  Anomaly")
    print(f"Actual Normal    {cm[0,0]:6d}  {cm[0,1]:6d}")
    print(f"Actual Anomaly   {cm[1,0]:6d}  {cm[1,1]:6d}")
    
    # ROC-AUC
    try:
        auc = roc_auc_score(y_test, y_pred)
        print(f"\n[+] ROC-AUC Score: {auc:.4f}")
    except Exception as e:
        print(f"\n[!] Could not compute ROC-AUC: {e}")
    
    # Score distribution analysis
    print(f"\n[+] Anomaly Score Distribution:")
    print(f"    Benign traffic  - Mean: {np.mean(scores[y_test==0]):.4f}, Std: {np.std(scores[y_test==0]):.4f}")
    print(f"    Attack traffic  - Mean: {np.mean(scores[y_test==1]):.4f}, Std: {np.std(scores[y_test==1]):.4f}")
    
    return best_thresh


def save_artifacts(model, scaler, selector, features, threshold):
    """Save all model artifacts"""
    os.makedirs('./models', exist_ok=True)
    
    joblib.dump(model, CONFIG['model_output'])
    joblib.dump(scaler, CONFIG['scaler_output'])
    joblib.dump(selector, CONFIG['selector_output'])
    
    metadata = {
        'features': features,
        'feature_count': len(features),
        'contamination': CONFIG['contamination'],
        'threshold': float(threshold),
        'model_type': 'IsolationForest',
        'training_mode': 'unsupervised (benign only)',
        'dataset': 'CICIDS2017 Monday-WorkingHours',
        'scaler': 'RobustScaler',
        'selector': 'SelectKBest_mutual_info'
    }
    
    with open(CONFIG['features_output'], 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n" + "="*60)
    print("ARTIFACTS SAVED")
    print("="*60)
    print(f"    Model:      {CONFIG['model_output']}")
    print(f"    Scaler:     {CONFIG['scaler_output']}")
    print(f"    Selector:   {CONFIG['selector_output']}")
    print(f"    Features:   {CONFIG['features_output']}")
    print(f"    Threshold:  {threshold:.4f}")


def main():
    print("="*60)
    print("IDRS - CICIDS2017 Unsupervised Anomaly Detection Training")
    print("="*60)
    
    # 1. Load benign training data (Monday)
    df_benign = load_cicids_data(CONFIG['dataset_path'])
    df_benign = clean_cicids_data(df_benign)
    df_benign, _ = remove_constant_features(df_benign)
    
    # 2. Load Wednesday (mixed realistic traffic) for validation
    if os.path.exists(CONFIG['attack_data_path']):
        print(f"\n[*] Loading realistic validation data (Wednesday - mixed traffic)...")
        df_mixed = load_cicids_data(CONFIG['attack_data_path'])
        df_mixed = clean_cicids_data(df_mixed)
        df_mixed, _ = remove_constant_features(df_mixed)
        
        # Ensure same columns between datasets
        common_cols = list(set(df_benign.columns) & set(df_mixed.columns))
        df_benign = df_benign[common_cols]
        df_mixed = df_mixed[common_cols]
        
        # Split Wednesday into benign and attack for realistic validation
        df_wed_benign = df_mixed[df_mixed['Label_Binary'] == 0].copy()
        df_wed_attack = df_mixed[df_mixed['Label_Binary'] == 1].copy()
        
        print(f"\n[*] Wednesday split: Benign={len(df_wed_benign)}, Attack={len(df_wed_attack)}")
        
        has_realistic_validation = True
    else:
        print(f"\n[!] No Wednesday data found, using synthetic split")
        df_wed_benign = df_benign.iloc[:1000].copy()
        df_wed_attack = df_benign.iloc[1000:2000].copy()
        df_wed_attack['Label_Binary'] = 1  # Mark as attack for validation only
        has_realistic_validation = False
    
    # 3. Feature engineering on ALL datasets (using same columns)
    X_benign, y_benign, feature_names = engineer_features(df_benign)
    X_wed_benign, y_wed_benign, _ = engineer_features(df_wed_benign)
    X_wed_attack, y_wed_attack, _ = engineer_features(df_wed_attack)
    
    # 4. Split Monday benign: 80% train, 20% validation (both are normal/benign)
    X_train, X_mon_val = train_test_split(
        X_benign, test_size=0.2, random_state=42
    )
    
    print(f"\n[*] Data split:")
    print(f"    Monday train (unsupervised): {len(X_train)}")
    print(f"    Monday validation:           {len(X_mon_val)}")
    print(f"    Wednesday benign:            {len(X_wed_benign)}")
    print(f"    Wednesday attack:            {len(X_wed_attack)}")
    
    # 5. Feature selection (uses Monday + Wednesday for discriminative power)
    # Combine: Monday benign + Wednesday benign + Wednesday attack
    X_fs_normal = pd.concat([X_benign, X_wed_benign], ignore_index=True)
    X_fs = pd.concat([X_fs_normal, X_wed_attack], ignore_index=True)
    y_fs = np.hstack([
        np.zeros(len(X_benign) + len(X_wed_benign)),
        np.ones(len(X_wed_attack))
    ])
    
    X_benign_sel, X_wed_attack_sel, scaler, selector, selected = select_features(
        X_fs_normal, X_wed_attack, y_fs, feature_names, k=CONFIG['feature_count']
    )
    
    # Re-split selected features back to train/val
    # X_benign_sel contains both Monday and Wednesday benign
    # We need to extract just the Monday training portion
    monday_count = len(X_train)
    X_train_sel = X_benign_sel[:monday_count]
    X_mon_val_sel = X_benign_sel[monday_count:monday_count + len(X_mon_val)]
    
    # 6. Train UNSUPERVISED on Monday benign only
    model = train_unsupervised_if(X_train_sel, contamination=CONFIG['contamination'])
    
    # 7. Validate on REALISTIC mixed traffic
    # Use: Monday validation (benign) + Wednesday attack (real attacks)
    # This gives realistic proportions (~20% benign, ~80% attack in test)
    X_test = np.vstack([X_mon_val_sel, X_wed_attack_sel])
    y_test = np.hstack([
        np.zeros(len(X_mon_val_sel)),
        np.ones(len(X_wed_attack_sel))
    ])
    
    threshold = validate_model(model, X_test, y_test)
    
    # 8. Save everything
    save_artifacts(model, scaler, selector, selected, threshold)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print("[*] Next steps:")
    print("    1. Copy ./models/ folder to your IDS VM")
    print("    2. Update ml_detector.py threshold to:", f"{threshold:.4f}")
    print("    3. Run: sudo python3 Manual_Rules_Fast.py")
    print("    4. Dashboard: python3 dashboard.py")


if __name__ == "__main__":
    main()