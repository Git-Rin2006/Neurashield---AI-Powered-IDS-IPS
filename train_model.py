#!/usr/bin/env python3
"""
NeuraShield - NSL-KDD Model Training Pipeline
Downloads NSL-KDD dataset, preprocesses, trains a Random Forest classifier,
and saves the model + preprocessing artifacts for production inference.

Usage:
    python3 train_model.py

Output:
    models/nids_rf_model.joblib       - Trained Random Forest model
    models/scaler.joblib              - Fitted StandardScaler
    models/label_encoders.joblib      - Fitted LabelEncoders for categorical features
    models/feature_columns.joblib     - Column names for inference mapping
"""

from __future__ import annotations

import os
import sys
import urllib.request
import time

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix


# ============================================================
# CONFIGURATION
# ============================================================

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

# NSL-KDD dataset URLs (public mirrors)
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"

TRAIN_FILE = os.path.join(MODELS_DIR, "KDDTrain+.txt")
TEST_FILE = os.path.join(MODELS_DIR, "KDDTest+.txt")

# NSL-KDD official 41 feature names + label + difficulty
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level"
]

# Categorical features that need label encoding
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# Attack type mapping to categories
ATTACK_CATEGORIES = {
    "normal": "BENIGN",
    # DoS attacks
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS",
    "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    # Probe attacks
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L attacks
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L",
    "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    # U2R attacks
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "httptunnel": "U2R", "ps": "U2R",
    "sqlattack": "U2R", "xterm": "U2R",
}


# ============================================================
# DOWNLOAD
# ============================================================

def download_dataset():
    """Download NSL-KDD dataset if not present."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    for url, filepath, name in [
        (TRAIN_URL, TRAIN_FILE, "KDDTrain+"),
        (TEST_URL, TEST_FILE, "KDDTest+"),
    ]:
        if os.path.exists(filepath):
            print(f"  [✓] {name} already exists ({os.path.getsize(filepath):,} bytes)")
            continue

        print(f"  [↓] Downloading {name}...")
        try:
            urllib.request.urlretrieve(url, filepath)
            print(f"  [✓] {name} downloaded ({os.path.getsize(filepath):,} bytes)")
        except Exception as exc:
            print(f"  [✗] Failed to download {name}: {exc}")
            sys.exit(1)


# ============================================================
# PREPROCESS
# ============================================================

def load_and_preprocess(filepath: str) -> pd.DataFrame:
    """Load NSL-KDD CSV and preprocess."""
    df = pd.read_csv(filepath, names=COLUMN_NAMES, header=None)

    # Drop difficulty_level column (not a feature)
    df.drop("difficulty_level", axis=1, inplace=True)

    # Map attack labels to categories
    df["attack_category"] = df["label"].apply(
        lambda x: ATTACK_CATEGORIES.get(x.strip().lower(), "Unknown")
    )

    # Binary classification: BENIGN (0) vs ATTACK (1)
    df["is_attack"] = (df["attack_category"] != "BENIGN").astype(int)

    return df


def encode_and_scale(
    df_train: pd.DataFrame,
    df_test: pd.DataFrame,
):
    """Encode categoricals, scale numerics, return X/y arrays and fitted transforms."""

    # Fit label encoders on COMBINED data to cover all possible values
    label_encoders = {}
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        combined = pd.concat([df_train[col], df_test[col]], axis=0)
        le.fit(combined.astype(str))
        df_train[col] = le.transform(df_train[col].astype(str))
        df_test[col] = le.transform(df_test[col].astype(str))
        label_encoders[col] = le

    # Feature columns (all numeric now)
    feature_cols = [c for c in df_train.columns
                    if c not in ("label", "attack_category", "is_attack")]

    X_train = df_train[feature_cols].values.astype(np.float64)
    X_test = df_test[feature_cols].values.astype(np.float64)
    y_train = df_train["is_attack"].values
    y_test = df_test["is_attack"].values

    # Handle any NaN/inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, scaler, label_encoders, feature_cols


# ============================================================
# TRAIN
# ============================================================

def train_model(X_train, y_train):
    """Train Random Forest classifier."""
    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        n_jobs=-1,            # Use all CPU cores
        random_state=42,
        class_weight="balanced",  # Handle class imbalance
    )

    print("  [⟳] Training Random Forest (120 trees)...")
    start = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - start
    print(f"  [✓] Training completed in {elapsed:.1f}s")

    return model


# ============================================================
# EVALUATE
# ============================================================

def evaluate_model(model, X_test, y_test):
    """Evaluate and print metrics."""
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    print()

    print("  Classification Report:")
    report = classification_report(
        y_test, y_pred,
        target_names=["BENIGN", "ATTACK"],
        digits=4
    )
    for line in report.split("\n"):
        print(f"    {line}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"\n  Confusion Matrix:")
    print(f"    True Neg (Normal→Normal):   {cm[0][0]:>6}")
    print(f"    False Pos (Normal→Attack):  {cm[0][1]:>6}")
    print(f"    False Neg (Attack→Normal):  {cm[1][0]:>6}")
    print(f"    True Pos (Attack→Attack):   {cm[1][1]:>6}")

    return acc


# ============================================================
# SAVE
# ============================================================

def save_artifacts(model, scaler, label_encoders, feature_cols):
    """Save all model artifacts for production use."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    artifacts = {
        "nids_rf_model.joblib": model,
        "scaler.joblib": scaler,
        "label_encoders.joblib": label_encoders,
        "feature_columns.joblib": feature_cols,
    }

    for name, obj in artifacts.items():
        path = os.path.join(MODELS_DIR, name)
        joblib.dump(obj, path)
        size = os.path.getsize(path)
        print(f"  [✓] Saved {name} ({size:,} bytes)")


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 60)
    print("  NeuraShield — ML Model Training Pipeline")
    print("  Random Forest Classifier on NSL-KDD Dataset")
    print("=" * 60)
    print()

    # Step 1: Download
    print("[1/5] Downloading NSL-KDD dataset...")
    download_dataset()
    print()

    # Step 2: Preprocess
    print("[2/5] Preprocessing data...")
    df_train = load_and_preprocess(TRAIN_FILE)
    df_test = load_and_preprocess(TEST_FILE)
    print(f"  [✓] Train samples: {len(df_train):,}")
    print(f"  [✓] Test samples:  {len(df_test):,}")
    print(f"  [✓] Attack types in train: {df_train['attack_category'].nunique()}")
    print(f"  [✓] Attack ratio: {df_train['is_attack'].mean():.2%}")
    print()

    # Step 3: Encode & Scale
    print("[3/5] Encoding categoricals & scaling features...")
    X_train, X_test, y_train, y_test, scaler, label_encoders, feature_cols = \
        encode_and_scale(df_train, df_test)
    print(f"  [✓] Feature vector size: {X_train.shape[1]}")
    print()

    # Step 4: Train
    print("[4/5] Training model...")
    model = train_model(X_train, y_train)
    print()

    # Step 5: Evaluate
    print("[5/5] Evaluating model...")
    accuracy = evaluate_model(model, X_test, y_test)
    print()

    # Save
    print("Saving model artifacts...")
    save_artifacts(model, scaler, label_encoders, feature_cols)
    print()

    print("=" * 60)
    print(f"  ✅ Model trained successfully! Accuracy: {accuracy:.2%}")
    print(f"  📁 Artifacts saved to: {MODELS_DIR}/")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
