"""
SecureDownload AI — ML Model Training
======================================
Trains a Random Forest classifier to detect malicious files.

Features used:
  - file_size   : size of file in bytes
  - entropy     : Shannon entropy (0–8); high = packed/encrypted
  - ext_risk    : extension risk level (0=safe, 1=medium, 2=high)

Run this script once to generate model.pkl:
    cd SecureDownloadAI/ml_model
    python train_model.py

The model is then loaded by the backend service (services/ml_service.py).
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from pathlib import Path


def generate_dataset(n_samples: int = 5000, seed: int = 42):
    """
    Generate a synthetic labeled dataset mimicking real file properties.

    In a real project, replace this with:
      - EMBER dataset (https://github.com/elastic/ember)
      - MalwareBazaar exports
      - VirusShare samples

    Label: 0 = SAFE, 1 = MALICIOUS
    """
    rng = np.random.RandomState(seed)
    features, labels = [], []

    # Safe files (label = 0)
    for _ in range(n_samples // 2):
        file_size = rng.randint(10_000, 100_000_000)
        entropy   = rng.uniform(3.0, 6.5)
        ext_risk  = rng.choice([0, 1], p=[0.9, 0.1])
        features.append([file_size, entropy, ext_risk])
        labels.append(0)

    # Malicious files (label = 1)
    for _ in range(n_samples // 2):
        file_size = rng.randint(1_000, 5_000_000)
        entropy   = rng.uniform(6.8, 8.0)
        ext_risk  = rng.choice([1, 2], p=[0.3, 0.7])
        features.append([file_size, entropy, ext_risk])
        labels.append(1)

    return np.array(features), np.array(labels)


def train():
    print("🔧 Generating synthetic dataset…")
    X, y = generate_dataset(n_samples=10_000)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"   Train samples : {len(X_train)}")
    print(f"   Test  samples : {len(X_test)}")

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print("\n🚀 Training Random Forest…")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

    print("🔢 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"   True Negative  (safe      → safe)      : {cm[0][0]}")
    print(f"   False Positive (safe      → malicious) : {cm[0][1]}")
    print(f"   False Negative (malicious → safe)      : {cm[1][0]}")
    print(f"   True Positive  (malicious → malicious) : {cm[1][1]}")

    print("\n📈 Feature Importances:")
    names = ["file_size", "entropy", "ext_risk"]
    for name, imp in zip(names, clf.feature_importances_):
        bar = "█" * int(imp * 40)
        print(f"   {name:<12} {bar} {imp:.4f}")

    output_path = Path(__file__).parent / "model.pkl"
    with open(output_path, "wb") as f:
        pickle.dump(clf, f)
    print(f"\n✅ Model saved to {output_path}")

    return clf


if __name__ == "__main__":
    train()
