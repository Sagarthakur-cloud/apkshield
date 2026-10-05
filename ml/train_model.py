"""
Train XGBoost on CICMalDroid 2020 real static features.
"""
import pandas as pd
import numpy as np
import joblib
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder


def main():
    print("=" * 60)
    print("APKShield — XGBoost Training (Real CICMalDroid 2020)")
    print("=" * 60)

    # ⚠️ UPDATED PATH — real dataset
    data_path = "ml/data/CICMalDroid_2020_static.csv"

    if not os.path.exists(data_path):
        print(f"\n✗ Dataset not found: {data_path}")
        print(f"  Current folder: {os.getcwd()}")
        print(f"  Available files in ml/data/:")
        if os.path.exists("ml/data"):
            for f in os.listdir("ml/data"):
                print(f"    - {f}")
        return

    # ── Load ──
    print(f"\n[1/6] Loading {data_path}...")
    df = pd.read_csv(data_path, low_memory=False)
    print(f"      Shape: {df.shape}")
    print(f"      Columns: {len(df.columns)}")

    # ── Label column ──
    print(f"\n[2/6] Detecting label column...")
    label_col = "Class"

    if label_col not in df.columns:
        for c in ["class", "Label", "label", "Category", "category"]:
            if c in df.columns:
                label_col = c
                break
        else:
            label_col = df.columns[-1]

    print(f"      Label column: {label_col}")
    print(f"      Unique values: {list(df[label_col].unique())}")

    # ── Prepare X and y ──
    print(f"\n[3/6] Preparing data...")

    drop_cols = [label_col]
    for c in ["sha256", "SHA256", "hash", "Hash", "md5", "MD5"]:
        if c in df.columns:
            drop_cols.append(c)

    X = df.drop(columns=drop_cols)
    y = df[label_col]

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    print(f"      Features: {X.shape[1]}")
    print(f"      Samples:  {X.shape[0]}")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y.astype(str))
    print(f"      Classes: {list(le.classes_)}")

    # ── Split ──
    print(f"\n[4/6] Splitting...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    print(f"      Training: {len(X_train)}")
    print(f"      Testing:  {len(X_test)}")

    # ── Train ──
    print(f"\n[5/6] Training XGBoost on {X.shape[1]} features...")
    print(f"      This may take 2-5 minutes...")

    n_classes = len(le.classes_)

    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        objective="multi:softprob" if n_classes > 2 else "binary:logistic",
        num_class=n_classes if n_classes > 2 else None,
        eval_metric="mlogloss" if n_classes > 2 else "logloss",
        use_label_encoder=False,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
    )

    model.fit(X_train, y_train)
    print("      ✓ Training complete")

    # ── Evaluate ──
    print(f"\n[6/6] Evaluating...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n{'=' * 60}")
    print(f"  ACCURACY: {acc * 100:.2f}%")
    print(f"{'=' * 60}\n")

    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # ── Save ──
    print(f"\nSaving model...")
    os.makedirs("ml", exist_ok=True)
    joblib.dump(model, "ml/ml_model.pkl")
    joblib.dump(list(X.columns), "ml/feature_columns.pkl")
    joblib.dump(le, "ml/label_encoder.pkl")

    print(f"      ✓ ml/ml_model.pkl")
    print(f"      ✓ ml/feature_columns.pkl")
    print(f"      ✓ ml/label_encoder.pkl")

    print(f"\n{'=' * 60}")
    print("✓ TRAINING COMPLETE — Real Data")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()