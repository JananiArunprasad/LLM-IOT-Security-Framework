import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, precision_score,
                             recall_score, f1_score)
import os

# ─────────────────────────────────────────
# SET YOUR PROJECT FOLDER PATH HERE
# ─────────────────────────────────────────
os.chdir(r"C:\Users\madha\OneDrive\LLM IN SECURITY PROJECT")  # ← change this to your actual folder
print("Working directory:", os.getcwd())

# ─────────────────────────────────────────
# STEP 1: Load cleaned dataset
# ─────────────────────────────────────────
df = pd.read_csv("ton_iot_cleaned.csv")
print("Loaded cleaned dataset:", df.shape)

# ─────────────────────────────────────────
# STEP 2: Encode and scale
# ─────────────────────────────────────────
le_proto      = LabelEncoder()
le_service    = LabelEncoder()
le_conn_state = LabelEncoder()

df["proto_enc"]      = le_proto.fit_transform(df["proto"])
df["service_enc"]    = le_service.fit_transform(df["service"])
df["conn_state_enc"] = le_conn_state.fit_transform(df["conn_state"])

feature_cols = [
    "proto_enc", "service_enc", "conn_state_enc",
    "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes",
    "dst_pkts", "dst_ip_bytes"
]

X = df[feature_cols].copy()
y = df["label"]   # 0 = benign, 1 = attack

# Log-transform skewed byte columns to reduce impact of extreme values
byte_cols = ["src_bytes", "dst_bytes", "src_ip_bytes",
             "dst_ip_bytes", "missed_bytes"]
for col in byte_cols:
    X[col] = np.log1p(X[col])   # log1p handles zero values safely

print("Log transformation applied to byte columns.")

# ─────────────────────────────────────────
# STEP 3: Split BEFORE training
# ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Scale AFTER splitting to prevent data leakage
scaler  = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)       # use same scaler, don't refit

print("Train size:", X_train_scaled.shape)
print("Test size :", X_test_scaled.shape)

# ─────────────────────────────────────────
# STEP 4: Train ONLY on benign traffic
# This is the correct approach —
# the model learns what "normal" looks like
# then flags anything that deviates
# ─────────────────────────────────────────
benign_mask    = y_train == 0
X_train_benign = X_train_scaled[benign_mask]
print(f"\nTraining on {len(X_train_benign)} benign-only rows...")

iso_forest = IsolationForest(
    n_estimators=200,      # more trees = more stable results
    contamination=0.1,     # expect ~10% anomalies
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X_train_benign)
print("Training complete!")

# ─────────────────────────────────────────
# STEP 5: Predict on test set
# -1 = anomaly (attack), 1 = normal (benign)
# Convert to 1/0 to match our labels
# ─────────────────────────────────────────
raw_preds = iso_forest.predict(X_test_scaled)
y_pred    = np.where(raw_preds == -1, 1, 0)

anomaly_scores         = iso_forest.decision_function(X_test_scaled)
anomaly_scores_flipped = -anomaly_scores   # higher = more suspicious

print("\nSample predictions (1=attack, 0=benign):")
print(y_pred[:10])
print("Actual labels:")
print(np.array(y_test[:10]))

# ─────────────────────────────────────────
# STEP 6: Evaluate
# ─────────────────────────────────────────
print("\n" + "="*50)
print("        MODEL EVALUATION REPORT")
print("="*50)

acc       = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall    = recall_score(y_test, y_pred, zero_division=0)
f1        = f1_score(y_test, y_pred, zero_division=0)

cm              = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP  = cm.ravel()
far             = FP / (FP + TN) if (FP + TN) > 0 else 0

print(f"Accuracy          : {acc:.4f}  ({acc*100:.2f}%)")
print(f"Precision         : {precision:.4f}")
print(f"Recall            : {recall:.4f}")
print(f"F1 Score          : {f1:.4f}")
print(f"False Alarm Rate  : {far:.4f}  ({far*100:.2f}%)")

print("\nConfusion Matrix:")
print(f"  True Negatives  (TN): {TN}  — correctly identified benign")
print(f"  False Positives (FP): {FP}  — benign flagged as attack")
print(f"  False Negatives (FN): {FN}  — attacks missed")
print(f"  True Positives  (TP): {TP}  — correctly identified attacks")

print("\nDetailed Classification Report:")
print(classification_report(y_test, y_pred,
      target_names=["Benign", "Attack"]))

# ─────────────────────────────────────────
# STEP 7: Save flagged anomalies for LLM
# ─────────────────────────────────────────
test_indices = y_test.index
df_test      = df.loc[test_indices].copy()
df_test["anomaly_score"] = np.round(anomaly_scores_flipped, 4)
df_test["prediction"]    = y_pred

flagged = df_test[df_test["prediction"] == 1][[
    "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "service", "conn_state",
    "src_bytes", "dst_bytes", "duration",
    "anomaly_score", "label", "type"
]].sort_values("anomaly_score", ascending=False)

flagged.to_csv("flagged_anomalies.csv", index=False)

print(f"\nFlagged {len(flagged)} suspicious rows")
print("Saved to flagged_anomalies.csv — ready for LLM in Module 3!")
print("\nTop 5 most suspicious devices:")
print(flagged.head())