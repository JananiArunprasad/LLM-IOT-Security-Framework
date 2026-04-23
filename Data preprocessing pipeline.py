import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# ─────────────────────────────────────────
# STEP 1: Load the dataset
# ─────────────────────────────────────────
# Replace the filename with your actual downloaded file name
df = pd.read_csv("C:\LLM IN SECURITY PROJECT")

print("Original shape:", df.shape)
print("\nFirst 3 rows:")
print(df.head(3))

# ─────────────────────────────────────────
# STEP 2: Keep only the 17 columns we need
# ─────────────────────────────────────────
cols_to_keep = [
    "src_ip", "src_port", "dst_ip", "dst_port",  # for dashboard + LLM
    "proto", "service", "conn_state",              # categorical features
    "duration", "src_bytes", "dst_bytes",          # numerical features
    "missed_bytes", "src_pkts", "src_ip_bytes",
    "dst_pkts", "dst_ip_bytes",
    "label", "type"                                # target labels
]

df = df[cols_to_keep]
print("\nAfter column selection:", df.shape)


# ─────────────────────────────────────────
# STEP 3: Handle missing values
# ─────────────────────────────────────────
print("\nMissing values per column:")
print(df.isnull().sum())

# Fill missing numerical values with 0
num_cols = ["duration", "src_bytes", "dst_bytes", "missed_bytes",
            "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes"]
df[num_cols] = df[num_cols].fillna(0)

# Fill missing categorical values with "unknown"
cat_cols = ["proto", "service", "conn_state"]
df[cat_cols] = df[cat_cols].fillna("unknown")

print("\nMissing values after cleaning:")
print(df.isnull().sum())


# ─────────────────────────────────────────
# STEP 4: Check label distribution
# ─────────────────────────────────────────
print("\nLabel distribution (0=benign, 1=attack):")
print(df["label"].value_counts())

print("\nAttack type distribution:")
print(df["type"].value_counts())


# ─────────────────────────────────────────
# STEP 5: Encode categorical columns
# (ML models need numbers, not text)
# ─────────────────────────────────────────
le = LabelEncoder()

df["proto_enc"]     = le.fit_transform(df["proto"])
df["service_enc"]   = le.fit_transform(df["service"])
df["conn_state_enc"]= le.fit_transform(df["conn_state"])

print("\nSample encoded values:")
print(df[["proto", "proto_enc", "service", "service_enc"]].head(5))


# ─────────────────────────────────────────
# STEP 6: Build the final feature set for
# Isolation Forest (numbers only)
# ─────────────────────────────────────────
feature_cols = [
    "proto_enc", "service_enc", "conn_state_enc",
    "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes",
    "dst_pkts", "dst_ip_bytes"
]

X = df[feature_cols]   # features (input to model)
y = df["label"]        # binary label (0 or 1)

print("\nFeature matrix shape:", X.shape)
print("Label shape:", y.shape)


# ─────────────────────────────────────────
# STEP 7: Scale the features
# (makes all numbers on the same scale)
# ─────────────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("\nScaling complete. Sample scaled values:")
print(X_scaled[:3])


# ─────────────────────────────────────────
# STEP 8: Train / test split
# ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTrain size:", X_train.shape)
print("Test size:", X_test.shape)


# ─────────────────────────────────────────
# STEP 9: Save the cleaned dataset
# ─────────────────────────────────────────
df.to_csv("ton_iot_cleaned.csv", index=False)
print("\nCleaned dataset saved as ton_iot_cleaned.csv")
print("Preprocessing complete — ready for Isolation Forest!")