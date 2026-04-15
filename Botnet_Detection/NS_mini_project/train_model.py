# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 20:55:18 2026

@author: ranil
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import pickle

# Load dataset
df = pd.read_csv("flow_dataset.csv")

print(df["label"].value_counts())

# Drop non-ML columns
df = df.drop(columns=["src_ip", "dst_ip"], errors="ignore")

# -------------------------
# ✅ BALANCE DATA FIRST
# -------------------------
from sklearn.utils import resample

df_class0 = df[df['label'] == 0]
df_class1 = df[df['label'] == 1]

if len(df_class0) > len(df_class1):
    df_majority = df_class0
    df_minority = df_class1
else:
    df_majority = df_class1
    df_minority = df_class0

print("Majority:", len(df_majority))
print("Minority:", len(df_minority))

if len(df_minority) == 0:
    print("❌ One class missing!")
    exit()

# Downsample majority
df_majority_downsampled = resample(
    df_majority,
    replace=False,
    n_samples=len(df_minority),
    random_state=42
)

df = pd.concat([df_majority_downsampled, df_minority])

# -------------------------
# ✅ NOW CREATE FEATURES
# -------------------------
X = df[[
    "packet_count",
    "avg_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "flow_duration",
    "avg_time_diff",
    "packet_rate",
    "burst_rate",
    "size_variation",
    "max_time_diff",
    "min_time_diff",
    "time_variation",
    "idle_time"
]]

y = df["label"]

# -------------------------
# Train-Test Split
# -------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


# Model
model = RandomForestClassifier(
    n_estimators=400,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=4,
    class_weight="balanced_subsample",
    random_state=42
)

# Train
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model
pickle.dump(model, open("model.pkl", "wb"))

print("Dataset size:", len(df))

print("\nModel saved as model.pkl")