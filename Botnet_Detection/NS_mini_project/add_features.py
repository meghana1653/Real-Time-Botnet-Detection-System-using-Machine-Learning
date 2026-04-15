# -*- coding: utf-8 -*-
"""
Created on Mon Apr 13 22:44:00 2026

@author: ranil
"""

import pandas as pd

# Load dataset
df = pd.read_csv("final_dataset.csv")

# Add new feature
df["is_fast"] = (df["time_diff"] < 0.01).astype(int)
df["is_large_packet"] = (df["packet_size"] > 200).astype(int)
df["burst"] = (df["time_diff"] < 0.005).astype(int)

# Save updated dataset
df.to_csv("enhanced_dataset.csv", index=False)

print("Feature added! New dataset saved.")