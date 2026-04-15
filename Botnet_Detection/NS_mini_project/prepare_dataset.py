# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 20:34:17 2026

@author: ranil
"""

import pandas as pd

# Load datasets
normal = pd.read_csv("network_data.csv")
attack = pd.read_csv("attack_data.csv")

# Add labels
normal["label"] = 0
attack["label"] = 1

# Combine
df = pd.concat([normal, attack])

# Save final dataset
df.to_csv("final_dataset.csv", index=False)

print("Final dataset created!")