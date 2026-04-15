# -*- coding: utf-8 -*-
"""
Created on Wed Apr  8 19:27:14 2026

@author: ranil
"""

from fastapi import FastAPI
import pickle
import numpy as np

app = FastAPI()

# Load model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

@app.get("/")
def home():
    return {"message": "Botnet Detection API is running"}

@app.post("/predict")
def predict(flow_duration: int, src_bytes: int, dst_bytes: int):
    try:
        features = np.array([[flow_duration, src_bytes, dst_bytes]])
        prediction = model.predict(features)[0]

        if prediction == 1:
            result = {
                "prediction": "Botnet",
                "risk": "High",
                "alert": "⚠️ Suspicious activity detected"
            }

            # log alert
            with open("alerts.log", "a") as f:
                f.write("Botnet detected\n")

        else:
            result = {
                "prediction": "Normal",
                "risk": "Low"
            }

        return result

    except Exception as e:
        return {"error": str(e)}