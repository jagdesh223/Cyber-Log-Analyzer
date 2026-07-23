from sklearn.ensemble import IsolationForest
import numpy as np


def detect_anomalies(logs):

    features = []


    for log in logs:

        failed = 1 if log["status"] == "FAILED" else 0

        username_length = len(
            log["username"]
        )


        features.append(
            [
                failed,
                username_length
            ]
        )


    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )


    predictions = model.fit_predict(
        np.array(features)
    )


    results = []


    for log, prediction in zip(logs, predictions):

        results.append({

            "ip": log["ip"],

            "username": log["username"],

            "status": log["status"],

            "anomaly":
                "Suspicious"
                if prediction == -1
                else "Normal"

        })


    return results
