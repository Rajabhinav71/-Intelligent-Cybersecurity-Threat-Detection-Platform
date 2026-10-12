"""
SentinelModel — wraps scikit-learn's Isolation Forest.

How Isolation Forest works (simple explanation):
  - It randomly splits the data to "isolate" each point
  - Normal points need MANY splits to isolate (they're surrounded by others)
  - Anomalies need FEW splits (they're far from the cluster)
  - So: low path length = anomaly

Features we use (must match what Spring Boot sends):
  [0] failed_logins  — failed login count in last 5 min (normal: 0-1)
  [1] request_rate   — requests per minute (normal: 1-30)
  [2] hour_of_day    — 0-23 (normal logins: 8-22)
  [3] login_success  — 0 or 1 (normal: mostly 1)
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler


class SentinelModel:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,       # 100 decision trees
            contamination=0.05,     # assume 5% of traffic is malicious
            random_state=42
        )
        self.scaler = MinMaxScaler()
        self.is_trained = False

    def train(self):
        """
        Train on synthetic "normal" behaviour data.
        In production you'd use real logs from your DB,
        but for the hackathon this is enough to get real scores.
        """
        np.random.seed(42)
        n = 500  # 500 samples of normal behaviour

        # Normal behaviour patterns:
        #   failed_logins:  mostly 0, occasionally 1
        #   request_rate:   1–30 req/min
        #   hour_of_day:    mostly business hours (8–22)
        #   login_success:  mostly 1 (successful)
        normal_data = np.column_stack([
            np.random.choice([0, 1], n, p=[0.85, 0.15]),   # failed_logins
            np.random.randint(1, 30, n),                     # request_rate
            np.random.randint(8, 22, n),                     # hour_of_day
            np.random.choice([0, 1], n, p=[0.1, 0.9]),      # login_success
        ]).astype(float)

        # Scale features to 0-1 range
        self.scaler.fit(normal_data)
        scaled = self.scaler.transform(normal_data)

        # Train the model
        self.model.fit(scaled)
        self.is_trained = True
        print(f"[SentinelML] Model trained on {n} normal behaviour samples.")

    def predict(self, features: list) -> tuple[int, bool]:
        """
        features: [failed_logins, request_rate, hour_of_day, login_success]
        returns:  (anomaly_score 0-100, is_anomaly bool)
        """
        if not self.is_trained:
            return 0, False

        x = np.array(features, dtype=float).reshape(1, -1)
        x_scaled = self.scaler.transform(x)

        # IsolationForest returns:
        #   1  = normal
        #  -1  = anomaly
        prediction = self.model.predict(x_scaled)[0]

        # decision_function gives raw score:
        #   negative = anomaly (further from normal)
        #   positive = normal
        raw_score = self.model.decision_function(x_scaled)[0]

        # Convert to 0-100 scale:
        # raw_score is roughly in range [-0.5, 0.5]
        # We invert and scale so higher = more suspicious
        anomaly_score = int(max(0, min(100, (-raw_score + 0.3) * 200)))

        is_anomaly = prediction == -1

        return anomaly_score, is_anomaly
