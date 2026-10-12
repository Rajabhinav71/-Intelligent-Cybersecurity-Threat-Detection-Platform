"""
SentinelX ML Microservice
─────────────────────────
Runs as a separate Python process on port 5000.
Spring Boot calls POST /predict with user behaviour features.
Returns an anomaly score 0-100 (higher = more suspicious).

Uses scikit-learn's Isolation Forest:
  - Trained on "normal" login behaviour
  - Anything that deviates from normal gets a high score
  - No labelled attack data needed (unsupervised learning)
"""

from flask import Flask, request, jsonify
from model import SentinelModel
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sentinelx-ml")

app = Flask(__name__)

# Load / train model on startup
model = SentinelModel()
model.train()
log.info("SentinelX ML model trained and ready.")


@app.route("/predict", methods=["POST"])
def predict():
    """
    Expects JSON body:
    {
      "failed_logins": 3,
      "request_rate": 45,
      "hour_of_day": 2,
      "login_success": 0
    }
    Returns:
    {
      "anomaly_score": 78,
      "is_anomaly": true
    }
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        features = [
            data.get("failed_logins", 0),
            data.get("request_rate", 0),
            data.get("hour_of_day", 12),
            data.get("login_success", 1),
        ]

        score, is_anomaly = model.predict(features)
        log.info(f"Prediction: features={features} score={score} anomaly={is_anomaly}")

        return jsonify({
            "anomaly_score": score,
            "is_anomaly": is_anomaly
        })

    except Exception as e:
        log.error(f"Prediction error: {e}")
        return jsonify({"error": str(e), "anomaly_score": 0}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": "IsolationForest"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
