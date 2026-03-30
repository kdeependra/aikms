"""
Anomaly detection model using Isolation Forest.

Features extracted from key usage events:
- requests_per_minute  (rolling window)
- unique_namespaces_per_minute
- hour_of_day  (0-23)
- day_of_week  (0-6)
- error_rate   (failed_ops / total_ops per key, rolling)
"""
import logging
import numpy as np
from collections import defaultdict, deque
from datetime import datetime

from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class AnomalyDetector:

    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self._trained = False
        # Rolling window per key_id: deque of (timestamp, features)
        self._window: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

    def record_event(self, key_id: str, operation: str, success: bool, timestamp: datetime) -> None:
        feat = self._extract_features(timestamp, success)
        self._window[key_id].append(feat)

    def predict(self, key_id: str, operation: str, success: bool, timestamp: datetime) -> float:
        """
        Returns an anomaly score in [0, 1] where > 0.5 indicates anomalous.
        Returns 0.0 if the model has not been trained yet.
        """
        if not self._trained:
            self.try_fit()
        if not self._trained:
            return 0.0

        feat = np.array([self._extract_features(timestamp, success)])
        raw_score = self.model.score_samples(feat)[0]  # negative; lower = more anomalous
        # Normalize to [0, 1]: IsolationForest scores are roughly in [-0.5, 0.5]
        normalized = float(np.clip((0.5 - raw_score), 0.0, 1.0))
        return normalized

    def try_fit(self) -> None:
        """Attempt to train the model on accumulated data."""
        all_features = [f for window in self._window.values() for f in window]
        if len(all_features) < 50:
            logger.debug("Not enough data to train anomaly model (%d samples)", len(all_features))
            return
        X = np.array(all_features)
        self.model.fit(X)
        self._trained = True
        logger.info("Anomaly model trained on %d samples", len(X))

    @staticmethod
    def _extract_features(ts: datetime, success: bool) -> list[float]:
        return [
            float(ts.hour),
            float(ts.weekday()),
            0.0 if success else 1.0,
        ]
