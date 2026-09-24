#!/usr/bin/env python3
"""
NeuraShield - Self-Learning AI Module (Layer 3)
Uses Isolation Forest to learn YOUR network's normal traffic baseline,
then detects anomalies that deviate from that learned behavior.

This is what makes NeuraShield competitive with enterprise solutions
like Darktrace — it learns what's "normal" for YOUR specific network
and flags anything unusual, even zero-day attacks it has never seen.

Usage:
    # Train baseline from collected flow data:
    from self_learning import SelfLearningEngine
    engine = SelfLearningEngine()
    engine.train_baseline()   # Trains on recent normal flows

    # Detect anomalies:
    score = engine.detect_anomaly(flow_features)
"""

from __future__ import annotations

import os
import time
import threading
from collections import deque
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict

import numpy as np
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ============================================================
# CONFIGURATION
# ============================================================

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
BASELINE_MODEL_PATH = os.path.join(MODELS_DIR, "baseline_isolation_forest.joblib")
BASELINE_SCALER_PATH = os.path.join(MODELS_DIR, "baseline_scaler.joblib")

# Features extracted from live traffic flows for baseline learning
BASELINE_FEATURES = [
    "flow_duration",
    "total_packets",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "unique_destination_ports",
    "connection_frequency",
]

# Minimum samples needed before training a baseline
MIN_TRAINING_SAMPLES = 50

# Maximum samples to store in memory for training
MAX_TRAINING_BUFFER = 10000

# Anomaly contamination rate (expected % of anomalies in training data)
# Lower = more sensitive (flags more as anomalous)
CONTAMINATION_RATE = 0.05

# Auto-retrain interval in seconds (default: 1 hour)
RETRAIN_INTERVAL = 3600


@dataclass
class AnomalyResult:
    """Result from the self-learning anomaly detector."""
    is_anomaly: bool
    anomaly_score: float        # -1 to 0 (more negative = more anomalous)
    confidence: int             # 0-100
    reason: str
    baseline_trained: bool      # Whether a baseline model exists

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================
# SELF-LEARNING ENGINE
# ============================================================

class SelfLearningEngine:
    """
    Self-learning anomaly detection engine using Isolation Forest.

    How it works:
    1. COLLECT: Gathers flow feature vectors from normal traffic
    2. LEARN:   Trains an Isolation Forest on the collected baseline
    3. DETECT:  Scores new flows — anything outside the baseline is flagged
    4. ADAPT:   Periodically retrains to adapt to network changes
    """

    def __init__(self):
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._training_buffer: deque = deque(maxlen=MAX_TRAINING_BUFFER)
        self._lock = threading.Lock()
        self._model_loaded = False
        self._samples_since_train = 0
        self._last_train_time = 0.0

        # Try to load existing baseline model
        self._load_model()

    # --------------------------------------------------------
    # MODEL PERSISTENCE
    # --------------------------------------------------------

    def _load_model(self):
        """Load previously trained baseline model from disk."""
        try:
            if os.path.exists(BASELINE_MODEL_PATH) and os.path.exists(BASELINE_SCALER_PATH):
                self._model = joblib.load(BASELINE_MODEL_PATH)
                self._scaler = joblib.load(BASELINE_SCALER_PATH)
                self._model_loaded = True
                print(f"[SELF-LEARN] ✓ Loaded baseline model from {BASELINE_MODEL_PATH}")
            else:
                print("[SELF-LEARN] No baseline model found — collecting traffic samples...")
        except Exception as exc:
            print(f"[SELF-LEARN] Warning: Could not load baseline model: {exc}")

    def _save_model(self):
        """Save trained baseline model to disk."""
        try:
            os.makedirs(MODELS_DIR, exist_ok=True)
            joblib.dump(self._model, BASELINE_MODEL_PATH)
            joblib.dump(self._scaler, BASELINE_SCALER_PATH)
            print(f"[SELF-LEARN] ✓ Baseline model saved ({len(self._training_buffer)} samples)")
        except Exception as exc:
            print(f"[SELF-LEARN] Warning: Could not save baseline model: {exc}")

    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    def _extract_features(self, flow_features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Convert flow feature dict to numeric vector."""
        vec = []
        for name in BASELINE_FEATURES:
            val = flow_features.get(name, 0.0)
            try:
                num = float(val) if val is not None else 0.0
                vec.append(num if np.isfinite(num) else 0.0)
            except (ValueError, TypeError):
                vec.append(0.0)
        return np.array(vec, dtype=np.float64)

    # --------------------------------------------------------
    # TRAINING
    # --------------------------------------------------------

    def collect_sample(self, flow_features: Dict[str, Any]):
        """
        Add a flow's features to the training buffer.
        Call this for EVERY completed flow, not just suspicious ones.
        The engine learns what "normal" looks like from ALL your traffic.
        """
        vec = self._extract_features(flow_features)
        if vec is not None:
            with self._lock:
                self._training_buffer.append(vec)
                self._samples_since_train += 1

        # Auto-train if we have enough samples and enough time has passed
        should_train = (
            not self._model_loaded and
            len(self._training_buffer) >= MIN_TRAINING_SAMPLES
        )
        should_retrain = (
            self._model_loaded and
            self._samples_since_train >= MIN_TRAINING_SAMPLES * 5 and
            (time.time() - self._last_train_time) > RETRAIN_INTERVAL
        )

        if should_train or should_retrain:
            self.train_baseline()

    def train_baseline(self) -> bool:
        """
        Train the Isolation Forest on collected traffic samples.
        This learns what YOUR network's normal behavior looks like.
        """
        with self._lock:
            if len(self._training_buffer) < MIN_TRAINING_SAMPLES:
                print(f"[SELF-LEARN] Need {MIN_TRAINING_SAMPLES} samples, "
                      f"have {len(self._training_buffer)} — waiting...")
                return False

            # Convert buffer to training matrix
            X_train = np.array(list(self._training_buffer), dtype=np.float64)

        # Handle NaN/inf
        X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)

        # Train Isolation Forest
        model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION_RATE,
            max_samples="auto",
            max_features=1.0,
            random_state=42,
            n_jobs=-1,
        )

        print(f"[SELF-LEARN] Training baseline on {len(X_train)} flow samples...")
        start = time.time()
        model.fit(X_scaled)
        elapsed = time.time() - start
        print(f"[SELF-LEARN] ✓ Baseline trained in {elapsed:.2f}s")

        # Atomic swap
        with self._lock:
            self._model = model
            self._scaler = scaler
            self._model_loaded = True
            self._samples_since_train = 0
            self._last_train_time = time.time()

        # Persist to disk
        self._save_model()
        return True

    # --------------------------------------------------------
    # DETECTION
    # --------------------------------------------------------

    def detect_anomaly(self, flow_features: Dict[str, Any]) -> AnomalyResult:
        """
        Score a flow against the learned baseline.

        Returns AnomalyResult with:
        - is_anomaly: True if the flow deviates from learned normal
        - anomaly_score: Raw score (-1 to 0, more negative = more anomalous)
        - confidence: 0-100 confidence level
        """
        # Also collect this sample for future retraining
        self.collect_sample(flow_features)

        if not self._model_loaded or self._model is None:
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0,
                reason=f"Baseline not trained yet ({len(self._training_buffer)}/{MIN_TRAINING_SAMPLES} samples)",
                baseline_trained=False,
            )

        vec = self._extract_features(flow_features)
        if vec is None:
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0,
                reason="Could not extract features",
                baseline_trained=True,
            )

        try:
            # Scale using the same scaler from training
            X = self._scaler.transform(vec.reshape(1, -1))

            # Predict: 1 = normal, -1 = anomaly
            prediction = self._model.predict(X)[0]

            # Score: negative = anomalous, positive = normal
            raw_score = self._model.score_samples(X)[0]

            # Convert to confidence (0-100)
            # score_samples returns values typically between -0.5 and 0.5
            # More negative = more anomalous
            is_anomaly = prediction == -1

            if is_anomaly:
                # Map score to confidence: -0.5 → 95%, -0.2 → 60%, 0 → 50%
                confidence = min(99, max(50, int(50 + abs(raw_score) * 100)))
                reason = self._explain_anomaly(flow_features, raw_score)
            else:
                confidence = min(99, max(50, int(50 + raw_score * 80)))
                reason = "Traffic matches learned baseline"

            return AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=float(raw_score),
                confidence=confidence,
                reason=reason,
                baseline_trained=True,
            )

        except Exception as exc:
            return AnomalyResult(
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0,
                reason=f"Detection error: {exc}",
                baseline_trained=True,
            )

    def _explain_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """Generate human-readable explanation for why traffic is anomalous."""
        reasons = []

        pkt_rate = float(features.get("packet_rate", 0))
        byte_rate = float(features.get("byte_rate", 0))
        syn_count = int(features.get("syn_count", 0))
        unique_ports = int(features.get("unique_destination_ports", 0))
        rst_count = int(features.get("rst_count", 0))
        total_pkts = int(features.get("total_packets", 0))

        if pkt_rate > 100:
            reasons.append(f"unusual packet rate ({pkt_rate:.0f}/s)")
        if byte_rate > 50000:
            reasons.append(f"unusual byte rate ({byte_rate:.0f} B/s)")
        if syn_count > 5 and total_pkts > 0 and syn_count / total_pkts > 0.8:
            reasons.append(f"SYN-heavy traffic ({syn_count}/{total_pkts} pkts)")
        if unique_ports > 10:
            reasons.append(f"wide port scan ({unique_ports} ports)")
        if rst_count > 10:
            reasons.append(f"high RST count ({rst_count})")

        if not reasons:
            reasons.append("traffic pattern deviates from learned baseline")

        severity = "significantly" if score < -0.3 else "moderately"
        return f"Flow {severity} deviates from baseline: {', '.join(reasons)}"

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return engine status for API/dashboard."""
        return {
            "baseline_trained": self._model_loaded,
            "training_samples_collected": len(self._training_buffer),
            "min_samples_needed": MIN_TRAINING_SAMPLES,
            "samples_since_last_train": self._samples_since_train,
            "retrain_interval_seconds": RETRAIN_INTERVAL,
        }
