#!/usr/bin/env python3
"""
NeuraShield - Multi-Layer AI Threat Detection Engine

3-Layer Detection Architecture:
    Layer 1: Heuristic Statistical Anomaly Engine (fast, deterministic fallback)
    Layer 2: Supervised ML — Random Forest trained on NSL-KDD (known attack classification)
    Layer 3: Self-Learning AI — Isolation Forest baseline anomaly detection (zero-day)

Each layer produces independent threat assessments. The final verdict
combines all layers using confidence-weighted scoring.
"""

from __future__ import annotations

import os
import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

try:
    import joblib
    import numpy as np
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    ML_LIBRARIES_AVAILABLE = False

try:
    from self_learning import SelfLearningEngine
    SELF_LEARNING_AVAILABLE = True
except ImportError:
    SELF_LEARNING_AVAILABLE = False


@dataclass
class MLAlert:
    """Standardized Machine Learning threat detection alert."""
    rule_id: str
    threat: str
    severity: str
    confidence: int
    source_ip: str
    destination_ip: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MLDetector:
    """
    Multi-Layer AI Threat Detection Engine.

    Processes flow features through 3 detection layers:
      Layer 1: Heuristic rules (always available)
      Layer 2: Random Forest ML (if trained model exists)
      Layer 3: Self-learning anomaly AI (learns your network)
    """

    # Features used by Layer 1 heuristic engine
    FEATURE_NAMES = [
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

    # NSL-KDD feature mapping: maps our live flow features to NSL-KDD columns
    # Our Scapy capture extracts these → mapped to NSL-KDD's 41 features
    NSL_KDD_FEATURE_MAP = {
        "duration": "flow_duration",
        "src_bytes": "total_bytes",
        "dst_bytes": "total_bytes",  # approximation
        "count": "connection_frequency",
        "srv_count": "connection_frequency",
        "land": None,           # filled with 0
        "wrong_fragment": None,  # filled with 0
        "urgent": None,         # filled with 0
    }

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the 3-layer detection engine.

        Args:
            model_path: Path to a specific model file (optional).
                        If None, auto-discovers models in models/ directory.
        """
        # Layer 2: Supervised ML model
        self.rf_model = None
        self.rf_scaler = None
        self.rf_label_encoders = None
        self.rf_feature_columns = None
        self.rf_loaded = False

        # Layer 3: Self-learning engine
        self.self_learning_engine = None
        self.self_learning_available = False

        # Auto-discover models
        models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

        # --- Load Layer 2: Random Forest ---
        if ML_LIBRARIES_AVAILABLE:
            rf_path = model_path or os.path.join(models_dir, "nids_rf_model.joblib")
            scaler_path = os.path.join(models_dir, "scaler.joblib")
            le_path = os.path.join(models_dir, "label_encoders.joblib")
            fc_path = os.path.join(models_dir, "feature_columns.joblib")

            if os.path.exists(rf_path):
                try:
                    self.rf_model = joblib.load(rf_path)
                    if os.path.exists(scaler_path):
                        self.rf_scaler = joblib.load(scaler_path)
                    if os.path.exists(le_path):
                        self.rf_label_encoders = joblib.load(le_path)
                    if os.path.exists(fc_path):
                        self.rf_feature_columns = joblib.load(fc_path)
                    self.rf_loaded = True
                    print(f"[ML Layer 2] ✓ Random Forest model loaded from {rf_path}")
                except Exception as exc:
                    print(f"[ML Layer 2] ✗ Failed to load RF model: {exc}")

        # --- Load Layer 3: Self-Learning AI ---
        if SELF_LEARNING_AVAILABLE:
            try:
                self.self_learning_engine = SelfLearningEngine()
                self.self_learning_available = True
                print("[ML Layer 3] ✓ Self-learning anomaly engine initialized")
            except Exception as exc:
                print(f"[ML Layer 3] ✗ Failed to initialize self-learning: {exc}")

        # Summary
        layers = []
        layers.append("Layer 1: Heuristic ✓")
        layers.append(f"Layer 2: Random Forest {'✓' if self.rf_loaded else '✗ (run train_model.py)'}")
        layers.append(f"Layer 3: Self-Learning {'✓' if self.self_learning_available else '✗'}")
        print(f"[ML ENGINE] Active layers: {' | '.join(layers)}")

    def extract_features(self, flow_features: Dict[str, Any]) -> List[float]:
        """Convert a flow feature dictionary into a numeric vector for Layer 1."""
        vec = []
        for name in self.FEATURE_NAMES:
            val = flow_features.get(name, 0.0)
            try:
                num = float(val) if val is not None else 0.0
                vec.append(num if math.isfinite(num) else 0.0)
            except (ValueError, TypeError):
                vec.append(0.0)
        return vec

    def _build_nsl_kdd_vector(self, flow_features: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Map live Scapy flow features to the NSL-KDD feature format
        that the Random Forest model expects.
        """
        if not self.rf_feature_columns or not ML_LIBRARIES_AVAILABLE:
            return None

        # Build a feature dict matching NSL-KDD columns
        nsl_features = {}

        # Direct mappings
        nsl_features["duration"] = float(flow_features.get("flow_duration", 0))
        nsl_features["src_bytes"] = float(flow_features.get("total_bytes", 0))
        nsl_features["dst_bytes"] = float(flow_features.get("total_bytes", 0)) * 0.3
        nsl_features["count"] = float(flow_features.get("connection_frequency", 0))
        nsl_features["srv_count"] = float(flow_features.get("connection_frequency", 0))

        # Protocol mapping
        protocol = str(flow_features.get("protocol", "6"))
        proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}
        protocol_type = proto_map.get(protocol, "tcp")

        # Flag mapping based on TCP flags
        syn_count = int(flow_features.get("syn_count", 0))
        ack_count = int(flow_features.get("ack_count", 0))
        rst_count = int(flow_features.get("rst_count", 0))
        fin_count = int(flow_features.get("fin_count", 0))

        if syn_count > 0 and ack_count > 0:
            flag = "SF"
        elif syn_count > 0 and rst_count > 0:
            flag = "REJ"
        elif syn_count > 0 and ack_count == 0:
            flag = "S0"
        elif rst_count > 0:
            flag = "RSTR"
        else:
            flag = "OTH"

        # Service mapping from destination port
        dst_port = int(flow_features.get("destination_port", 0))
        port_service_map = {
            80: "http", 443: "http", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "domain_u", 110: "pop_3", 143: "imap4",
            3306: "sql_net", 8080: "http",
        }
        service = port_service_map.get(dst_port, "other")

        # Encode categoricals
        if self.rf_label_encoders:
            for col, value in [("protocol_type", protocol_type), ("service", service), ("flag", flag)]:
                le = self.rf_label_encoders.get(col)
                if le:
                    try:
                        nsl_features[col] = le.transform([value])[0]
                    except ValueError:
                        # Unknown category — use most common
                        nsl_features[col] = 0
                else:
                    nsl_features[col] = 0

        # Derived network features
        total_pkts = float(flow_features.get("total_packets", 1))
        pkt_rate = float(flow_features.get("packet_rate", 0))

        nsl_features["land"] = 0
        nsl_features["wrong_fragment"] = 0
        nsl_features["urgent"] = 0
        nsl_features["hot"] = 0
        nsl_features["num_failed_logins"] = 0
        nsl_features["logged_in"] = 0
        nsl_features["num_compromised"] = 0
        nsl_features["root_shell"] = 0
        nsl_features["su_attempted"] = 0
        nsl_features["num_root"] = 0
        nsl_features["num_file_creations"] = 0
        nsl_features["num_shells"] = 0
        nsl_features["num_access_files"] = 0
        nsl_features["num_outbound_cmds"] = 0
        nsl_features["is_host_login"] = 0
        nsl_features["is_guest_login"] = 0

        # Rate-based features (derived from flow stats)
        nsl_features["serror_rate"] = min(1.0, syn_count / max(total_pkts, 1) if ack_count == 0 else 0)
        nsl_features["srv_serror_rate"] = nsl_features["serror_rate"]
        nsl_features["rerror_rate"] = min(1.0, rst_count / max(total_pkts, 1))
        nsl_features["srv_rerror_rate"] = nsl_features["rerror_rate"]
        nsl_features["same_srv_rate"] = 1.0
        nsl_features["diff_srv_rate"] = 0.0
        nsl_features["srv_diff_host_rate"] = 0.0

        # Host-based features
        unique_ports = float(flow_features.get("unique_destination_ports", 1))
        nsl_features["dst_host_count"] = min(255, pkt_rate)
        nsl_features["dst_host_srv_count"] = min(255, pkt_rate * 0.7)
        nsl_features["dst_host_same_srv_rate"] = max(0, 1.0 - (unique_ports / 255.0))
        nsl_features["dst_host_diff_srv_rate"] = min(1.0, unique_ports / 255.0)
        nsl_features["dst_host_same_src_port_rate"] = 0.5
        nsl_features["dst_host_srv_diff_host_rate"] = 0.0
        nsl_features["dst_host_serror_rate"] = nsl_features["serror_rate"]
        nsl_features["dst_host_srv_serror_rate"] = nsl_features["serror_rate"]
        nsl_features["dst_host_rerror_rate"] = nsl_features["rerror_rate"]
        nsl_features["dst_host_srv_rerror_rate"] = nsl_features["rerror_rate"]

        # Build vector in the exact order the model expects
        vec = []
        for col in self.rf_feature_columns:
            vec.append(float(nsl_features.get(col, 0.0)))

        return np.array(vec, dtype=np.float64)

    def analyze(self, flow_features: Dict[str, Any]) -> Optional[MLAlert]:
        """
        Analyze flow features through all 3 detection layers.
        Returns the highest-confidence MLAlert, or None if traffic is normal.
        """
        source_ip = str(flow_features.get("source_ip", "0.0.0.0"))
        destination_ip = str(flow_features.get("destination_ip", "0.0.0.0"))
        feature_vector = self.extract_features(flow_features)

        alerts: List[MLAlert] = []

        # ============================================================
        # LAYER 2: Random Forest ML (Known Attack Classification)
        # ============================================================
        if self.rf_loaded and self.rf_model is not None and ML_LIBRARIES_AVAILABLE:
            try:
                nsl_vec = self._build_nsl_kdd_vector(flow_features)
                if nsl_vec is not None:
                    X = nsl_vec.reshape(1, -1)

                    # Scale if scaler is available
                    if self.rf_scaler is not None:
                        X = self.rf_scaler.transform(X)

                    prediction = self.rf_model.predict(X)[0]

                    # Get probability if available
                    if hasattr(self.rf_model, "predict_proba"):
                        probas = self.rf_model.predict_proba(X)[0]
                        confidence = int(max(probas) * 100)
                    else:
                        confidence = 75

                    # prediction: 0 = BENIGN, 1 = ATTACK
                    if int(prediction) == 1 and confidence > 60:
                        alerts.append(MLAlert(
                            rule_id="ML001",
                            threat="ML_RF_ATTACK_DETECTED",
                            severity="HIGH" if confidence > 80 else "MEDIUM",
                            confidence=confidence,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            evidence=f"Random Forest ML: {confidence}% attack probability"
                        ))
            except Exception as exc:
                pass  # Silent fail — Layer 1 and 3 will catch it

        # ============================================================
        # LAYER 3: Self-Learning Anomaly Detection (Zero-Day)
        # ============================================================
        if self.self_learning_available and self.self_learning_engine is not None:
            try:
                anomaly_result = self.self_learning_engine.detect_anomaly(flow_features)

                if anomaly_result.is_anomaly and anomaly_result.confidence > 60:
                    alerts.append(MLAlert(
                        rule_id="ML200",
                        threat="AI_BASELINE_ANOMALY",
                        severity="HIGH" if anomaly_result.confidence > 80 else "MEDIUM",
                        confidence=anomaly_result.confidence,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        evidence=f"Self-learning AI: {anomaly_result.reason}"
                    ))
            except Exception:
                pass

        # ============================================================
        # LAYER 1: Heuristic Statistical Anomaly Engine (Fallback)
        # ============================================================
        packet_rate = feature_vector[3]
        syn_count = feature_vector[6]
        ack_count = feature_vector[7]
        rst_count = feature_vector[9]
        unique_ports = feature_vector[10]
        conn_freq = feature_vector[11]

        anomaly_score = 0
        reasons = []

        if packet_rate > 300.0:
            anomaly_score += 40
            reasons.append(f"Excessive packet rate ({packet_rate:.1f} pkts/s)")

        if syn_count > 15 and ack_count == 0:
            anomaly_score += 45
            reasons.append(f"Unanswered TCP SYN burst (SYN={int(syn_count)}, ACK=0)")

        if unique_ports > 15:
            anomaly_score += 50
            reasons.append(f"High destination port fan-out ({int(unique_ports)} ports)")

        if conn_freq > 40:
            anomaly_score += 35
            reasons.append(f"Rapid connection burst ({int(conn_freq)} connections/min)")

        if rst_count > 25:
            anomaly_score += 30
            reasons.append(f"Abnormal RST count ({int(rst_count)})")

        if anomaly_score >= 60:
            threat_type = "STATISTICAL_TRAFFIC_ANOMALY"
            if unique_ports > 15:
                threat_type = "ML_PORT_SCAN_BEHAVIOR"
            elif syn_count > 15:
                threat_type = "ML_SYN_FLOOD_BEHAVIOR"
            elif packet_rate > 300.0:
                threat_type = "ML_DOS_RATE_ANOMALY"

            confidence = min(99, 50 + anomaly_score // 2)
            severity = "HIGH" if confidence > 75 else "MEDIUM"

            alerts.append(MLAlert(
                rule_id="ML100",
                threat=threat_type,
                severity=severity,
                confidence=confidence,
                source_ip=source_ip,
                destination_ip=destination_ip,
                evidence=" | ".join(reasons)
            ))

        # ============================================================
        # VERDICT: Return highest-confidence alert
        # ============================================================
        if not alerts:
            return None

        # Sort by confidence descending, return the best
        alerts.sort(key=lambda a: a.confidence, reverse=True)
        return alerts[0]

    def get_engine_status(self) -> Dict[str, Any]:
        """Return status of all ML layers for API/dashboard."""
        status = {
            "layer_1_heuristic": True,
            "layer_2_random_forest": self.rf_loaded,
            "layer_3_self_learning": self.self_learning_available,
        }
        if self.self_learning_available and self.self_learning_engine:
            status["self_learning_status"] = self.self_learning_engine.get_status()
        return status
