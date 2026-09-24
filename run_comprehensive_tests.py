#!/usr/bin/env python3
"""
NeuraShield Comprehensive Automated Test Suite
Tests all 3 AI Layers, Rule Detector, Database, Flow Aggregator, Queue Manager, and API Endpoints.
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import unittest
from pathlib import Path
from typing import Dict, Any

# Ensure current dir in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database
from rule_detector import RuleDetector
from ml_detector import MLDetector
from self_learning import SelfLearningEngine
from flow_aggregator import FlowAggregator, PacketMetadata
import queue_manager
from fastapi.testclient import TestClient
from api import app


class TestNeuraShieldSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db_dir = Path(__file__).parent / "test_data"
        cls.test_db_dir.mkdir(exist_ok=True)
        cls.test_db_path = cls.test_db_dir / "test_suite.db"
        if cls.test_db_path.exists():
            os.remove(cls.test_db_path)
        database.init_db(cls.test_db_path)

    @classmethod
    def tearDownClass(cls):
        if cls.test_db_dir.exists():
            shutil.rmtree(cls.test_db_dir, ignore_errors=True)

    # ---------------------------------------------------------
    # PHASE 1: Database Operations
    # ---------------------------------------------------------
    def test_01_database_core(self):
        """Test DB creation, incident logging, querying, and summary counts."""
        row_id = database.log_incident(
            rule_id="R001",
            threat="PORT_SCAN",
            severity="HIGH",
            confidence=95,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            evidence="25 unique destination ports contacted in 5s",
            source_port=54321,
            destination_port=80,
            protocol=6,
            db_path=self.test_db_path
        )
        self.assertGreater(row_id, 0, "Incident logging failed")

        incidents = database.get_incidents(limit=10, db_path=self.test_db_path)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threat"], "PORT_SCAN")
        self.assertEqual(incidents[0]["severity"], "HIGH")

        stat_id = database.log_traffic_stats(
            active_flows=5,
            total_packets=120,
            total_bytes=15000,
            packet_rate=24.0,
            byte_rate=3000.0,
            db_path=self.test_db_path
        )
        self.assertGreater(stat_id, 0, "Traffic stats logging failed")

        summary = database.get_summary_counts(db_path=self.test_db_path)
        self.assertEqual(summary["total_incidents"], 1)
        self.assertEqual(summary["high_severity"], 1)
        print("  [Phase 1] Database core operations: PASSED")

    # ---------------------------------------------------------
    # PHASE 2: Layer 1 - Rule Detector Engine
    # ---------------------------------------------------------
    def test_02_rule_detector_heuristics(self):
        """Test deterministic rules: Port Scan, SYN Flood, Data Exfiltration."""
        rule_engine = RuleDetector()

        # Port Scan (R001)
        port_scan_flow = {
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "protocol": 6,
            "unique_destination_ports": 30,
            "syn_count": 30,
            "ack_count": 0,
            "flow_duration": 3.0,
            "total_packets": 30,
            "total_bytes": 1500,
            "packet_rate": 10.0,
            "byte_rate": 500.0,
            "average_packet_size": 50.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 30,
            "interfaces": ["eth0"]
        }
        alerts = rule_engine.analyze(port_scan_flow)
        self.assertTrue(any(a.rule_id == "R001" for a in alerts), "Port scan rule failed")

        # SYN Flood / DDoS (R003)
        syn_flood_flow = {
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.1",
            "protocol": 6,
            "unique_destination_ports": 1,
            "syn_count": 250,
            "ack_count": 2,
            "flow_duration": 2.0,
            "total_packets": 252,
            "total_bytes": 12600,
            "packet_rate": 126.0,
            "byte_rate": 6300.0,
            "average_packet_size": 50.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 50,
            "interfaces": ["eth0"]
        }
        alerts_syn = rule_engine.analyze(syn_flood_flow)
        self.assertTrue(any(a.rule_id == "R003" for a in alerts_syn), "SYN flood rule failed")

        print("  [Phase 2] Layer 1 Heuristic Rules: PASSED")

    # ---------------------------------------------------------
    # PHASE 3: Layer 2 - Supervised Random Forest AI Model
    # ---------------------------------------------------------
    def test_03_layer2_random_forest(self):
        """Test pre-trained Random Forest model loading and classification."""
        ml_engine = MLDetector()
        self.assertTrue(ml_engine.rf_loaded, "Random Forest model failed to load")

        # Disable Layer 3 temporarily to isolate Layer 2 Random Forest evaluation
        ml_engine.self_learning_available = False

        # Benign Traffic Flow
        benign_flow = {
            "source_ip": "192.168.1.105",
            "destination_ip": "8.8.8.8",
            "protocol": 17, # UDP
            "unique_destination_ports": 1,
            "syn_count": 0,
            "ack_count": 0,
            "flow_duration": 0.5,
            "total_packets": 2,
            "total_bytes": 150,
            "packet_rate": 4.0,
            "byte_rate": 300.0,
            "average_packet_size": 75.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 1
        }
        alert_benign = ml_engine.analyze(benign_flow)
        self.assertIsNone(alert_benign, "Benign flow misclassified as threat")

        # Severe DDoS / Probe Attack Flow
        attack_flow = {
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.1",
            "protocol": 6,
            "unique_destination_ports": 150,
            "syn_count": 1000,
            "ack_count": 0,
            "flow_duration": 1.0,
            "total_packets": 1000,
            "total_bytes": 60000,
            "packet_rate": 1000.0,
            "byte_rate": 60000.0,
            "average_packet_size": 60.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 200
        }
        alert_attack = ml_engine.analyze(attack_flow)
        self.assertIsNotNone(alert_attack, "Attack flow missed by ML engine")
        self.assertIn("ML_", alert_attack.threat)
        self.assertGreater(alert_attack.confidence, 50)
        print(f"  [Phase 3] Layer 2 Random Forest ML: PASSED (Detected: {alert_attack.threat}, Conf: {alert_attack.confidence}%)")

    # ---------------------------------------------------------
    # PHASE 4: Layer 3 - Self-Learning Isolation Forest Anomaly Engine
    # ---------------------------------------------------------
    def test_04_layer3_self_learning(self):
        """Test baseline collection, online training, and zero-day anomaly detection."""
        sl_engine = SelfLearningEngine()
        
        # Collect normal web browser traffic samples into sample buffer
        for i in range(60):
            sample = {
                "flow_duration": 1.0 + (i % 5) * 0.1,
                "total_packets": 10 + (i % 10),
                "total_bytes": 3000 + (i % 100) * 50,
                "packet_rate": 10.0 + (i % 3),
                "byte_rate": 3000.0 + (i % 10) * 10,
                "average_packet_size": 300.0,
                "syn_count": 1,
                "ack_count": 8,
                "fin_count": 1,
                "rst_count": 0,
                "unique_destination_ports": 1,
                "connection_frequency": 2
            }
            sl_engine.collect_sample(sample)

        # Train baseline
        trained = sl_engine.train_baseline()
        self.assertTrue(trained, "Self-learning engine failed to train baseline model")
        status = sl_engine.get_status()
        self.assertTrue(status["baseline_trained"], "Baseline model marked as untrained")

        # Test normal flow against baseline -> should NOT be anomaly
        normal_test = {
            "flow_duration": 1.2,
            "total_packets": 12,
            "total_bytes": 3200,
            "packet_rate": 10.0,
            "byte_rate": 3000.0,
            "average_packet_size": 300.0,
            "syn_count": 1,
            "ack_count": 9,
            "fin_count": 1,
            "rst_count": 0,
            "unique_destination_ports": 1,
            "connection_frequency": 2
        }
        res_normal = sl_engine.detect_anomaly(normal_test)
        self.assertFalse(res_normal.is_anomaly, "Normal traffic flagged as zero-day anomaly")

        # Test abnormal zero-day attack flow (wildly outside normal cluster)
        zero_day_flow = {
            "flow_duration": 0.001,
            "total_packets": 5000,
            "total_bytes": 1000000,
            "packet_rate": 500000.0,
            "byte_rate": 100000000.0,
            "average_packet_size": 200.0,
            "syn_count": 5000,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 500,
            "unique_destination_ports": 500,
            "connection_frequency": 1000
        }
        res_zero_day = sl_engine.detect_anomaly(zero_day_flow)
        self.assertTrue(res_zero_day.is_anomaly, "Zero-day anomaly missed by Layer 3 Isolation Forest")
        print(f"  [Phase 4] Layer 3 Self-Learning Isolation Forest: PASSED (Normal Score: {res_normal.anomaly_score:.2f}, Anomaly Score: {res_zero_day.anomaly_score:.2f})")

    # ---------------------------------------------------------
    # PHASE 5: Flow Aggregator Packet Extraction
    # ---------------------------------------------------------
    def test_05_flow_aggregator(self):
        """Test PacketMetadata to Flow Feature aggregation."""
        aggregator = FlowAggregator(timeout=2.0)

        # Send 5 SYN packet metadata objects
        for i in range(5):
            meta = PacketMetadata(
                timestamp=time.time(),
                source_ip="192.168.1.200",
                destination_ip="10.0.0.5",
                source_port=1000 + i,
                destination_port=80,
                protocol=6,
                packet_size=60,
                tcp_flags="S",
                interface="ens33"
            )
            aggregator.update(meta)

        active_flows = aggregator.active_flows
        self.assertGreater(len(active_flows), 0, "Flow Aggregator failed to track active flows")
        print("  [Phase 5] Flow Aggregator: PASSED")

    # ---------------------------------------------------------
    # PHASE 6: Queue Manager Deduplication & Metadata Extraction
    # ---------------------------------------------------------
    def test_06_queue_manager_extraction(self):
        """Test metadata extraction and deduplication in queue manager."""
        try:
            from scapy.all import IP, TCP, Ether
        except ImportError:
            self.skipTest("Scapy not available")

        pkt = Ether()/IP(src="10.10.10.10", dst="192.168.1.1")/TCP(sport=4444, dport=22, flags="S")
        meta = queue_manager.extract_metadata(pkt, interface="ens33")
        self.assertIsNotNone(meta, "Metadata extraction returned None")
        self.assertEqual(meta.source_ip, "10.10.10.10")
        self.assertEqual(meta.destination_ip, "192.168.1.1")
        self.assertEqual(meta.destination_port, 22)
        
        # Test deduplication
        dup_1 = queue_manager.is_duplicate(pkt, time.time())
        dup_2 = queue_manager.is_duplicate(pkt, time.time())
        self.assertTrue(dup_2, "Packet deduplication failed")
        print("  [Phase 6] Queue Manager Metadata & Deduplication: PASSED")

    # ---------------------------------------------------------
    # PHASE 7: Web API Endpoints Test
    # ---------------------------------------------------------
    def test_07_api_endpoints(self):
        """Test FastAPI REST endpoints (status, incidents, summary, stats)."""
        client = TestClient(app)

        # /api/status
        res_status = client.get("/api/status")
        self.assertEqual(res_status.status_code, 200)
        json_status = res_status.json()
        self.assertIn("status", json_status)
        self.assertEqual(json_status["status"], "ACTIVE")

        # /api/incidents
        res_incidents = client.get("/api/incidents")
        self.assertEqual(res_incidents.status_code, 200)

        # /api/summary
        res_summary = client.get("/api/summary")
        self.assertEqual(res_summary.status_code, 200)

        # /api/stats/traffic
        res_traffic = client.get("/api/stats/traffic")
        self.assertEqual(res_traffic.status_code, 200)

        print("  [Phase 7] FastAPI REST API Endpoints: PASSED (All endpoints OK)")


if __name__ == "__main__":
    print("\n=======================================================")
    print("🛡️  NeuraShield Comprehensive Verification Test Suite")
    print("=======================================================\n")
    unittest.main(verbosity=2)
