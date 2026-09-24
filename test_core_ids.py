#!/usr/bin/env python3
"""
NeuraShield Core IDS Integration Verification Test
Tests Database, Rule Detector, ML Engine, and Web API.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

import database
from ml_detector import MLDetector
from rule_detector import RuleDetector, SecurityAlert


class TestNeuraShieldCoreIDS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db_path = Path(__file__).parent / "test_neurashield.db"
        if cls.test_db_path.exists():
            os.remove(cls.test_db_path)
        database.init_db(cls.test_db_path)

    @classmethod
    def tearDownClass(cls):
        if cls.test_db_path.exists():
            os.remove(cls.test_db_path)

    def test_01_database_operations(self):
        """Verify SQLite incident and traffic stats logging and queries."""
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
        self.assertGreater(row_id, 0)

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
        self.assertGreater(stat_id, 0)

        summary = database.get_summary_counts(db_path=self.test_db_path)
        self.assertEqual(summary["total_incidents"], 1)
        self.assertEqual(summary["high_severity"], 1)

    def test_02_rule_detector(self):
        """Verify deterministic rule detection engine."""
        rule_engine = RuleDetector()

        # Port Scan Flow Feature Vector
        scan_flow = {
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "protocol": 6,
            "unique_destination_ports": 25,
            "syn_count": 25,
            "ack_count": 0,
            "flow_duration": 4.0,
            "total_packets": 25,
            "total_bytes": 1250,
            "packet_rate": 6.25,
            "byte_rate": 312.5,
            "average_packet_size": 50.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 25,
            "interfaces": ["eth0"]
        }

        alerts = rule_engine.analyze(scan_flow)
        self.assertIsNotNone(alerts)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].rule_id, "R001")
        self.assertEqual(alerts[0].threat, "PORT_SCAN")

    def test_03_ml_detector(self):
        """Verify ML anomaly and behavioral classification engine."""
        ml_engine = MLDetector()

        # Benign flow
        benign_flow = {
            "source_ip": "192.168.1.50",
            "destination_ip": "140.82.121.4",
            "protocol": 6,
            "unique_destination_ports": 1,
            "syn_count": 1,
            "ack_count": 10,
            "flow_duration": 2.5,
            "total_packets": 15,
            "total_bytes": 4500,
            "packet_rate": 6.0,
            "byte_rate": 1800.0,
            "average_packet_size": 300.0,
            "fin_count": 1,
            "rst_count": 0,
            "connection_frequency": 1
        }
        ml_alert_benign = ml_engine.analyze(benign_flow)
        self.assertIsNone(ml_alert_benign)

        # Anomaly flow (extreme packet rate & SYN burst)
        anomaly_flow = {
            "source_ip": "172.16.0.5",
            "destination_ip": "10.0.0.2",
            "protocol": 6,
            "unique_destination_ports": 1,
            "syn_count": 500,
            "ack_count": 0,
            "flow_duration": 1.0,
            "total_packets": 500,
            "total_bytes": 25000,
            "packet_rate": 500.0,
            "byte_rate": 25000.0,
            "average_packet_size": 50.0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_frequency": 45
        }
        ml_alert_anomaly = ml_engine.analyze(anomaly_flow)
        self.assertIsNotNone(ml_alert_anomaly)
        self.assertEqual(ml_alert_anomaly.rule_id, "ML100")
        self.assertIn("ML_", ml_alert_anomaly.threat)


if __name__ == "__main__":
    unittest.main()
