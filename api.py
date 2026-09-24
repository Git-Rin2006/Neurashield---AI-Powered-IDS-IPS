#!/usr/bin/env python3
"""
NeuraShield - Operational IDS Telemetry & Topology API
Provides high-density, production-focused telemetry, node health status, and threat queries.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import database
import ips_engine
import flow_aggregator
from rule_detector import RuleDetector
from ml_detector import MLDetector

# Ensure database is initialized
database.init_db()

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)

# Try FastAPI / Uvicorn import
try:
    from fastapi import FastAPI, Query, HTTPException, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse, PlainTextResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


def get_topology_data():
    """Return operational state of the 4-node network topology (60s live alert window)."""
    # Evaluate node threat status strictly against threats occurring in the last 60 seconds
    active_incidents = database.get_recent_active_incidents(seconds=60)

    vm1_threats = [i for i in active_incidents if i.get("destination_ip") == "10.10.10.10" or i.get("source_ip") == "10.10.10.10"]
    vm2_threats = [i for i in active_incidents if i.get("destination_ip") == "10.10.20.10" or i.get("source_ip") == "10.10.20.10" or i.get("source_ip") == "10.10.20.1"]

    stats_hist = database.get_traffic_stats_history(limit=1)
    latest_traffic = stats_hist[0] if stats_hist else {}

    return {
        "vm3_gateway": {
            "node_id": "VM3",
            "name": "Ubuntu IDS Gateway (VM 3)",
            "ip": "10.1.1.101 / 10.10.10.1",
            "role": "Firewall & Intrusion Detection",
            "interfaces": ["ens33 (Host)", "ens37 (VM1)", "ens38 (VM2)"],
            "status": "HEALTHY",
            "active_flows": latest_traffic.get("active_flows", 0),
            "total_packets": latest_traffic.get("total_packets", 0)
        },
        "vm1": {
            "node_id": "VM1",
            "name": "VM 1 (Office PC 1)",
            "ip": "10.10.10.10",
            "subnet": "10.10.10.0/24",
            "interface": "ens37",
            "status": "ALERT" if vm1_threats else "ONLINE",
            "threat_count": len(vm1_threats),
            "latest_threat": vm1_threats[0].get("threat") if vm1_threats else None
        },
        "vm2": {
            "node_id": "VM2",
            "name": "VM 2 (Office PC 2)",
            "ip": "10.10.20.10",
            "subnet": "10.10.20.0/24",
            "interface": "ens38",
            "status": "ALERT" if vm2_threats else "ONLINE",
            "threat_count": len(vm2_threats),
            "latest_threat": vm2_threats[0].get("threat") if vm2_threats else None
        },
        "host_machine": {
            "node_id": "HOST",
            "name": "Physical Host Machine / WAN",
            "ip": "10.1.1.1",
            "interface": "ens33",
            "status": "CONNECTED"
        }
    }


def get_grouped_incidents(limit: int = 15):
    """Return deduplicated, productive threat alert summary cards."""
    incidents = database.get_incidents(limit=300)
    grouped = {}

    for inc in incidents:
        key = (inc.get("rule_id"), inc.get("threat"), inc.get("source_ip"), inc.get("destination_ip"))
        if key not in grouped:
            grouped[key] = {
                "id": inc.get("id"),
                "timestamp": inc.get("timestamp"),
                "rule_id": inc.get("rule_id"),
                "threat": inc.get("threat"),
                "severity": inc.get("severity"),
                "confidence": inc.get("confidence"),
                "source_ip": inc.get("source_ip"),
                "destination_ip": inc.get("destination_ip"),
                "evidence": inc.get("evidence"),
                "count": 1
            }
        else:
            grouped[key]["count"] += 1

    result = list(grouped.values())
    result.sort(key=lambda x: x["id"], reverse=True)
    return result[:limit]


if HAS_FASTAPI:
    app = FastAPI(title="NeuraShield IDS Operational Telemetry API", version="2.2.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def startup_event():
        try:
            import queue_manager
            queue_manager.start_background_pipeline()
        except Exception as exc:
            print(f"[API STARTUP] Background pipeline start warning: {exc}")

    @app.get("/api/status")
    def get_system_status():
        summary = database.get_summary_counts()
        traffic_history = database.get_traffic_stats_history(limit=1)
        latest_traffic = traffic_history[0] if traffic_history else {}
        return {
            "status": "ACTIVE",
            "engine": "NeuraShield Core IDS Engine",
            "version": "2.2.0",
            "active_flows": latest_traffic.get("active_flows", 0),
            "total_packets": latest_traffic.get("total_packets", 0),
            "total_incidents": summary.get("total_incidents", 0),
            "high_severity_incidents": summary.get("high_severity", 0),
            "critical_severity_incidents": summary.get("critical_severity", 0)
        }

    @app.get("/api/topology")
    def get_topology():
        return get_topology_data()

    @app.get("/api/incidents")
    def get_incidents(limit: int = 50, offset: int = 0, severity: str = None, threat: str = None):
        incidents = database.get_incidents(limit=limit, offset=offset, severity=severity, threat=threat)
        return {"count": len(incidents), "incidents": incidents}

    @app.get("/api/incidents/grouped")
    def get_grouped_incidents_api(limit: int = 15):
        alerts = get_grouped_incidents(limit=limit)
        return {"count": len(alerts), "alerts": alerts}

    @app.get("/api/stats/traffic")
    def get_traffic_statistics(limit: int = 30):
        history = database.get_traffic_stats_history(limit=limit)
        return {"count": len(history), "history": history}

    @app.get("/api/summary")
    def get_dashboard_summary():
        return database.get_summary_counts()

    @app.post("/api/incidents/clear")
    def clear_database_incidents():
        count = database.clear_incidents()
        return {"success": True, "cleared_count": count}

    # --- IPS FIREWALL ENDPOINTS ---
    @app.get("/api/ips/blocked")
    def get_blocked_ips_api():
        ips_mod = ips_engine.get_ips_engine()
        active_blocked = database.get_active_blocked_ips()
        history_blocked = database.get_all_blocked_ips_history(limit=50)
        return {
            "active_count": len(active_blocked),
            "active": active_blocked,
            "history": history_blocked
        }

    @app.post("/api/ips/block")
    def block_ip_api(ip: str = Query(...), threat: str = Query("MANUAL_BLOCK"), duration: int = Query(900)):
        ips_mod = ips_engine.get_ips_engine()
        success = ips_mod.block_ip(ip=ip, threat=threat, severity="HIGH", duration_seconds=duration, action_by="ADMIN_DASHBOARD")
        if not success:
            raise HTTPException(status_code=400, detail="Failed to block IP (Invalid IP, Whitelisted, or Already Blocked)")
        return {"success": True, "message": f"Successfully blocked IP {ip} for {duration} seconds"}

    @app.post("/api/ips/unblock")
    def unblock_ip_api(ip: str = Query(...)):
        ips_mod = ips_engine.get_ips_engine()
        success = ips_mod.unblock_ip(ip=ip, action_by="ADMIN_DASHBOARD")
        return {"success": success, "message": f"Unblocked IP {ip}"}

    # --- LIVE PACKET FLOWS ENDPOINT ---
    @app.get("/api/flows/active")
    def get_active_flows_api():
        # Get active flow records from queue_manager flow_aggregator if available
        active_flows_list = []
        try:
            import queue_manager
            flows_dict = queue_manager.flow_aggregator.active_flows
            for key, flow in list(flows_dict.items()):
                feats = queue_manager.flow_aggregator.generate_features(flow)
                active_flows_list.append(feats)
        except Exception:
            pass
        return {"count": len(active_flows_list), "flows": active_flows_list[:50]}

    # --- RULE REGISTRY & ML STATUS ENDPOINT ---
    @app.get("/api/rules")
    def get_rules_and_models_api():
        r_detector = RuleDetector()
        ml_detector = MLDetector()
        return {
            "heuristic_rules": [
                {"id": "R001", "name": "Port Scan Detection", "threshold": "> 20 unique ports / 5s", "severity": "HIGH"},
                {"id": "R002", "name": "Connection Rate Flood", "threshold": "> 50 connections / 60s", "severity": "HIGH"},
                {"id": "R003", "name": "SYN Flood DDoS", "threshold": "> 20 SYNs & low ACKs", "severity": "HIGH"},
                {"id": "R004", "name": "Abnormal Data Ratio", "threshold": "> 50,000 bytes/sec exfiltration", "severity": "MEDIUM"},
                {"id": "R006", "name": "UDP Flood Burst", "threshold": "> 100 UDP packets / 5s", "severity": "HIGH"},
            ],
            "ml_status": {
                "layer1_heuristics": True,
                "layer2_random_forest_loaded": ml_detector.rf_loaded,
                "layer3_self_learning_loaded": ml_detector.self_learning_available,
                "dataset_trained": "NSL-KDD (125,973 samples)",
            }
        }

    # --- CSV LOG EXPORT ENDPOINT ---
    @app.get("/api/logs/export")
    def export_incidents_csv():
        incidents = database.get_incidents(limit=1000)
        lines = ["id,timestamp,rule_id,threat,severity,confidence,source_ip,destination_ip,source_port,destination_port,protocol,evidence"]
        for inc in incidents:
            line = f'{inc.get("id")},"{inc.get("timestamp")}","{inc.get("rule_id")}","{inc.get("threat")}","{inc.get("severity")}",{inc.get("confidence")},"{inc.get("source_ip")}","{inc.get("destination_ip")}","{inc.get("source_port")}","{inc.get("destination_port")}","{inc.get("protocol")}","{inc.get("evidence")}"'
            lines.append(line)
        csv_data = "\n".join(lines)
        return PlainTextResponse(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=neurashield_incidents.csv"})

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def read_root():
        index_path = STATIC_DIR / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return {"message": "NeuraShield API is running."}


# Standard Library Fallback
def run_stdlib_server(port: int = 8080):
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class NeuraShieldHandler(BaseHTTPRequestHandler):
        def _send_json(self, data: dict, status: int = 200):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, filepath: Path, content_type: str = "text/html"):
            if not filepath.exists():
                self.send_error(404, "File Not Found")
                return
            content = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            path = parsed.path

            if path == "/api/status":
                summary = database.get_summary_counts()
                traffic_history = database.get_traffic_stats_history(limit=1)
                latest_traffic = traffic_history[0] if traffic_history else {}
                self._send_json({
                    "status": "ACTIVE",
                    "engine": "NeuraShield Core IDS Engine",
                    "version": "2.2.0",
                    "active_flows": latest_traffic.get("active_flows", 0),
                    "total_packets": latest_traffic.get("total_packets", 0),
                    "total_incidents": summary.get("total_incidents", 0),
                    "high_severity_incidents": summary.get("high_severity", 0),
                    "critical_severity_incidents": summary.get("critical_severity", 0)
                })
            elif path == "/api/topology":
                self._send_json(get_topology_data())
            elif path == "/api/incidents/grouped":
                limit = int(params.get("limit", [15])[0])
                self._send_json({"count": len(get_grouped_incidents(limit)), "alerts": get_grouped_incidents(limit)})
            elif path == "/api/incidents":
                limit = int(params.get("limit", [50])[0])
                offset = int(params.get("offset", [0])[0])
                severity = params.get("severity", [None])[0]
                threat = params.get("threat", [None])[0]
                incidents = database.get_incidents(limit=limit, offset=offset, severity=severity, threat=threat)
                self._send_json({"count": len(incidents), "incidents": incidents})
            elif path == "/api/stats/traffic":
                limit = int(params.get("limit", [30])[0])
                history = database.get_traffic_stats_history(limit=limit)
                self._send_json({"count": len(history), "history": history})
            elif path == "/api/summary":
                self._send_json(database.get_summary_counts())
            elif path == "/" or path == "/index.html":
                self._send_file(STATIC_DIR / "index.html", "text/html")
            elif path.startswith("/static/"):
                relative = path.replace("/static/", "")
                file_path = STATIC_DIR / relative
                c_type = "text/html"
                if relative.endswith(".css"):
                    c_type = "text/css"
                elif relative.endswith(".js"):
                    c_type = "application/javascript"
                self._send_file(file_path, c_type)
            else:
                self.send_error(404, "Not Found")

        def do_POST(self):
            self.send_error(404, "Not Found")

    print(f"[HTTP] Starting NeuraShield Standalone Web Server on http://0.0.0.0:{port}...")
    server = HTTPServer(("0.0.0.0", port), NeuraShieldHandler)
    server.serve_forever()


if __name__ == "__main__":
    port = 8080
    if HAS_FASTAPI:
        import uvicorn
        print(f"[FASTAPI] Starting NeuraShield FastAPI Server on http://0.0.0.0:{port}...")
        uvicorn.run("api:app", host="0.0.0.0", port=port, reload=True)
    else:
        run_stdlib_server(port=port)
