#!/usr/bin/env python3
"""
NeuraShield - Database Storage Layer
SQLite database manager for persistent incident storage, traffic metrics, and system logging.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).parent / "neurashield.db"

_local = threading.local()

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Get a thread-local SQLite database connection."""
    if not hasattr(_local, "conn") or _local.conn is None or getattr(_local, "db_path", None) != db_path:
        if hasattr(_local, "conn") and _local.conn is not None:
            try:
                _local.conn.close()
            except Exception:
                pass
        _local.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.db_path = db_path
    return _local.conn

def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize SQLite database tables and indices."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Incidents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            threat TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port TEXT,
            destination_port TEXT,
            protocol TEXT,
            evidence TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Traffic statistics table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            active_flows INTEGER NOT NULL,
            total_packets INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            packet_rate REAL NOT NULL,
            byte_rate REAL NOT NULL,
            duplicate_packets INTEGER DEFAULT 0,
            dropped_packets INTEGER DEFAULT 0
        )
    """)

    # System logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            module TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)

    # Blocked IPs table for active IPS firewall
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            threat TEXT NOT NULL,
            severity TEXT NOT NULL,
            blocked_at TEXT NOT NULL,
            unblock_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            action_by TEXT DEFAULT 'AUTO_IPS',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Schema migration check for blocked_ips columns
    cursor.execute("PRAGMA table_info(blocked_ips)")
    cols = [row[1] for row in cursor.fetchall()]
    if "ip" not in cols and "ip_address" in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN ip TEXT")
        cursor.execute("UPDATE blocked_ips SET ip = ip_address WHERE ip IS NULL OR ip = ''")
    if "is_active" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN is_active INTEGER DEFAULT 1")
    if "action_by" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN action_by TEXT DEFAULT 'AUTO_IPS'")
    if "threat" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN threat TEXT DEFAULT 'IPS_RULE'")
    if "severity" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN severity TEXT DEFAULT 'HIGH'")
    if "blocked_at" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN blocked_at TEXT DEFAULT ''")
    if "unblock_at" not in cols:
        cursor.execute("ALTER TABLE blocked_ips ADD COLUMN unblock_at TEXT DEFAULT ''")

    # Create indices for quick querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_threat ON incidents(threat)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_stats(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(is_active)")

    conn.commit()
    conn.close()


def log_incident(
    rule_id: str,
    threat: str,
    severity: str,
    confidence: int,
    source_ip: str,
    destination_ip: str,
    evidence: str,
    source_port: Optional[Any] = None,
    destination_port: Optional[Any] = None,
    protocol: Optional[Any] = None,
    timestamp: Optional[str] = None,
    db_path: Path = DB_PATH
) -> int:
    """Insert a security alert incident into the database."""
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incidents (
            timestamp, rule_id, threat, severity, confidence,
            source_ip, destination_ip, source_port, destination_port, protocol, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        rule_id,
        threat,
        severity,
        confidence,
        str(source_ip),
        str(destination_ip),
        str(source_port) if source_port is not None else "-",
        str(destination_port) if destination_port is not None else "-",
        str(protocol) if protocol is not None else "-",
        evidence
    ))
    conn.commit()
    return cursor.lastrowid or 0


def log_traffic_stats(
    active_flows: int,
    total_packets: int,
    total_bytes: int,
    packet_rate: float,
    byte_rate: float,
    duplicate_packets: int = 0,
    dropped_packets: int = 0,
    timestamp: Optional[str] = None,
    db_path: Path = DB_PATH
) -> int:
    """Insert a traffic statistics snapshot into the database."""
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO traffic_stats (
            timestamp, active_flows, total_packets, total_bytes, packet_rate, byte_rate, duplicate_packets, dropped_packets
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, active_flows, total_packets, total_bytes, packet_rate, byte_rate, duplicate_packets, dropped_packets))
    conn.commit()
    return cursor.lastrowid or 0


def log_system_event(
    level: str,
    module: str,
    message: str,
    timestamp: Optional[str] = None,
    db_path: Path = DB_PATH
) -> None:
    """Log a system execution event."""
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO system_logs (timestamp, level, module, message)
        VALUES (?, ?, ?, ?)
    """, (timestamp, level, module, message))
    conn.commit()


def get_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    threat: Optional[str] = None,
    db_path: Path = DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve recent incidents from the database."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    query = "SELECT * FROM incidents"
    params: List[Any] = []
    where_clauses = []

    if severity:
        where_clauses.append("severity = ?")
        params.append(severity.upper())
    if threat:
        where_clauses.append("threat = ?")
        params.append(threat.upper())

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_traffic_stats_history(
    limit: int = 30,
    db_path: Path = DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve recent traffic statistics snapshots for charting."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    return [dict(row) for row in reversed(rows)]


def clear_incidents(db_path: Path = DB_PATH) -> int:
    """Clear all historical incidents and traffic stats from database."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM traffic_stats")
    conn.commit()
    return cursor.rowcount or 0


def get_recent_active_incidents(seconds: int = 60, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve incidents created within the last N seconds for live alert status."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM incidents 
        WHERE datetime(created_at) >= datetime('now', '-' || ? || ' seconds')
        ORDER BY id DESC
    """, (seconds,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_summary_counts(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Get aggregated metrics summary for dashboard display."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM incidents")
    total_incidents = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM incidents WHERE severity = 'HIGH'")
    high_severity = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM incidents WHERE severity = 'CRITICAL'")
    critical_severity = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM blocked_ips WHERE is_active = 1")
    blocked_count = cursor.fetchone()["total"]

    cursor.execute("SELECT threat, COUNT(*) as count FROM incidents GROUP BY threat ORDER BY count DESC LIMIT 5")
    top_threats = [dict(row) for row in cursor.fetchall()]

    return {
        "total_incidents": total_incidents,
        "high_severity": high_severity,
        "critical_severity": critical_severity,
        "blocked_ips_count": blocked_count,
        "top_threats": top_threats,
    }


def log_blocked_ip(
    ip: str,
    threat: str,
    severity: str,
    blocked_at: str,
    unblock_at: str,
    action_by: str = "AUTO_IPS",
    db_path: Path = DB_PATH
) -> int:
    """Log an IP block action in the database with dynamic column support."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(blocked_ips)")
    cols = [row[1] for row in cursor.fetchall()]

    extra_cols = []
    extra_vals = []

    if "ip_address" in cols:
        extra_cols.append("ip_address")
        extra_vals.append(ip)
    if "reason" in cols:
        extra_cols.append("reason")
        extra_vals.append(threat)
    if "expires_at" in cols:
        extra_cols.append("expires_at")
        extra_vals.append(unblock_at)
    if "confidence" in cols:
        extra_cols.append("confidence")
        extra_vals.append(100)
    if "status" in cols:
        extra_cols.append("status")
        extra_vals.append("ACTIVE")

    base_cols = ["ip", "threat", "severity", "blocked_at", "unblock_at", "is_active", "action_by"]
    base_vals = [ip, threat, severity, blocked_at, unblock_at, 1, action_by]

    all_cols = base_cols + extra_cols
    all_vals = base_vals + extra_vals
    placeholders = ", ".join(["?"] * len(all_vals))

    sql = f"INSERT INTO blocked_ips ({', '.join(all_cols)}) VALUES ({placeholders})"
    cursor.execute(sql, all_vals)
    conn.commit()
    return cursor.lastrowid or 0


def deactivate_blocked_ip(ip: str, db_path: Path = DB_PATH) -> int:
    """Mark an IP as unblocked/inactive in the database."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(blocked_ips)")
    cols = [row[1] for row in cursor.fetchall()]

    if "ip" in cols and "ip_address" in cols:
        cursor.execute("""
            UPDATE blocked_ips SET is_active = 0 WHERE (ip = ? OR ip_address = ?) AND is_active = 1
        """, (ip, ip))
    elif "ip" in cols:
        cursor.execute("""
            UPDATE blocked_ips SET is_active = 0 WHERE ip = ? AND is_active = 1
        """, (ip,))
    else:
        cursor.execute("""
            UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ? AND is_active = 1
        """, (ip,))

    conn.commit()
    return cursor.rowcount or 0


def get_active_blocked_ips(db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all currently active blocked IPs."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_all_blocked_ips_history(limit: int = 50, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all historical blocked IP records."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM blocked_ips ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def clear_incidents(db_path: Path = DB_PATH) -> int:
    """Clear all logged incidents from database."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents")
    count = cursor.rowcount
    conn.commit()
    return count


if __name__ == "__main__":
    init_db()
    print("[DB] SQLite database initialized successfully at:", DB_PATH)
