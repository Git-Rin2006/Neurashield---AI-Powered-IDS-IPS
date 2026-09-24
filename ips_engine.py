#!/usr/bin/env python3
"""
NeuraShield - Production-Grade Active Intrusion Prevention System (IPS)
Real-time Linux iptables firewall manager with automated quarantine auto-unblocking,
input validation, protected IP whitelisting, and SQLite audit logging.
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import threading
import subprocess
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set

import database

# Whitelisted IPs that can NEVER be blocked (prevents self-lockout)
WHITELISTED_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "10.10.10.1",   # Gateway VM3 interface ens37
    "10.10.20.1",   # Gateway VM3 interface ens38
    "10.1.1.101",   # Gateway VM3 interface ens33
}

# Default quarantine duration for automatically blocked IPs (15 minutes = 900 seconds)
DEFAULT_QUARANTINE_SECONDS = 900


class IPSEngine:
    """
    Production-Grade Active IPS Engine.
    
    Interacts with Linux `iptables` to block and quarantine malicious source hosts.
    Thread-safe, resilient against subprocess errors, and features automatic background unblocking.
    """

    def __init__(self, db_path=database.DB_PATH, default_duration: int = DEFAULT_QUARANTINE_SECONDS):
        self.db_path = db_path
        self.default_duration = default_duration
        self.lock = threading.Lock()

        # Check if iptables command is available on system
        self.iptables_path = shutil.which("iptables")
        self.is_linux = sys.platform.startswith("linux") and self.iptables_path is not None

        # Start background quarantine cleanup worker thread
        self.stop_event = threading.Event()
        self.worker_thread = threading.Thread(
            target=self._quarantine_cleanup_worker,
            name="NeuraShield-IPS-QuarantineWorker",
            daemon=True
        )
        self.worker_thread.start()
        print(f"[IPS ENGINE] ✓ Production IPS Active (iptables available: {self.is_linux})")

    # --------------------------------------------------------
    # VALIDATION & SAFETY CHECKS
    # --------------------------------------------------------

    def is_valid_ip(self, ip_str: str) -> bool:
        """Validate if a string is a valid, non-multicast, non-unspecified IP address."""
        if not ip_str or not isinstance(ip_str, str):
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return False
            return True
        except ValueError:
            return False

    def is_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP is in the immutable safety whitelist."""
        if not self.is_valid_ip(ip_str):
            return True # Treat invalid IPs as protected to avoid blocking errors
        ip_clean = str(ipaddress.ip_address(ip_str.strip()))
        return ip_clean in WHITELISTED_IPS

    # --------------------------------------------------------
    # IPTABLES EXECUTOR (SECURE SUBPROCESS)
    # --------------------------------------------------------

    def _run_iptables_cmd(self, args: List[str]) -> bool:
        """
        Execute iptables command securely without shell=True.
        Supports fallback if non-root permissions.
        """
        if not self.is_linux:
            print(f"[IPS SIMULATED] Executed iptables {' '.join(args)}")
            return True

        cmd = ["iptables"] + args
        if os.geteuid() != 0:
            cmd = ["sudo", "-n", "iptables"] + args

        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return True
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                # If rule check fails (-C), return False silently
                if "-C" not in args:
                    print(f"[IPS FIREWALL WARNING] iptables returncode={res.returncode}: {err_msg}")
                return False
        except Exception as exc:
            print(f"[IPS FIREWALL ERROR] Command failed ({' '.join(cmd)}): {exc}")
            return False

    def _is_ip_blocked_in_iptables(self, ip: str) -> bool:
        """Check if IP rule already exists in iptables FORWARD or INPUT chains."""
        forward_check = self._run_iptables_cmd(["-C", "FORWARD", "-s", ip, "-j", "DROP"])
        input_check = self._run_iptables_cmd(["-C", "INPUT", "-s", ip, "-j", "DROP"])
        return forward_check or input_check

    # --------------------------------------------------------
    # CORE IPS BLOCK / UNBLOCK LOGIC
    # --------------------------------------------------------

    def block_ip(
        self,
        ip: str,
        threat: str = "UNKNOWN_THREAT",
        severity: str = "HIGH",
        duration_seconds: Optional[int] = None,
        action_by: str = "AUTO_IPS"
    ) -> bool:
        """
        Active block an IP address across FORWARD and INPUT chains in real-time,
        logging quarantine metadata to database.
        """
        ip = ip.strip()
        if not self.is_valid_ip(ip):
            print(f"[IPS REJECTED] Cannot block invalid IP address: {ip}")
            return False

        if self.is_whitelisted(ip):
            print(f"[IPS WHITELIST] IP {ip} is whitelisted — blocking bypassed for safety.")
            return False

        duration = duration_seconds or self.default_duration
        blocked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        unblock_dt = datetime.now() + timedelta(seconds=duration)
        unblock_at = unblock_dt.strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            # Check if already active in DB
            active_blocks = database.get_active_blocked_ips(db_path=self.db_path)
            if any(b.get("ip") == ip for b in active_blocks):
                print(f"[IPS ALREADY BLOCKED] IP {ip} is already actively quarantined.")
                return True

            # Execute real-time iptables DROP rules
            success_forward = self._run_iptables_cmd(["-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
            success_input = self._run_iptables_cmd(["-I", "INPUT", "1", "-s", ip, "-j", "DROP"])

            # Save to SQLite database
            row_id = database.log_blocked_ip(
                ip=ip,
                threat=threat,
                severity=severity,
                blocked_at=blocked_at,
                unblock_at=unblock_at,
                action_by=action_by,
                db_path=self.db_path
            )

            print(f"[IPS ACTIVE BLOCK] ✓ Blocked IP {ip} ({threat}) | Quarantine: {duration}s | DB Row #{row_id}")
            database.log_system_event(
                level="WARNING",
                module="IPS",
                message=f"Quarantined IP {ip} for {duration}s due to threat {threat} (Severity: {severity})",
                db_path=self.db_path
            )
            return True

    def unblock_ip(self, ip: str, action_by: str = "AUTO_IPS") -> bool:
        """Remove iptables DROP rules for an IP and mark unblocked in database."""
        ip = ip.strip()
        with self.lock:
            # Remove from iptables
            self._run_iptables_cmd(["-D", "FORWARD", "-s", ip, "-j", "DROP"])
            self._run_iptables_cmd(["-D", "INPUT", "-s", ip, "-j", "DROP"])

            # Deactivate in database
            deactivated = database.deactivate_blocked_ip(ip=ip, db_path=self.db_path)

            print(f"[IPS UNBLOCK] ✓ Unblocked IP {ip} (Action by: {action_by}) | DB records updated: {deactivated}")
            database.log_system_event(
                level="INFO",
                module="IPS",
                message=f"Unblocked IP {ip} from firewall quarantine (Action by: {action_by})",
                db_path=self.db_path
            )
            return True

    def evaluate_alert(self, alert: Any) -> bool:
        """
        Evaluate a security alert from Rule or ML engine and execute automatic blocking
        if severity is HIGH or CRITICAL.
        """
        if not alert or not hasattr(alert, "source_ip") or not hasattr(alert, "severity"):
            return False

        severity = str(alert.severity).upper()
        if severity in ["HIGH", "CRITICAL"]:
            src_ip = str(alert.source_ip).strip()
            threat = getattr(alert, "threat", "SUSPICIOUS_BEHAVIOR")
            return self.block_ip(ip=src_ip, threat=threat, severity=severity, action_by="AUTO_ENGINE")
        return False

    # --------------------------------------------------------
    # QUARANTINE CLEANUP WORKER
    # --------------------------------------------------------

    def _quarantine_cleanup_worker(self):
        """Background thread worker to unblock IPs whose quarantine period has expired."""
        while not self.stop_event.wait(10.0):
            try:
                active_blocks = database.get_active_blocked_ips(db_path=self.db_path)
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                for block in active_blocks:
                    unblock_at = block.get("unblock_at")
                    ip = block.get("ip")

                    if unblock_at and now_str >= unblock_at and ip:
                        print(f"[IPS AUTO-UNBLOCK] Quarantine expired for IP {ip} — unblocking.")
                        self.unblock_ip(ip=ip, action_by="QUARANTINE_EXPIRED")
            except Exception as exc:
                print(f"[IPS QUARANTINE WORKER ERROR] {exc}")


# Global singleton instance
_ips_instance: Optional[IPSEngine] = None
_ips_lock = threading.Lock()


def get_ips_engine(db_path=database.DB_PATH) -> IPSEngine:
    """Get global IPSEngine singleton instance."""
    global _ips_instance
    with _ips_lock:
        if _ips_instance is None:
            _ips_instance = IPSEngine(db_path=db_path)
        return _ips_instance
