"""
NeuraShield - Rule-Based Threat Detection Engine
Stage 4

Pipeline position:

Stage 1 - Live Network Monitoring
        |
        v
Stage 2 - Packet Queue + Metadata
        |
        v
Stage 3 - Flow Aggregation + Feature Generation
        |
        v
Stage 4 - Rule-Based Threat Detection
        |
        v
Stage 5 - Machine Learning

Architecture principles:
- Stage 4 consumes Stage 3 flow features.
- No raw packets are processed here.
- No payload inspection.
- No raw packet storage.
- Stage 3 owns flow aggregation.
- Stage 4 owns threat-rule decisions.
- Rolling state is used only where a rule requires
  cross-flow behavioral analysis.
- Alert cooldowns prevent alert flooding.
- Thread-safe state.
- Compatible with both dictionaries and objects.
"""


from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Dict, List, Optional
import time


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# R001 - PORT SCAN
#
# Stage 3 already calculates:
#
#     unique_destination_ports
#
# over the configured short source-level window.
#
# Project specification:
#
#     More than 20 unique destination ports
#     within five seconds.
#
# Therefore Stage 4 consumes the Stage 3 feature instead
# of maintaining another independent port-scan history.
# ------------------------------------------------------------

PORT_SCAN_PORTS = 20
PORT_SCAN_WINDOW = 5.0
PORT_SCAN_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R002 - CONNECTION FLOOD
#
# Configurable Stage 4 heuristic:
#
#     30 completed flow events to the same service
#     within 60 seconds.
#
# A Stage 3 finalized flow is treated as one connection
# event for this rule.
# ------------------------------------------------------------

CONNECTION_FLOOD_CONNECTIONS = 30
CONNECTION_FLOOD_WINDOW = 60.0
CONNECTION_FLOOD_COOLDOWN = 30.0


# ------------------------------------------------------------
# R003 - SYN FLOOD
#
# Excessive SYN activity in a flow.
# ------------------------------------------------------------

SYN_FLOOD_MIN_SYN = 20
SYN_FLOOD_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R004 - TCP RST ABUSE
# ------------------------------------------------------------

RST_FLOOD_MIN_RST = 20
RST_FLOOD_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R005 - ICMP FLOOD
# ------------------------------------------------------------

ICMP_FLOOD_MIN_PACKETS = 100
ICMP_FLOOD_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R006 - UDP FLOOD
# ------------------------------------------------------------

UDP_FLOOD_MIN_PACKETS = 100
UDP_FLOOD_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R007 - HIGH PACKET RATE
# ------------------------------------------------------------

HIGH_PACKET_RATE = 100.0
HIGH_PACKET_RATE_MIN_PACKETS = 100
HIGH_PACKET_RATE_MIN_DURATION = 2.0
HIGH_PACKET_RATE_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# R008 - HIGH BANDWIDTH
# ------------------------------------------------------------

HIGH_BYTE_RATE = 1_000_000.0
HIGH_BANDWIDTH_MIN_BYTES = 5_000_000
HIGH_BANDWIDTH_MIN_PACKETS = 500
HIGH_BANDWIDTH_MIN_DURATION = 5.0
HIGH_BANDWIDTH_ALERT_COOLDOWN = 30.0


# ------------------------------------------------------------
# MEMORY LIMITS
# ------------------------------------------------------------

MAX_CONNECTION_HISTORY = 100000


# ============================================================
# SECURITY ALERT
# ============================================================

@dataclass
class SecurityAlert:
    """
    Standardized Stage 4 security alert.

    This object is intentionally simple so that later stages
    can consume it easily.

    Compatible with:
        alert.rule_id
        alert["rule_id"]
        alert.get("rule_id")
        alert.to_dict()
    """

    rule_id: str
    threat: str
    severity: str
    confidence: int
    source_ip: str
    destination_ip: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def get(
        self,
        key: str,
        default: Any = None
    ) -> Any:

        return getattr(
            self,
            key,
            default
        )

    def __getitem__(
        self,
        key: str
    ) -> Any:

        return getattr(
            self,
            key
        )


# ============================================================
# RULE DETECTOR
# ============================================================

class RuleDetector:

    def __init__(self):

        self.lock = Lock()

        # ----------------------------------------------------
        # R002 CONNECTION FLOOD HISTORY
        #
        # Key:
        #
        #   (
        #       source_ip,
        #       destination_ip,
        #       protocol,
        #       destination_port
        #   )
        #
        # Value:
        #
        #   deque(timestamp)
        #
        # Each timestamp represents one finalized Stage 3
        # flow event.
        # ----------------------------------------------------

        self.connection_history = defaultdict(deque)

        # ----------------------------------------------------
        # R002 ALERT COOLDOWN
        # ----------------------------------------------------

        self.connection_alert_time = {}

        # ----------------------------------------------------
        # ALERT COOLDOWNS
        #
        # Key:
        #
        #   (
        #       rule_id,
        #       source_ip,
        #       destination_ip
        #   )
        # ----------------------------------------------------

        self.alert_times = {}

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        self.total_flows_analyzed = 0

        self.total_alerts_generated = 0

        self.rule_trigger_counts = defaultdict(int)

    # ========================================================
    # GENERAL HELPERS
    # ========================================================

    @staticmethod
    def _get(
        flow: Any,
        key: str,
        default: Any = None
    ) -> Any:

        """
        Retrieve a value from either:

            dict

        or:

            object
        """

        if isinstance(
            flow,
            dict
        ):

            return flow.get(
                key,
                default
            )

        return getattr(
            flow,
            key,
            default
        )

    # --------------------------------------------------------

    @staticmethod
    def _protocol_name(
        flow: Any
    ) -> str:

        """
        Resolve protocol name from Stage 3 features.

        Supports both:

            protocol_name

        and:

            protocol number
        """

        protocol_name = RuleDetector._get(
            flow,
            "protocol_name",
            None
        )

        if protocol_name:

            return str(
                protocol_name
            ).upper()

        protocol = RuleDetector._get(
            flow,
            "protocol",
            None
        )

        if protocol == 6:

            return "TCP"

        if protocol == 17:

            return "UDP"

        if protocol == 1:

            return "ICMP"

        if protocol is None:

            return ""

        return str(
            protocol
        ).upper()

    # --------------------------------------------------------

    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0
    ) -> int:

        try:

            return int(
                value or 0
            )

        except (
            TypeError,
            ValueError
        ):

            return default

    # --------------------------------------------------------

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0
    ) -> float:

        try:

            return float(
                value or 0
            )

        except (
            TypeError,
            ValueError
        ):

            return default

    # --------------------------------------------------------

    @staticmethod
    def _now() -> float:

        return time.monotonic()

    # ========================================================
    # ALERT COOLDOWN HELPER
    # ========================================================

    def _cooldown_active(
        self,
        rule_id: str,
        source_ip: str,
        destination_ip: str,
        cooldown: float
    ) -> bool:

        key = (
            rule_id,
            str(source_ip),
            str(destination_ip)
        )

        now = self._now()

        last_alert = self.alert_times.get(
            key
        )

        if (
            last_alert is not None
            and
            now - last_alert < cooldown
        ):

            return True

        self.alert_times[key] = now

        return False

    # ========================================================
    # R001 - PORT SCAN
    # ========================================================

    def _check_port_scan(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        """
        Detect a port scan using the feature generated
        by Stage 3.

        Stage 3 feature:

            unique_destination_ports

        Project rule:

            One source IP contacts more than twenty
            unique destination ports within five seconds.

        Stage 4 does NOT reconstruct the five-second
        destination-port history.
        """

        source_ip = self._get(
            flow,
            "source_ip"
        )

        destination_ip = self._get(
            flow,
            "destination_ip"
        )

        protocol = self._protocol_name(
            flow
        )

        if not source_ip or not destination_ip:

            return None

        if protocol not in (
            "TCP",
            "UDP"
        ):

            return None

        unique_destination_ports = self._safe_int(
            self._get(
                flow,
                "unique_destination_ports",
                0
            )
        )

        # ----------------------------------------------------
        # "MORE THAN 20"
        #
        # Therefore:
        #
        #     21+
        # ----------------------------------------------------

        if unique_destination_ports <= PORT_SCAN_PORTS:

            return None

        if self._cooldown_active(
            "R001",
            source_ip,
            destination_ip,
            PORT_SCAN_ALERT_COOLDOWN
        ):

            return None

        return SecurityAlert(
            rule_id="R001",
            threat="PORT_SCAN",
            severity="HIGH",
            confidence=95,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"Unique destination ports contacted: "
                f"{unique_destination_ports} "
                f"(threshold: more than "
                f"{PORT_SCAN_PORTS} within "
                f"{PORT_SCAN_WINDOW:.0f} seconds)"
            )
        )

    # ========================================================
    # R002 - CONNECTION FLOOD
    # ========================================================

    def _check_connection_flood(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        """
        Detect repeated completed flow events to the same
        destination service.

        Stage 3 provides finalized flows.

        Each finalized flow is treated as one connection
        event for this rule.

        This rule is intentionally separate from Stage 3's
        connection_frequency because this rule focuses on
        repeated activity against the same service.
        """

        source_ip = self._get(
            flow,
            "source_ip"
        )

        destination_ip = self._get(
            flow,
            "destination_ip"
        )

        destination_port = self._get(
            flow,
            "destination_port"
        )

        protocol = self._protocol_name(
            flow
        )

        if not source_ip or not destination_ip:

            return None

        if destination_port in (
            None,
            "-",
            0
        ):

            return None

        if protocol not in (
            "TCP",
            "UDP"
        ):

            return None

        try:

            destination_port = int(
                destination_port
            )

        except (
            TypeError,
            ValueError
        ):

            return None

        key = (
            str(source_ip),
            str(destination_ip),
            protocol,
            destination_port
        )

        now = self._now()

        with self.lock:

            history = self.connection_history[
                key
            ]

            # One finalized Stage 3 flow = one event.
            history.append(
                now
            )

            cutoff = (
                now
                -
                CONNECTION_FLOOD_WINDOW
            )

            while (
                history
                and
                history[0] < cutoff
            ):

                history.popleft()

            connection_count = len(
                history
            )

            if connection_count < (
                CONNECTION_FLOOD_CONNECTIONS
            ):

                return None

            last_alert = self.connection_alert_time.get(
                key
            )

            if (
                last_alert is not None
                and
                now - last_alert
                < CONNECTION_FLOOD_COOLDOWN
            ):

                return None

            self.connection_alert_time[
                key
            ] = now

            # ------------------------------------------------
            # BOUNDED MEMORY CLEANUP
            # ------------------------------------------------

            if len(
                self.connection_history
            ) > MAX_CONNECTION_HISTORY:

                self._cleanup_connection_history(
                    now
                )

            return SecurityAlert(
                rule_id="R002",
                threat="CONNECTION_FLOOD",
                severity="HIGH",
                confidence=90,
                source_ip=str(
                    source_ip
                ),
                destination_ip=str(
                    destination_ip
                ),
                evidence=(
                    f"Repeated connections to "
                    f"destination port "
                    f"{destination_port}: "
                    f"{connection_count} events "
                    f"in {CONNECTION_FLOOD_WINDOW:.0f} "
                    f"seconds "
                    f"(threshold: "
                    f"{CONNECTION_FLOOD_CONNECTIONS})"
                )
            )

    # --------------------------------------------------------

    def _cleanup_connection_history(
        self,
        now: float
    ) -> None:

        """
        Remove stale or empty connection histories.
        """

        cutoff = (
            now
            -
            CONNECTION_FLOOD_WINDOW
        )

        stale_keys = []

        for key, history in (
            self.connection_history.items()
        ):

            while (
                history
                and
                history[0] < cutoff
            ):

                history.popleft()

            if not history:

                stale_keys.append(
                    key
                )

        for key in stale_keys:

            self.connection_history.pop(
                key,
                None
            )

    # ========================================================
    # R003 - SYN FLOOD
    # ========================================================

    def _check_syn_flood(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        """
        Detect excessive SYN activity reported by Stage 3.

        Stage 3 provides syn_count and ack_count.
        """

        protocol = self._protocol_name(
            flow
        )

        if protocol != "TCP":

            return None

        syn_count = self._safe_int(
            self._get(
                flow,
                "syn_count",
                0
            )
        )

        ack_count = self._safe_int(
            self._get(
                flow,
                "ack_count",
                0
            )
        )

        if syn_count < SYN_FLOOD_MIN_SYN:

            return None

        # A high SYN count with substantially fewer ACKs
        # is more suspicious than balanced TCP traffic.
        if ack_count > syn_count:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R003",
            source_ip,
            destination_ip,
            SYN_FLOOD_ALERT_COOLDOWN
        ):

            return None

        return SecurityAlert(
            rule_id="R003",
            threat="SYN_FLOOD",
            severity="HIGH",
            confidence=95,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"SYN packets: {syn_count} "
                f"(threshold: "
                f"{SYN_FLOOD_MIN_SYN}), "
                f"ACK packets: {ack_count}"
            )
        )

    # ========================================================
    # R004 - TCP RST ABUSE
    # ========================================================

    def _check_rst_abuse(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        protocol = self._protocol_name(
            flow
        )

        if protocol != "TCP":

            return None

        rst_count = self._safe_int(
            self._get(
                flow,
                "rst_count",
                0
            )
        )

        if rst_count < RST_FLOOD_MIN_RST:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R004",
            source_ip,
            destination_ip,
            RST_FLOOD_ALERT_COOLDOWN
        ):

            return None

        return SecurityAlert(
            rule_id="R004",
            threat="TCP_RST_ABUSE",
            severity="HIGH",
            confidence=90,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"RST packets: {rst_count} "
                f"(threshold: "
                f"{RST_FLOOD_MIN_RST})"
            )
        )

    # ========================================================
    # R005 - ICMP FLOOD
    # ========================================================

    def _check_icmp_flood(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        protocol = self._protocol_name(
            flow
        )

        if protocol != "ICMP":

            return None

        total_packets = self._safe_int(
            self._get(
                flow,
                "total_packets",
                0
            )
        )

        if total_packets < ICMP_FLOOD_MIN_PACKETS:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R005",
            source_ip,
            destination_ip,
            ICMP_FLOOD_ALERT_COOLDOWN
        ):

            return None

        return SecurityAlert(
            rule_id="R005",
            threat="ICMP_FLOOD",
            severity="HIGH",
            confidence=95,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"ICMP packets: {total_packets} "
                f"(threshold: "
                f"{ICMP_FLOOD_MIN_PACKETS})"
            )
        )

    # ========================================================
    # R006 - UDP FLOOD
    # ========================================================

    def _check_udp_flood(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        protocol = self._protocol_name(
            flow
        )

        if protocol != "UDP":

            return None

        total_packets = self._safe_int(
            self._get(
                flow,
                "total_packets",
                0
            )
        )

        if total_packets < UDP_FLOOD_MIN_PACKETS:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R006",
            source_ip,
            destination_ip,
            UDP_FLOOD_ALERT_COOLDOWN
        ):

            return None

        return SecurityAlert(
            rule_id="R006",
            threat="UDP_FLOOD",
            severity="HIGH",
            confidence=95,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"UDP packets: {total_packets} "
                f"(threshold: "
                f"{UDP_FLOOD_MIN_PACKETS})"
            )
        )

    # ========================================================
    # R007 - HIGH PACKET RATE
    # ========================================================

    def _check_high_packet_rate(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        """
        Detect unusually high packet rates.

        Stage 3 provides packet_rate.

        Unlike the previous implementation, this rule is
        not unnecessarily restricted to TCP.
        """

        packet_rate = self._safe_float(
            self._get(
                flow,
                "packet_rate",
                0
            )
        )

        total_packets = self._safe_int(
            self._get(
                flow,
                "total_packets",
                0
            )
        )

        duration = self._safe_float(
            self._get(
                flow,
                "duration",
                0
            )
        )

        if packet_rate < HIGH_PACKET_RATE:

            return None

        # ----------------------------------------------------
        # Require sufficient observation.
        # ----------------------------------------------------

        sustained = (
            total_packets >=
            HIGH_PACKET_RATE_MIN_PACKETS
            and
            duration >=
            HIGH_PACKET_RATE_MIN_DURATION
        )

        if not sustained:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R007",
            source_ip,
            destination_ip,
            HIGH_PACKET_RATE_ALERT_COOLDOWN
        ):

            return None

        protocol = self._protocol_name(
            flow
        )

        return SecurityAlert(
            rule_id="R007",
            threat="HIGH_PACKET_RATE",
            severity="MEDIUM",
            confidence=85,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"Protocol: {protocol}, "
                f"Packet rate: "
                f"{packet_rate:.2f} packets/sec, "
                f"Total packets: {total_packets}, "
                f"Duration: {duration:.2f} sec"
            )
        )

    # ========================================================
    # R008 - HIGH BANDWIDTH
    # ========================================================

    def _check_high_bandwidth(
        self,
        flow: Any
    ) -> Optional[SecurityAlert]:

        """
        Detect unusually high byte-rate traffic.

        Stage 3 provides:

            byte_rate
            total_bytes
            total_packets
            duration
        """

        byte_rate = self._safe_float(
            self._get(
                flow,
                "byte_rate",
                0
            )
        )

        total_bytes = self._safe_int(
            self._get(
                flow,
                "total_bytes",
                0
            )
        )

        total_packets = self._safe_int(
            self._get(
                flow,
                "total_packets",
                0
            )
        )

        duration = self._safe_float(
            self._get(
                flow,
                "duration",
                0
            )
        )

        if byte_rate < HIGH_BYTE_RATE:

            return None

        if total_bytes < HIGH_BANDWIDTH_MIN_BYTES:

            return None

        if total_packets < HIGH_BANDWIDTH_MIN_PACKETS:

            return None

        if duration < HIGH_BANDWIDTH_MIN_DURATION:

            return None

        source_ip = self._get(
            flow,
            "source_ip",
            "-"
        )

        destination_ip = self._get(
            flow,
            "destination_ip",
            "-"
        )

        if self._cooldown_active(
            "R008",
            source_ip,
            destination_ip,
            HIGH_BANDWIDTH_ALERT_COOLDOWN
        ):

            return None

        protocol = self._protocol_name(
            flow
        )

        return SecurityAlert(
            rule_id="R008",
            threat="HIGH_BANDWIDTH_USAGE",
            severity="HIGH",
            confidence=90,
            source_ip=str(
                source_ip
            ),
            destination_ip=str(
                destination_ip
            ),
            evidence=(
                f"Protocol: {protocol}, "
                f"Byte rate: "
                f"{byte_rate:.2f} bytes/sec, "
                f"Total bytes: {total_bytes}, "
                f"Packets: {total_packets}, "
                f"Duration: {duration:.2f} sec"
            )
        )

    # ========================================================
    # RUN ALL RULES
    # ========================================================

    def check_rules(
        self,
        flow: Any
    ) -> List[SecurityAlert]:

        """
        Analyze ONE finalized Stage 3 flow.

        Stage 4 never receives raw packets.
        """

        with self.lock:

            self.total_flows_analyzed += 1

        alerts: List[SecurityAlert] = []

        # ----------------------------------------------------
        # R001
        # ----------------------------------------------------

        alert = self._check_port_scan(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R002
        # ----------------------------------------------------

        alert = self._check_connection_flood(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R003
        # ----------------------------------------------------

        alert = self._check_syn_flood(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R004
        # ----------------------------------------------------

        alert = self._check_rst_abuse(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R005
        # ----------------------------------------------------

        alert = self._check_icmp_flood(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R006
        # ----------------------------------------------------

        alert = self._check_udp_flood(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R007
        # ----------------------------------------------------

        alert = self._check_high_packet_rate(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # R008
        # ----------------------------------------------------

        alert = self._check_high_bandwidth(
            flow
        )

        if alert:

            alerts.append(
                alert
            )

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        if alerts:

            with self.lock:

                self.total_alerts_generated += len(
                    alerts
                )

                for alert in alerts:

                    self.rule_trigger_counts[
                        alert.rule_id
                    ] += 1

        return alerts

    # ========================================================
    # PIPELINE COMPATIBILITY
    # ========================================================

    def analyze(
        self,
        flow: Any
    ) -> List[SecurityAlert]:

        return self.check_rules(
            flow
        )

    # --------------------------------------------------------

    def detect(
        self,
        flow: Any
    ) -> List[SecurityAlert]:

        return self.analyze(
            flow
        )

    # ========================================================
    # STATISTICS
    # ========================================================

    def statistics(
        self
    ) -> Dict[str, Any]:

        with self.lock:

            return {
                "total_flows_analyzed":
                    self.total_flows_analyzed,

                "total_alerts_generated":
                    self.total_alerts_generated,

                "rule_trigger_counts":
                    dict(
                        self.rule_trigger_counts
                    ),

                "connection_flood_tracked_services":
                    len(
                        self.connection_history
                    ),
            }


# ============================================================
# TEST FLOW CREATOR
# ============================================================

def make_flow(
    source_ip="10.10.10.10",
    destination_ip="10.10.20.10",
    source_port=50000,
    destination_port=443,
    protocol=6,
    protocol_name="TCP",
    total_packets=10,
    total_bytes=10000,
    duration=1.0,
    syn_count=1,
    ack_count=5,
    fin_count=0,
    rst_count=0,
    unique_destination_ports=1,
    connection_frequency=1,
    packet_rate=10.0,
    byte_rate=10000.0,
):

    """
    Create a Stage 3-compatible feature dictionary.

    This mirrors the type of feature object consumed by
    Stage 4.
    """

    return {
        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "source_port":
            source_port,

        "destination_port":
            destination_port,

        "protocol":
            protocol,

        "protocol_name":
            protocol_name,

        "total_packets":
            total_packets,

        "total_bytes":
            total_bytes,

        "duration":
            duration,

        "syn_count":
            syn_count,

        "ack_count":
            ack_count,

        "fin_count":
            fin_count,

        "rst_count":
            rst_count,

        "unique_destination_ports":
            unique_destination_ports,

        "connection_frequency":
            connection_frequency,

        "packet_rate":
            packet_rate,

        "byte_rate":
            byte_rate,
    }


# ============================================================
# SELF TEST
# ============================================================

def run_self_test():

    passed = 0
    failed = 0

    def check(
        name: str,
        condition: bool
    ):

        nonlocal passed
        nonlocal failed

        if condition:

            print(
                f"[PASS] {name}"
            )

            passed += 1

        else:

            print(
                f"[FAIL] {name}"
            )

            failed += 1

    # ========================================================
    # R001 - PORT SCAN
    # ========================================================

    detector = RuleDetector()

    port_scan_flow = make_flow(
        protocol=6,
        protocol_name="TCP",
        unique_destination_ports=21,
        destination_port=443,
    )

    alerts = detector.analyze(
        port_scan_flow
    )

    check(
        "R001 port scan detection",
        any(
            alert.rule_id == "R001"
            for alert in alerts
        )
    )

    # Exactly 20 must NOT trigger because the project says
    # "more than twenty".

    detector_20 = RuleDetector()

    exactly_20_flow = make_flow(
        unique_destination_ports=20
    )

    alerts_20 = detector_20.analyze(
        exactly_20_flow
    )

    check(
        "R001 threshold boundary",
        not any(
            alert.rule_id == "R001"
            for alert in alerts_20
        )
    )

    # ========================================================
    # R001 - COOLDOWN
    # ========================================================

    detector_cooldown = RuleDetector()

    first_alerts = detector_cooldown.analyze(
        port_scan_flow
    )

    second_alerts = detector_cooldown.analyze(
        port_scan_flow
    )

    r001_first = [
        alert
        for alert in first_alerts
        if alert.rule_id == "R001"
    ]

    r001_second = [
        alert
        for alert in second_alerts
        if alert.rule_id == "R001"
    ]

    check(
        "R001 alert cooldown",
        len(r001_first) == 1
        and
        len(r001_second) == 0
    )

    # ========================================================
    # R002 - CONNECTION FLOOD
    # ========================================================

    flood_detector = RuleDetector()

    flood_alerts = []

    for i in range(
        CONNECTION_FLOOD_CONNECTIONS
    ):

        flow = make_flow(
            source_port=40000 + i,
            destination_port=80,
            protocol=6,
            protocol_name="TCP",
        )

        alerts = flood_detector.analyze(
            flow
        )

        flood_alerts.extend(
            alerts
        )

    r002_alerts = [
        alert
        for alert in flood_alerts
        if alert.rule_id == "R002"
    ]

    check(
        "R002 connection flood detection",
        len(r002_alerts) == 1
    )

    # ========================================================
    # R002 - PORT SCAN SHOULD NOT TRIGGER FLOOD
    # ========================================================

    scan_detector = RuleDetector()

    unwanted_r002 = False

    for port in range(
        1,
        11
    ):

        flow = make_flow(
            destination_port=port,
            source_port=50000 + port,
            protocol=6,
            protocol_name="TCP",
            unique_destination_ports=port,
        )

        alerts = scan_detector.analyze(
            flow
        )

        for alert in alerts:

            if alert.rule_id == "R002":

                unwanted_r002 = True

    check(
        "R002 does not trigger from different ports",
        not unwanted_r002
    )

    # ========================================================
    # R003 - SYN FLOOD
    # ========================================================

    syn_detector = RuleDetector()

    syn_flow = make_flow(
        syn_count=25,
        ack_count=0,
        total_packets=25,
    )

    syn_alerts = syn_detector.analyze(
        syn_flow
    )

    check(
        "R003 SYN flood detection",
        any(
            alert.rule_id == "R003"
            for alert in syn_alerts
        )
    )

    # ========================================================
    # R004 - RST ABUSE
    # ========================================================

    rst_detector = RuleDetector()

    rst_flow = make_flow(
        rst_count=25,
        total_packets=30,
    )

    rst_alerts = rst_detector.analyze(
        rst_flow
    )

    check(
        "R004 TCP RST abuse detection",
        any(
            alert.rule_id == "R004"
            for alert in rst_alerts
        )
    )

    # ========================================================
    # R005 - ICMP FLOOD
    # ========================================================

    icmp_detector = RuleDetector()

    icmp_flow = make_flow(
        protocol=1,
        protocol_name="ICMP",
        destination_port=None,
        total_packets=100,
    )

    icmp_alerts = icmp_detector.analyze(
        icmp_flow
    )

    check(
        "R005 ICMP flood detection",
        any(
            alert.rule_id == "R005"
            for alert in icmp_alerts
        )
    )

    # ========================================================
    # R006 - UDP FLOOD
    # ========================================================

    udp_detector = RuleDetector()

    udp_flow = make_flow(
        protocol=17,
        protocol_name="UDP",
        destination_port=53,
        total_packets=100,
    )

    udp_alerts = udp_detector.analyze(
        udp_flow
    )

    check(
        "R006 UDP flood detection",
        any(
            alert.rule_id == "R006"
            for alert in udp_alerts
        )
    )

    # ========================================================
    # R007 - NORMAL HIGH RATE
    # ========================================================

    rate_detector = RuleDetector()

    normal_high_rate = make_flow(
        protocol=6,
        protocol_name="TCP",
        total_packets=600,
        total_bytes=500000,
        duration=6.0,
        packet_rate=100.0,
        byte_rate=83333.0,
        syn_count=1,
        rst_count=0,
        connection_frequency=1,
    )

    normal_alerts = rate_detector.analyze(
        normal_high_rate
    )

    check(
        "R007 high packet rate detection",
        any(
            alert.rule_id == "R007"
            for alert in normal_alerts
        )
    )

    # ========================================================
    # R007 - UDP ALSO SUPPORTED
    # ========================================================

    udp_rate_flow = make_flow(
        protocol=17,
        protocol_name="UDP",
        destination_port=53,
        total_packets=200,
        total_bytes=300000,
        duration=2.0,
        packet_rate=100.0,
        byte_rate=150000.0,
    )

    udp_rate_detector = RuleDetector()

    udp_rate_alerts = udp_rate_detector.analyze(
         udp_rate_flow
    )

    check(
        "R007 supports non-TCP flow rates",
        any(
            alert.rule_id == "R007"
            for alert in udp_rate_alerts
        )
    )

    # ========================================================
    # R008 - HIGH BANDWIDTH
    # ========================================================

    bandwidth_detector = RuleDetector()

    bandwidth_flow = make_flow(
        protocol=6,
        protocol_name="TCP",
        total_packets=600,
        total_bytes=6_000_000,
        duration=6.0,
        packet_rate=100.0,
        byte_rate=1_000_000.0,
    )

    bandwidth_alerts = bandwidth_detector.analyze(
        bandwidth_flow
    )

    check(
        "R008 high bandwidth detection",
        any(
            alert.rule_id == "R008"
            for alert in bandwidth_alerts
        )
    )

    # ========================================================
    # ALERT OBJECT COMPATIBILITY
    # ========================================================

    compatibility_detector = RuleDetector()

    compatibility_alerts = compatibility_detector.analyze(
        make_flow(
            unique_destination_ports=21
        )
    )

    if compatibility_alerts:

        alert = compatibility_alerts[0]

        check(
            "Alert attribute access",
            alert.rule_id == "R001"
        )

        check(
            "Alert dictionary access",
            alert["rule_id"] == "R001"
        )

        check(
            "Alert get() compatibility",
            alert.get("rule_id") == "R001"
        )

        check(
            "Alert to_dict() compatibility",
            alert.to_dict()["rule_id"] == "R001"
        )

    else:

        check(
            "Alert attribute access",
            False
        )

        check(
            "Alert dictionary access",
            False
        )

        check(
            "Alert get() compatibility",
            False
        )

        check(
            "Alert to_dict() compatibility",
            False
        )

    # ========================================================
    # PIPELINE API
    # ========================================================

    result = compatibility_detector.analyze(
        make_flow()
    )

    check(
        "Pipeline analyze() compatibility",
        isinstance(
            result,
            list
        )
    )

    result_detect = compatibility_detector.detect(
        make_flow()
    )

    check(
        "Pipeline detect() compatibility",
        isinstance(
            result_detect,
            list
        )
    )

    # ========================================================
    # STAGE 3 FEATURE COMPATIBILITY
    # ========================================================

    stage3_feature_flow = make_flow(
        source_ip="10.1.1.100",
        destination_ip="10.2.2.100",
        source_port=50000,
        destination_port=443,
        protocol=6,
        protocol_name="TCP",
        total_packets=50,
        total_bytes=50000,
        duration=5.0,
        syn_count=1,
        ack_count=20,
        rst_count=0,
        unique_destination_ports=5,
        connection_frequency=2,
        packet_rate=10.0,
        byte_rate=10000.0,
    )

    stage3_result = compatibility_detector.analyze(
        stage3_feature_flow
    )

    check(
        "Stage 3 feature compatibility",
        isinstance(
            stage3_result,
            list
        )
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    stats = compatibility_detector.statistics()

    check(
        "Detector statistics",
        (
            "total_flows_analyzed"
            in stats
            and
            "total_alerts_generated"
            in stats
            and
            "rule_trigger_counts"
            in stats
        )
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()

    print(
        "-" * 70
    )

    if failed == 0:

        print(
            "[PASS] STAGE 4 RULE DETECTOR "
            "SELF-TEST: ALL TESTS PASSED"
        )

        print(
            "-" * 70
        )

        print(
            "Stage 4 is ready for integration."
        )

        return True

    print(
        f"[FAIL] SELF-TEST FAILED: "
        f"{failed} test(s) failed"
    )

    print(
        "-" * 70
    )

    return False


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 70
    )

    print(
        "NEURASHIELD STAGE 4 "
        "RULE-BASED DETECTION ENGINE"
    )

    print(
        "=" * 70
    )

    print()

    run_self_test()
