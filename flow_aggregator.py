#!/usr/bin/env python3

"""
NeuraShield - Stage 3
Secure Network Flow Aggregation Engine

Responsibilities:
    - Convert packet metadata into bidirectional network flows
    - Maintain canonical 5-tuple flow keys
    - Track traffic direction reliably
    - Track TCP flags
    - Aggregate packets and bytes
    - Track destination ports correctly
    - Calculate source-level destination-port diversity
    - Calculate connection frequency
    - Expire inactive flows
    - Provide ML-ready feature dictionaries

Security design:
    - No payload inspection
    - No raw packet storage
    - Bounded in-memory state
    - Thread-safe aggregation
    - Input validation
    - Deduplication handled before aggregation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Optional, Tuple, Dict, List, Set
from collections import defaultdict, deque
import time


# ============================================================
# CONFIGURATION
# ============================================================

# A flow is finalized after this period of inactivity.
FLOW_INACTIVITY_TIMEOUT = 5.0

# Window used for source-level connection frequency.
CONNECTION_WINDOW = 60.0

# Window used for source-level destination-port diversity.
DESTINATION_PORT_WINDOW = 5.0

# Protection against accidentally creating unlimited flows.
MAX_ACTIVE_FLOWS = 50000

# Protection against unlimited connection-history growth.
MAX_CONNECTION_HISTORY = 100000

# Protection against unlimited destination-port-history growth.
MAX_DESTINATION_PORT_HISTORY = 100000


# ============================================================
# DATA TYPES
# ============================================================

Endpoint = Tuple[str, Optional[int]]

FlowKey = Tuple[
    str,
    str,
    Optional[int],
    Optional[int],
    int,
]


@dataclass(frozen=True)
class PacketMetadata:
    """
    Sanitized packet metadata.

    Payload is intentionally excluded.
    """

    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: int
    packet_size: int
    tcp_flags: str = ""
    interface: str = ""


@dataclass
class FlowRecord:
    """
    Bidirectional network flow.
    """

    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: int

    start_time: float
    last_time: float

    initiator: Optional[Endpoint] = None

    total_packets: int = 0
    total_bytes: int = 0

    packets_a_to_b: int = 0
    packets_b_to_a: int = 0

    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    # Destination ports observed from this flow's initiator.
    #
    # Since a 5-tuple flow contains one destination port,
    # this is normally a set of size 1 for a valid TCP/UDP flow.
    #
    # Source-level destination-port diversity is tracked separately.
    destination_ports: Set[int] = field(default_factory=set)

    # Track which interfaces observed the flow.
    interfaces: Set[str] = field(default_factory=set)


# ============================================================
# FLOW AGGREGATOR
# ============================================================

class FlowAggregator:

    def __init__(
        self,
        timeout: float = FLOW_INACTIVITY_TIMEOUT,
        connection_window: float = CONNECTION_WINDOW,
        destination_port_window: float = DESTINATION_PORT_WINDOW,
        max_active_flows: int = MAX_ACTIVE_FLOWS,
    ):

        if timeout <= 0:
            raise ValueError(
                "Flow inactivity timeout must be greater than zero."
            )

        if connection_window <= 0:
            raise ValueError(
                "Connection window must be greater than zero."
            )

        if destination_port_window <= 0:
            raise ValueError(
                "Destination-port window must be greater than zero."
            )

        if max_active_flows <= 0:
            raise ValueError(
                "Maximum active flows must be greater than zero."
            )

        self.timeout = float(timeout)
        self.connection_window = float(connection_window)
        self.destination_port_window = float(
            destination_port_window
        )
        self.max_active_flows = int(max_active_flows)

        self.active_flows: Dict[FlowKey, FlowRecord] = {}

        # Source IP -> timestamps of initiated connections.
        self.connection_history = defaultdict(deque)

        # Source IP -> (timestamp, destination_port)
        #
        # Used to calculate how many distinct destination ports
        # a source contacted during the recent behavioral window.
        self.destination_port_history = defaultdict(deque)

        self.lock = RLock()

        self.accepted_packets = 0
        self.rejected_packets = 0
        self.duplicate_packets = 0


    # ========================================================
    # VALIDATION
    # ========================================================

    @staticmethod
    def _valid_ip(value: str) -> bool:
        return (
            isinstance(value, str)
            and 0 < len(value) <= 45
        )


    @staticmethod
    def _valid_port(value: Optional[int]) -> bool:
        return (
            value is None
            or (
                isinstance(value, int)
                and 0 <= value <= 65535
            )
        )


    @staticmethod
    def _valid_protocol(value: int) -> bool:
        return (
            isinstance(value, int)
            and 0 <= value <= 255
        )


    @staticmethod
    def _valid_packet_size(value: int) -> bool:
        return (
            isinstance(value, int)
            and 0 < value <= 65535
        )


    def validate_packet(
        self,
        packet: PacketMetadata
    ) -> bool:

        if not isinstance(packet, PacketMetadata):
            return False

        if not self._valid_ip(packet.source_ip):
            return False

        if not self._valid_ip(packet.destination_ip):
            return False

        if not self._valid_port(packet.source_port):
            return False

        if not self._valid_port(packet.destination_port):
            return False

        if not self._valid_protocol(packet.protocol):
            return False

        if not self._valid_packet_size(packet.packet_size):
            return False

        if not isinstance(
            packet.timestamp,
            (int, float)
        ):
            return False

        if packet.timestamp < 0:
            return False

        return True


    # ========================================================
    # FLOW KEY
    # ========================================================

    @staticmethod
    def create_flow_key(
        packet: PacketMetadata
    ) -> FlowKey:

        endpoint_1 = (
            packet.source_ip,
            packet.source_port
        )

        endpoint_2 = (
            packet.destination_ip,
            packet.destination_port
        )

        # Canonical ordering makes the flow bidirectional.
        if endpoint_1 <= endpoint_2:
            first = endpoint_1
            second = endpoint_2
        else:
            first = endpoint_2
            second = endpoint_1

        return (
            first[0],
            second[0],
            first[1],
            second[1],
            packet.protocol,
        )


    # ========================================================
    # INITIATOR DETECTION
    # ========================================================

    @staticmethod
    def _detect_initiator(
        packet: PacketMetadata
    ) -> Optional[Endpoint]:

        flags = (
            packet.tcp_flags or ""
        ).upper()

        source = (
            packet.source_ip,
            packet.source_port
        )

        destination = (
            packet.destination_ip,
            packet.destination_port
        )

        # SYN without ACK = connection initiator.
        if "S" in flags and "A" not in flags:
            return source

        # SYN-ACK = reverse endpoint is initiator.
        if "S" in flags and "A" in flags:
            return destination

        return None


    # ========================================================
    # UPDATE FLOW
    # ========================================================

    def update(
        self,
        packet: PacketMetadata
    ) -> Optional[FlowRecord]:

        if not self.validate_packet(packet):

            with self.lock:
                self.rejected_packets += 1

            return None

        with self.lock:

            key = self.create_flow_key(packet)

            flow = self.active_flows.get(key)

            # ------------------------------------------------
            # New flow
            # ------------------------------------------------

            if flow is None:

                if len(self.active_flows) >= self.max_active_flows:
                    self._expire_oldest_flow()

                endpoint_a = (
                    key[0],
                    key[2]
                )

                endpoint_b = (
                    key[1],
                    key[3]
                )

                initiator = self._detect_initiator(
                    packet
                )

                flow = FlowRecord(
                    endpoint_a=endpoint_a,
                    endpoint_b=endpoint_b,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                    last_time=packet.timestamp,
                    initiator=initiator,
                )

                self.active_flows[key] = flow

                # Record source-level connection initiation.
                if initiator is not None:

                    self._record_connection(
                        initiator[0],
                        packet.timestamp
                    )


            # ------------------------------------------------
            # Existing flow
            # ------------------------------------------------

            flow.last_time = max(
                flow.last_time,
                packet.timestamp
            )

            if packet.interface:
                flow.interfaces.add(
                    packet.interface
                )

            source = (
                packet.source_ip,
                packet.source_port
            )

            destination = (
                packet.destination_ip,
                packet.destination_port
            )

            # If initiator wasn't known yet, learn it from TCP.
            if flow.initiator is None:

                detected = self._detect_initiator(
                    packet
                )

                if detected is not None:

                    flow.initiator = detected

                    self._record_connection(
                        detected[0],
                        packet.timestamp
                    )

            # ------------------------------------------------
            # Direction accounting
            # ------------------------------------------------

            if source == flow.endpoint_a:

                flow.packets_a_to_b += 1
                flow.bytes_a_to_b += packet.packet_size

            elif source == flow.endpoint_b:

                flow.packets_b_to_a += 1
                flow.bytes_b_to_a += packet.packet_size

            # ------------------------------------------------
            # Total statistics
            # ------------------------------------------------

            flow.total_packets += 1
            flow.total_bytes += packet.packet_size

            # ------------------------------------------------
            # TCP flags
            # ------------------------------------------------

            flags = (
                packet.tcp_flags or ""
            ).upper()

            if "S" in flags:
                flow.syn_count += 1

            if "A" in flags:
                flow.ack_count += 1

            if "F" in flags:
                flow.fin_count += 1

            if "R" in flags:
                flow.rst_count += 1

            # ------------------------------------------------
            # Flow-level destination-port tracking
            # ------------------------------------------------

            # Only count ports contacted by the initiator.
            #
            # This is kept as flow metadata.
            # Source-level destination-port diversity is handled
            # separately below.
            if (
                flow.initiator is not None
                and source == flow.initiator
                and packet.destination_port is not None
            ):

                flow.destination_ports.add(
                    packet.destination_port
                )

            # ------------------------------------------------
            # Source-level destination-port tracking
            # ------------------------------------------------

            # Every source -> destination-port observation is
            # recorded for behavioral analysis.
            #
            # This is intentionally source-level rather than
            # flow-level because a port scan creates many
            # different 5-tuple flows.
            if packet.destination_port is not None:

                self._record_destination_port(
                    packet.source_ip,
                    packet.destination_port,
                    packet.timestamp
                )

            self.accepted_packets += 1

            return flow


    # ========================================================
    # CONNECTION HISTORY
    # ========================================================

    def _record_connection(
        self,
        source_ip: str,
        timestamp: float
    ):

        history = self.connection_history[
            source_ip
        ]

        history.append(timestamp)

        self._prune_connection_history(
            source_ip,
            timestamp
        )


    def _prune_connection_history(
        self,
        source_ip: str,
        current_time: float
    ):

        history = self.connection_history[
            source_ip
        ]

        cutoff = (
            current_time
            - self.connection_window
        )

        while history and history[0] < cutoff:
            history.popleft()

        # Hard memory protection.
        while len(history) > MAX_CONNECTION_HISTORY:
            history.popleft()


    def get_connection_frequency(
        self,
        source_ip: str,
        current_time: float
    ) -> int:

        with self.lock:

            self._prune_connection_history(
                source_ip,
                current_time
            )

            return len(
                self.connection_history[source_ip]
            )


    # ========================================================
    # DESTINATION PORT HISTORY
    # ========================================================

    def _record_destination_port(
        self,
        source_ip: str,
        destination_port: int,
        timestamp: float
    ):

        history = self.destination_port_history[
            source_ip
        ]

        history.append(
            (
                timestamp,
                destination_port
            )
        )

        self._prune_destination_port_history(
            source_ip,
            timestamp
        )


    def _prune_destination_port_history(
        self,
        source_ip: str,
        current_time: float
    ):

        history = self.destination_port_history[
            source_ip
        ]

        cutoff = (
            current_time
            - self.destination_port_window
        )

        while history:

            timestamp, _ = history[0]

            if timestamp < cutoff:
                history.popleft()
            else:
                break

        # Hard memory protection.
        while (
            len(history)
            > MAX_DESTINATION_PORT_HISTORY
        ):
            history.popleft()


    def get_unique_destination_ports(
        self,
        source_ip: str,
        current_time: float
    ) -> int:
        """
        Return the number of distinct destination ports contacted
        by a source IP during the configured destination-port window.

        This is a source-level behavioral feature.

        Example:

            source IP: 10.10.10.10

            5-second window:
                port 22
                port 23
                port 80
                port 443
                port 8080

            result:
                5
        """

        with self.lock:

            self._prune_destination_port_history(
                source_ip,
                current_time
            )

            cutoff = (
                current_time
                - self.destination_port_window
            )

            ports = {
                destination_port
                for timestamp, destination_port
                in self.destination_port_history[
                    source_ip
                ]
                if timestamp >= cutoff
            }

            return len(ports)


    # ========================================================
    # FLOW EXPIRATION
    # ========================================================

    def _expire_oldest_flow(self):

        if not self.active_flows:
            return

        oldest_key = min(
            self.active_flows,
            key=lambda k:
                self.active_flows[k].last_time
        )

        del self.active_flows[
            oldest_key
        ]


    def get_expired_flows(
        self,
        current_time: Optional[float] = None
    ) -> List[FlowRecord]:

        if current_time is None:
            current_time = time.time()

        expired = []

        with self.lock:

            for key, flow in list(
                self.active_flows.items()
            ):

                inactivity = (
                    current_time
                    - flow.last_time
                )

                if inactivity >= self.timeout:

                    expired.append(flow)

                    del self.active_flows[key]

        return expired


    # ========================================================
    # FLUSH EVERYTHING
    # ========================================================

    def flush(self) -> List[FlowRecord]:

        with self.lock:

            flows = list(
                self.active_flows.values()
            )

            self.active_flows.clear()

            return flows


    # ========================================================
    # FEATURE GENERATION
    # ========================================================

    def generate_features(
        self,
        flow: FlowRecord
    ) -> Dict:

        duration = max(
            0.0,
            flow.last_time
            - flow.start_time
        )

        packet_rate = (
            flow.total_packets / duration
            if duration > 0
            else float(flow.total_packets)
        )

        byte_rate = (
            flow.total_bytes / duration
            if duration > 0
            else float(flow.total_bytes)
        )

        average_packet_size = (
            flow.total_bytes
            / flow.total_packets
            if flow.total_packets > 0
            else 0.0
        )

        # -----------------------------------------------
        # Reliable source/destination direction
        # -----------------------------------------------

        if flow.initiator == flow.endpoint_a:

            source_ip = flow.endpoint_a[0]
            source_port = flow.endpoint_a[1]

            destination_ip = flow.endpoint_b[0]
            destination_port = flow.endpoint_b[1]

        elif flow.initiator == flow.endpoint_b:

            source_ip = flow.endpoint_b[0]
            source_port = flow.endpoint_b[1]

            destination_ip = flow.endpoint_a[0]
            destination_port = flow.endpoint_a[1]

        else:

            # Fallback when capture started mid-flow and
            # no SYN was observed.
            source_ip = flow.endpoint_a[0]
            source_port = flow.endpoint_a[1]

            destination_ip = flow.endpoint_b[0]
            destination_port = flow.endpoint_b[1]

        # -----------------------------------------------
        # Connection frequency
        # -----------------------------------------------

        if flow.initiator is not None:

            connection_frequency = (
                self.get_connection_frequency(
                    flow.initiator[0],
                    flow.last_time
                )
            )

        else:

            connection_frequency = 0

        # -----------------------------------------------
        # Source-level destination-port diversity
        # -----------------------------------------------

        unique_destination_ports = (
            self.get_unique_destination_ports(
                source_ip,
                flow.last_time
            )
        )

        # -----------------------------------------------
        # Flow-level destination-port count
        # -----------------------------------------------

        flow_destination_port_count = len(
            flow.destination_ports
        )

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
                flow.protocol,

            "flow_duration":
                round(
                    duration,
                    6
                ),

            "total_packets":
                flow.total_packets,

            "total_bytes":
                flow.total_bytes,

            "packet_rate":
                round(
                    packet_rate,
                    4
                ),

            "byte_rate":
                round(
                    byte_rate,
                    4
                ),

            "average_packet_size":
                round(
                    average_packet_size,
                    4
                ),

            "syn_count":
                flow.syn_count,

            "ack_count":
                flow.ack_count,

            "fin_count":
                flow.fin_count,

            "rst_count":
                flow.rst_count,

            # IMPORTANT:
            #
            # This is now a SOURCE-LEVEL behavioral feature,
            # not a property of one individual 5-tuple flow.
            #
            # It represents the number of distinct destination
            # ports contacted by this source within the recent
            # destination-port window.
            "unique_destination_ports":
                unique_destination_ports,

            # Number of destination ports observed within this
            # individual flow. Normally 0 or 1 because the
            # destination port is part of the 5-tuple.
            "flow_destination_port_count":
                flow_destination_port_count,

            "connection_frequency":
                connection_frequency,

            "packets_forward":
                (
                    flow.packets_a_to_b
                    if flow.initiator
                    == flow.endpoint_a
                    else flow.packets_b_to_a
                ),

            "packets_reverse":
                (
                    flow.packets_b_to_a
                    if flow.initiator
                    == flow.endpoint_a
                    else flow.packets_a_to_b
                ),

            "bytes_forward":
                (
                    flow.bytes_a_to_b
                    if flow.initiator
                    == flow.endpoint_a
                    else flow.bytes_b_to_a
                ),

            "bytes_reverse":
                (
                    flow.bytes_b_to_a
                    if flow.initiator
                    == flow.endpoint_a
                    else flow.bytes_a_to_b
                ),

            "interfaces":
                sorted(
                    flow.interfaces
                ),
        }


# ============================================================
# PROTOCOL HELPER
# ============================================================

def protocol_name(
    protocol: int
) -> str:

    names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    return names.get(
        protocol,
        f"PROTO-{protocol}"
    )


# ============================================================
# DISPLAY
# ============================================================

def print_flow(
    flow: FlowRecord,
    aggregator=None
):

    if aggregator is None:
        aggregator = FlowAggregator()

    features = (
        aggregator.generate_features(
            flow
        )
    )

    print()
    print("=" * 70)
    print(
        "              NEURASHIELD - COMPLETED FLOW"
    )
    print("=" * 70)

    print(
        f"Source IP              : "
        f"{features['source_ip']}"
    )

    print(
        f"Destination IP         : "
        f"{features['destination_ip']}"
    )

    print(
        f"Source Port            : "
        f"{features['source_port']}"
    )

    print(
        f"Destination Port       : "
        f"{features['destination_port']}"
    )

    print(
        f"Protocol               : "
        f"{features['protocol']} "
        f"({protocol_name(features['protocol'])})"
    )

    print(
        f"Flow Duration          : "
        f"{features['flow_duration']:.4f} sec"
    )

    print(
        f"Total Packets          : "
        f"{features['total_packets']}"
    )

    print(
        f"Total Bytes            : "
        f"{features['total_bytes']}"
    )

    print(
        f"Packet Rate            : "
        f"{features['packet_rate']:.2f} packets/sec"
    )

    print(
        f"Byte Rate              : "
        f"{features['byte_rate']:.2f} bytes/sec"
    )

    print(
        f"Average Packet Size    : "
        f"{features['average_packet_size']:.2f} bytes"
    )

    print(
        f"SYN Count              : "
        f"{features['syn_count']}"
    )

    print(
        f"ACK Count              : "
        f"{features['ack_count']}"
    )

    print(
        f"FIN Count              : "
        f"{features['fin_count']}"
    )

    print(
        f"RST Count              : "
        f"{features['rst_count']}"
    )

    print(
        f"Unique Destination Ports : "
        f"{features['unique_destination_ports']}"
    )

    print(
        f"Flow Destination Ports : "
        f"{features['flow_destination_port_count']}"
    )

    print(
        f"Connection Frequency   : "
        f"{features['connection_frequency']}"
    )

    print(
        f"Interfaces             : "
        f"{', '.join(features['interfaces']) or 'N/A'}"
    )

    print("=" * 70)


# ============================================================
# SELF TEST
# ============================================================

def self_test():

    print()
    print("=" * 70)
    print(
        "        NEURASHIELD STAGE 3 SELF-TEST"
    )
    print("=" * 70)

    aggregator = FlowAggregator(
        timeout=5,
        connection_window=60,
        destination_port_window=5
    )

    base = 1000.0

    # --------------------------------------------------------
    # SYN
    # --------------------------------------------------------

    syn = PacketMetadata(
        timestamp=base,
        source_ip="10.10.10.10",
        destination_ip="10.10.20.10",
        source_port=50000,
        destination_port=80,
        protocol=6,
        packet_size=74,
        tcp_flags="S",
        interface="ens37",
    )

    aggregator.update(syn)

    # --------------------------------------------------------
    # SYN-ACK
    # --------------------------------------------------------

    syn_ack = PacketMetadata(
        timestamp=base + 0.001,
        source_ip="10.10.20.10",
        destination_ip="10.10.10.10",
        source_port=80,
        destination_port=50000,
        protocol=6,
        packet_size=74,
        tcp_flags="SA",
        interface="ens38",
    )

    aggregator.update(syn_ack)

    # --------------------------------------------------------
    # ACK
    # --------------------------------------------------------

    ack = PacketMetadata(
        timestamp=base + 0.002,
        source_ip="10.10.10.10",
        destination_ip="10.10.20.10",
        source_port=50000,
        destination_port=80,
        protocol=6,
        packet_size=66,
        tcp_flags="A",
        interface="ens37",
    )

    aggregator.update(ack)

    flows = aggregator.flush()

    if len(flows) != 1:

        raise AssertionError(
            "Bidirectional flow aggregation failed."
        )

    flow = flows[0]

    features = aggregator.generate_features(
        flow
    )

    # --------------------------------------------------------
    # Tests
    # --------------------------------------------------------

    assert (
        features["source_ip"]
        == "10.10.10.10"
    )

    print(
        "[PASS] Initiator direction"
    )

    assert (
        features["destination_ip"]
        == "10.10.20.10"
    )

    print(
        "[PASS] Destination direction"
    )

    assert (
        features["source_port"]
        == 50000
    )

    print(
        "[PASS] Source port"
    )

    assert (
        features["destination_port"]
        == 80
    )

    print(
        "[PASS] Destination port"
    )

    assert (
        features["total_packets"]
        == 3
    )

    print(
        "[PASS] Packet aggregation"
    )

    assert (
        features["total_bytes"]
        == 214
    )

    print(
        "[PASS] Byte aggregation"
    )

    assert (
        features["syn_count"]
        == 2
    )

    print(
        "[PASS] SYN count"
    )

    assert (
        features["ack_count"]
        == 2
    )

    print(
        "[PASS] ACK count"
    )

    assert (
        features["flow_destination_port_count"]
        == 1
    )

    print(
        "[PASS] Flow destination-port tracking"
    )

    assert (
        features["unique_destination_ports"]
        == 1
    )

    print(
        "[PASS] Source-level destination-port diversity"
    )

    assert (
        features["packets_forward"]
        == 2
    )

    print(
        "[PASS] Forward packet count"
    )

    assert (
        features["packets_reverse"]
        == 1
    )

    print(
        "[PASS] Reverse packet count"
    )

    assert "ens37" in features["interfaces"]
    assert "ens38" in features["interfaces"]

    print(
        "[PASS] Interface tracking"
    )

    # --------------------------------------------------------
    # Connection frequency test
    # --------------------------------------------------------

    aggregator = FlowAggregator()

    for index in range(3):

        packet = PacketMetadata(
            timestamp=2000.0 + index,
            source_ip="10.10.10.10",
            destination_ip=(
                f"10.10.20.{20 + index}"
            ),
            source_port=40000 + index,
            destination_port=80,
            protocol=6,
            packet_size=74,
            tcp_flags="S",
            interface="ens37",
        )

        aggregator.update(packet)

    test_flow = list(
        aggregator.active_flows.values()
    )[-1]

    test_features = (
        aggregator.generate_features(
            test_flow
        )
    )

    assert (
        test_features["connection_frequency"]
        == 3
    )

    print(
        "[PASS] Connection frequency"
    )

    # --------------------------------------------------------
    # Destination-port diversity test
    # --------------------------------------------------------

    aggregator = FlowAggregator(
        destination_port_window=5
    )

    scanned_ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        443,
    ]

    for index, port in enumerate(
        scanned_ports
    ):

        packet = PacketMetadata(
            timestamp=3000.0 + (index * 0.5),
            source_ip="10.10.10.50",
            destination_ip="10.10.20.10",
            source_port=45000 + index,
            destination_port=port,
            protocol=6,
            packet_size=74,
            tcp_flags="S",
            interface="ens37",
        )

        aggregator.update(packet)

    scan_flow = list(
        aggregator.active_flows.values()
    )[-1]

    scan_features = (
        aggregator.generate_features(
            scan_flow
        )
    )

    assert (
        scan_features[
            "unique_destination_ports"
        ]
        == 7
    )

    print(
        "[PASS] Source-level unique destination ports"
    )

    # --------------------------------------------------------
    # Destination-port window expiry test
    # --------------------------------------------------------

    port_count_after_window = (
        aggregator.get_unique_destination_ports(
            "10.10.10.50",
            3008.001
        )
    )

    assert (
        port_count_after_window
        == 0
    )

    print(
        "[PASS] Destination-port window expiration"
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    print("-" * 70)

    print(
        "[PASS] STAGE 3 SELF-TEST: ALL TESTS PASSED"
    )

    print("=" * 70)
    print()

    print(
        "Stage 3 is ready for integration."
    )

    print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    self_test()
