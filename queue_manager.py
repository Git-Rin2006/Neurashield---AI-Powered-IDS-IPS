#!/usr/bin/env python3

"""
NeuraShield - Stage 3 Integrated Packet Pipeline

Packet Capture
      ↓
Bounded Queue
      ↓
Metadata Extraction
      ↓
Short-window Deduplication
      ↓
Flow Aggregation
      ↓
Expired Flow Feature Generation

Security properties:
    - Payload inspection disabled
    - No raw packet persistence
    - Bounded queue
    - Bounded deduplication cache
    - Thread-safe state
    - Graceful shutdown
    - Automatic interface discovery
    - No shell command execution
"""

from __future__ import annotations

import hashlib
import signal
import socket
import threading
import time
from collections import OrderedDict
from queue import Queue, Full, Empty
from typing import Optional

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
)

from flow_aggregator import (
    FlowAggregator,
    PacketMetadata,
    protocol_name,
)


# ============================================================
# CONFIGURATION
# ============================================================

QUEUE_MAX_SIZE = 10000

FLOW_TIMEOUT = 5.0

REPORT_INTERVAL = 1.0

# Duplicate packets arriving on different interfaces are
# considered duplicates only inside this short interval.
DEDUP_WINDOW = 0.050

# Maximum fingerprints retained in memory.
MAX_DEDUP_CACHE = 20000


# ============================================================
# GLOBAL STATE
# ============================================================

packet_queue = Queue(
    maxsize=QUEUE_MAX_SIZE
)

flow_aggregator = FlowAggregator(
    timeout=FLOW_TIMEOUT
)

stop_event = threading.Event()

capture_threads = []

dedup_lock = threading.Lock()

dedup_cache = OrderedDict()

dropped_packets = 0

stats_lock = threading.Lock()


# ============================================================
# INTERFACE DISCOVERY
# ============================================================

def discover_interfaces():

    interfaces = []

    for interface in socket.if_nameindex():

        _, name = interface

        # Never capture loopback traffic here.
        if name == "lo":
            continue

        interfaces.append(name)

    return interfaces


# ============================================================
# DEDUPLICATION
# ============================================================

def packet_fingerprint(
    packet,
    timestamp: float
) -> str:
    """
    Build a short-lived fingerprint from Layer-3+ data.

    Ethernet headers are intentionally excluded so that the
    same IP packet observed on ens37 and ens38 can be
    recognized as the same logical packet.
    """

    if not packet.haslayer(IP):
        return ""

    ip_layer = packet[IP]

    try:
        raw_ip = bytes(ip_layer)
    except Exception:
        return ""

    # Time bucket prevents the cache from treating legitimate
    # retransmissions seconds later as duplicates.
    bucket = int(
        timestamp / DEDUP_WINDOW
    )

    material = (
        raw_ip
        + bucket.to_bytes(
            8,
            byteorder="big",
            signed=False
        )
    )

    return hashlib.blake2s(
        material,
        digest_size=16
    ).hexdigest()


def is_duplicate(packet, timestamp):

    fingerprint = packet_fingerprint(
        packet,
        timestamp
    )

    if not fingerprint:
        return False

    now = timestamp

    with dedup_lock:

        # Remove expired fingerprints.
        while dedup_cache:

            oldest_key = next(
                iter(dedup_cache)
            )

            oldest_time = (
                dedup_cache[oldest_key]
            )

            if now - oldest_time > DEDUP_WINDOW:
                dedup_cache.pop(
                    oldest_key,
                    None
                )
            else:
                break

        if fingerprint in dedup_cache:

            dedup_cache.move_to_end(
                fingerprint
            )

            return True

        dedup_cache[fingerprint] = now

        # Hard memory bound.
        while len(dedup_cache) > MAX_DEDUP_CACHE:
            dedup_cache.popitem(
                last=False
            )

    return False


# ============================================================
# METADATA EXTRACTION
# ============================================================

def extract_metadata(
    packet,
    interface: str
) -> Optional[PacketMetadata]:

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    timestamp = float(
        getattr(
            packet,
            "time",
            time.time()
        )
    )

    source_ip = str(ip.src)
    destination_ip = str(ip.dst)

    source_port = None
    destination_port = None

    tcp_flags = ""

    protocol = int(
        getattr(
            ip,
            "proto",
            0
        )
    )

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        source_port = int(
            tcp.sport
        )

        destination_port = int(
            tcp.dport
        )

        tcp_flags = str(
            tcp.flags
        )

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        source_port = int(
            udp.sport
        )

        destination_port = int(
            udp.dport
        )

    elif packet.haslayer(ICMP):

        source_port = None
        destination_port = None

    packet_size = len(packet)

    if packet_size <= 0:
        return None

    return PacketMetadata(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_size=packet_size,
        tcp_flags=tcp_flags,
        interface=interface,
    )


# ============================================================
# CAPTURE THREAD
# ============================================================

def capture_worker(interface: str):

    print(
        f"[CAPTURE] Monitoring interface: {interface}"
    )

    def handle_packet(packet):

        global dropped_packets

        if stop_event.is_set():
            return

        timestamp = float(
            getattr(
                packet,
                "time",
                time.time()
            )
        )

        # Only IPv4 traffic is processed in this stage.
        if not packet.haslayer(IP):
            return

        # Short-window cross-interface deduplication.
        if is_duplicate(
            packet,
            timestamp
        ):

            with stats_lock:
                flow_aggregator.duplicate_packets += 1

            return

        try:

            packet_queue.put_nowait(
                (
                    packet,
                    interface
                )
            )

        except Full:

            with stats_lock:
                dropped_packets += 1

    try:

        sniff(
            iface=interface,
            prn=handle_packet,
            store=False,
            stop_filter=lambda _: (
                stop_event.is_set()
            ),
        )

    except PermissionError:

        print(
            f"[ERROR] Permission denied on "
            f"{interface}. Run with sudo."
        )

        stop_event.set()

    except Exception as exc:

        print(
            f"[ERROR] Capture failure on "
            f"{interface}: {exc}"
        )

        stop_event.set()


# ============================================================
# PROCESSOR THREAD
# ============================================================

def processor_worker():

    while not stop_event.is_set():

        try:

            packet, interface = (
                packet_queue.get(
                    timeout=0.5
                )
            )

        except Empty:
            continue

        try:

            metadata = extract_metadata(
                packet,
                interface
            )

            if metadata is None:
                continue

            flow_aggregator.update(
                metadata
            )

            print(
                f"[QUEUE → FLOW] "
                f"{interface} | "
                f"{metadata.source_ip}:"
                f"{metadata.source_port} → "
                f"{metadata.destination_ip}:"
                f"{metadata.destination_port} | "
                f"PROTO={metadata.protocol} | "
                f"SIZE={metadata.packet_size} | "
                f"QUEUE={packet_queue.qsize()}"
            )

        except Exception as exc:

            print(
                f"[PROCESSOR ERROR] {exc}"
            )

        finally:

            packet_queue.task_done()


# ============================================================
# REPORTER THREAD
# ============================================================

def reporter_worker():

    while not stop_event.wait(
        REPORT_INTERVAL
    ):

        try:

            expired = (
                flow_aggregator
                .get_expired_flows()
            )

            for flow in expired:

                print_completed_flow(
                    flow
                )

        except Exception as exc:

            print(
                f"[REPORTER ERROR] {exc}"
            )


# ============================================================
# FLOW DISPLAY
# ============================================================

def print_completed_flow(flow):

    features = (
        flow_aggregator
        .generate_features(flow)
    )

    print()
    print("=" * 70)
    print(
        "              NEURASHIELD FLOW"
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
        f"Connection Frequency   : "
        f"{features['connection_frequency']}"
    )

    print(
        f"Interfaces             : "
        f"{', '.join(features['interfaces']) or 'N/A'}"
    )

    print("=" * 70)


# ============================================================
# SHUTDOWN
# ============================================================

def shutdown_handler(
    signum=None,
    frame=None
):

    if stop_event.is_set():
        return

    print()
    print(
        "[SYSTEM] Shutdown requested..."
    )

    stop_event.set()


# ============================================================
# MAIN
# ============================================================

def main():

    global capture_threads

    interfaces = discover_interfaces()

    if not interfaces:

        print(
            "[ERROR] No network interfaces found."
        )

        return 1

    signal.signal(
        signal.SIGINT,
        shutdown_handler
    )

    signal.signal(
        signal.SIGTERM,
        shutdown_handler
    )

    print("=" * 70)
    print(
        "          NEURASHIELD - LIVE MONITORING"
    )
    print("=" * 70)

    print(
        "Interface Discovery    : AUTOMATIC"
    )

    print(
        f"Interfaces Detected    : "
        f"{len(interfaces)}"
    )

    for interface in interfaces:

        print(
            f"  └─ {interface}"
        )

    print(
        "Payload Inspection     : Disabled"
    )

    print(
        f"Flow Timeout           : "
        f"{FLOW_TIMEOUT:g} seconds"
    )

    print(
        f"Queue Capacity         : "
        f"{QUEUE_MAX_SIZE}"
    )

    print(
        f"Deduplication Window   : "
        f"{DEDUP_WINDOW * 1000:.0f} ms"
    )

    print(
        "Status                 : ACTIVE"
    )

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 70)
    print()

    # --------------------------------------------------------
    # Start processor
    # --------------------------------------------------------

    processor = threading.Thread(
        target=processor_worker,
        name="NeuraShield-Processor",
        daemon=True
    )

    processor.start()

    # --------------------------------------------------------
    # Start reporter
    # --------------------------------------------------------

    reporter = threading.Thread(
        target=reporter_worker,
        name="NeuraShield-Reporter",
        daemon=True
    )

    reporter.start()

    # --------------------------------------------------------
    # Start capture workers
    # --------------------------------------------------------

    for interface in interfaces:

        thread = threading.Thread(
            target=capture_worker,
            args=(interface,),
            name=f"NeuraShield-Capture-{interface}",
            daemon=True
        )

        thread.start()

        capture_threads.append(
            thread
        )

    # --------------------------------------------------------
    # Main wait loop
    # --------------------------------------------------------

    try:

        while not stop_event.wait(1.0):
            pass

    except KeyboardInterrupt:

        shutdown_handler()

    # --------------------------------------------------------
    # Final flush
    # --------------------------------------------------------

    print()
    print(
        "[SYSTEM] Flushing active flows..."
    )

    remaining = (
        flow_aggregator.flush()
    )

    for flow in remaining:

        print_completed_flow(
            flow
        )

    print()
    print("=" * 70)
    print(
        "              NEURASHIELD - STOPPED"
    )
    print("=" * 70)

    print(
        f"Accepted Packets      : "
        f"{flow_aggregator.accepted_packets}"
    )

    print(
        f"Duplicate Packets     : "
        f"{flow_aggregator.duplicate_packets}"
    )

    print(
        f"Dropped Packets       : "
        f"{dropped_packets}"
    )

    print(
        f"Rejected Packets      : "
        f"{flow_aggregator.rejected_packets}"
    )

    print("=" * 70)

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
