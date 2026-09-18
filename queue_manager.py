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
import ipaddress
import math
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

from rule_detector import RuleDetector
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
rule_detector = RuleDetector()
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
    """
    Discover interfaces without shell commands.

    Stage 2 intentionally supports multiple interfaces, but only
    interfaces that exist, are non-loopback, and have a usable IPv4
    address are eligible because this pipeline processes IPv4 traffic.
    """
    interfaces = []

    try:
        discovered = socket.if_nameindex()
    except OSError as exc:
        print(f"[ERROR] Interface discovery failed: {exc}")
        return []

    for _, name in discovered:
        if not isinstance(name, str):
            continue

        name = name.strip()
        if not name or name == "lo":
            continue

        if not interface_exists(name):
            continue

        if get_interface_ipv4(name) is None:
            continue

        interfaces.append(name)

    return sorted(set(interfaces))


def interface_exists(interface: str) -> bool:
    """Return True only for a current, non-loopback interface."""
    if not isinstance(interface, str):
        return False

    interface = interface.strip()
    if not interface or interface == "lo":
        return False

    try:
        available = {name for _, name in socket.if_nameindex()}
    except OSError:
        return False

    return interface in available


def get_interface_ipv4(interface: str) -> Optional[str]:
    """Resolve a usable IPv4 address without executing shell commands."""
    if not interface_exists(interface):
        return None

    try:
        from scapy.all import get_if_addr
        address = str(get_if_addr(interface))
        ipaddress.IPv4Address(address)
        if address == "0.0.0.0":
            return None
        return address
    except (OSError, ValueError):
        return None
    except Exception:
        return None


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

    now = time.monotonic()

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

def _valid_ip(value: object) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return isinstance(value, str)
    except (ValueError, TypeError):
        return False


def _valid_port(value: object) -> bool:
    return value is None or (type(value) is int and 0 <= value <= 65535)


def _valid_protocol(value: object) -> bool:
    return type(value) is int and 0 <= value <= 255


def _valid_packet_size(value: object) -> bool:
    return type(value) is int and 0 < value <= 65535


def _valid_timestamp(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def extract_metadata(packet, interface: str) -> Optional[PacketMetadata]:
    """
    Convert a transient Scapy packet into sanitized PacketMetadata.

    The raw packet is never placed in the queue. Once this function
    returns, Stage 2 retains only the bounded metadata object.
    """
    if not interface_exists(interface):
        return None

    if not packet.haslayer(IP):
        return None

    try:
        ip = packet[IP]
        timestamp = float(getattr(packet, "time", time.time()))
        source_ip = str(ip.src)
        destination_ip = str(ip.dst)
        protocol = int(getattr(ip, "proto", 0))
        packet_size = len(packet)

        if not _valid_timestamp(timestamp):
            return None
        if not _valid_ip(source_ip) or not _valid_ip(destination_ip):
            return None
        if not _valid_protocol(protocol):
            return None
        if not _valid_packet_size(packet_size):
            return None

        source_port = None
        destination_port = None
        tcp_flags = ""

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)
            if not _valid_port(source_port) or not _valid_port(destination_port):
                return None
            tcp_flags = str(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            source_port = int(udp.sport)
            destination_port = int(udp.dport)
            if not _valid_port(source_port) or not _valid_port(destination_port):
                return None
        elif packet.haslayer(ICMP):
            source_port = None
            destination_port = None

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
    except (TypeError, ValueError, AttributeError, OSError):
        return None
    except Exception:
        return None


# ============================================================
# CAPTURE THREAD
# ============================================================

def capture_worker(interface: str):
    """Capture transient packets and enqueue metadata only."""
    if not interface_exists(interface):
        print(f"[ERROR] Interface validation failed: {interface}")
        stop_event.set()
        return

    ipv4 = get_interface_ipv4(interface)
    if ipv4 is None:
        print(f"[ERROR] No usable IPv4 address on {interface}.")
        stop_event.set()
        return

    print(f"[CAPTURE] Monitoring interface: {interface} ({ipv4})")

    def handle_packet(packet):
        global dropped_packets

        if stop_event.is_set() or not packet.haslayer(IP):
            return

        try:
            timestamp = float(getattr(packet, "time", time.time()))
            if not _valid_timestamp(timestamp):
                return

            # Deduplication uses the transient packet only.
            if is_duplicate(packet, timestamp):
                with stats_lock:
                    flow_aggregator.duplicate_packets += 1
                return

            # Convert to sanitized metadata BEFORE queue insertion.
            metadata = extract_metadata(packet, interface)
            if metadata is None:
                return

            try:
                packet_queue.put_nowait(metadata)
            except Full:
                with stats_lock:
                    dropped_packets += 1

        except Exception as exc:
            print(f"[PACKET HANDLER ERROR] {interface}: {exc}")

    try:
        sniff(
            iface=interface,
            prn=handle_packet,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except PermissionError:
        print(f"[ERROR] Permission denied on {interface}. Run with sudo.")
        stop_event.set()
    except OSError as exc:
        print(f"[ERROR] Capture failure on {interface}: {exc}")
        stop_event.set()
    except Exception as exc:
        print(f"[ERROR] Capture failure on {interface}: {exc}")
        stop_event.set()


# ============================================================
# PROCESSOR THREAD
# ============================================================

def processor_worker():
    """Drain metadata into Stage 3, including queued work during shutdown."""
    while not stop_event.is_set() or not packet_queue.empty():
        try:
            metadata = packet_queue.get(timeout=0.5)
        except Empty:
            continue

        try:
            if not isinstance(metadata, PacketMetadata):
                continue

            flow_aggregator.update(metadata)

            print(
                f"[QUEUE → FLOW] {metadata.interface} | "
                f"{metadata.source_ip}:{metadata.source_port} → "
                f"{metadata.destination_ip}:{metadata.destination_port} | "
                f"PROTO={metadata.protocol} | SIZE={metadata.packet_size} | "
                f"QUEUE={packet_queue.qsize()}"
            )
        except Exception as exc:
            print(f"[PROCESSOR ERROR] {exc}")
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

    # ============================================================
    # STAGE 4 - RULE-BASED DETECTION
    # ============================================================

    alerts = rule_detector.analyze(features)

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

    # ============================================================
    # SECURITY ALERTS
    # ============================================================

    if alerts:

        print()
        print("              SECURITY ALERTS")
        print("-" * 70)

        for alert in alerts:

            print(
                f"Rule ID               : "
                f"{alert.rule_id}"
            )

            print(
                f"Threat                : "
                f"{alert.threat}"
            )

            print(
                f"Severity              : "
                f"{alert.severity}"
            )

            print(
                f"Confidence            : "
                f"{alert.confidence}"
            )

            print(
                f"Source IP             : "
                f"{alert.source_ip}"
            )

            print(
                f"Destination IP        : "
                f"{alert.destination_ip}"
            )

            print(
                f"Evidence              : "
                f"{alert.evidence}"
            )

            print("-" * 70)

    else:

        print()
        print(
            "Security Status        : "
            "NO RULE-BASED ALERTS"
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
    # Stop capture workers and drain queued metadata
    # --------------------------------------------------------

    for thread in capture_threads:
        thread.join(timeout=2.0)

    processor.join(timeout=10.0)

    if not packet_queue.empty():
        print(
            f"[WARNING] Queue still contains {packet_queue.qsize()} "
            "metadata item(s) after processor timeout."
        )

    reporter.join(timeout=2.0)

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
