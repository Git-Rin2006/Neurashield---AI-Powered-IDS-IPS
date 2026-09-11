#!/usr/bin/env python3

"""
NeuraShield - Stage 1
Secure Live Network Packet Capture Engine

Responsibilities:
    - Automatically discover usable network interfaces
    - Determine the primary interface using the system routing table
    - Validate the selected interface
    - Capture IPv4 traffic
    - Extract sanitized packet metadata
    - Avoid payload inspection
    - Avoid raw packet persistence
    - Gracefully handle shutdown and capture errors

Security properties:
    - No hard-coded interface names
    - No shell command execution
    - No subprocess execution
    - No raw packet storage
    - No payload inspection
    - Interface names are validated before use
    - Only discovered interfaces may be selected
    - Loopback is excluded
    - Invalid interfaces are rejected
    - Packet metadata is validated before processing
    - Scapy capture uses store=False
    - Graceful SIGINT/SIGTERM handling

Target platform:
    Ubuntu Linux
"""

from __future__ import annotations

import os
import signal
import sys
import socket
from datetime import datetime
from typing import Optional

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    conf,
)


# ============================================================
# CONFIGURATION
# ============================================================

# Interfaces that should never be selected automatically.
#
# We intentionally do NOT blacklist names such as:
#   eth0
#   ens33
#   enp3s0
#   wlp2s0
#
# because interface naming differs between systems.
EXCLUDED_INTERFACES = {
    "lo",
}


# Maximum values used for defensive validation.
MAX_IP_LENGTH = 45
MAX_PACKET_SIZE = 65535
MAX_PROTOCOL = 255
MAX_PORT = 65535


# ============================================================
# GLOBAL STATE
# ============================================================

shutdown_requested = False


# ============================================================
# SIGNAL HANDLING
# ============================================================

def shutdown_handler(signum=None, frame=None):
    """
    Request a graceful shutdown.

    No destructive operation is performed here.
    The handler only changes process state.
    """

    global shutdown_requested

    if shutdown_requested:
        return

    shutdown_requested = True

    print()
    print("[SYSTEM] Shutdown requested.")


# ============================================================
# INTERFACE DISCOVERY
# ============================================================

def discover_interfaces() -> list[str]:
    """
    Discover network interfaces using Python's socket API.

    No shell commands are executed.

    Returns:
        A sorted list of interface names excluding loopback.
    """

    interfaces: list[str] = []

    try:
        discovered = socket.if_nameindex()

    except OSError as exc:
        print(
            f"[ERROR] Network interface discovery failed: {exc}"
        )
        return []

    for _, name in discovered:

        if not isinstance(name, str):
            continue

        name = name.strip()

        if not name:
            continue

        if name in EXCLUDED_INTERFACES:
            continue

        interfaces.append(name)

    return sorted(set(interfaces))


# ============================================================
# INTERFACE VALIDATION
# ============================================================

def interface_exists(interface: str) -> bool:
    """
    Verify that an interface currently exists.

    The interface must be present in the operating system's
    interface list.
    """

    if not isinstance(interface, str):
        return False

    interface = interface.strip()

    if not interface:
        return False

    if interface in EXCLUDED_INTERFACES:
        return False

    try:
        available = {
            name
            for _, name in socket.if_nameindex()
        }

    except OSError:
        return False

    return interface in available


# ============================================================
# IPv4 VALIDATION
# ============================================================

def get_interface_ipv4(interface: str) -> Optional[str]:
    """
    Obtain the IPv4 address associated with an interface.

    Scapy's interface configuration is used instead of invoking
    external system commands.
    """

    if not interface_exists(interface):
        return None

    try:
        address = conf.iface.ip

        # Only use this if Scapy's currently selected interface
        # is the interface we requested.
        if str(conf.iface) == interface:
            address = conf.iface.ip
        else:
            # Scapy's interface resolver can resolve the interface
            # without executing a shell command.
            resolved = conf.ifaces.dev_from_name(interface)

            if resolved is None:
                return None

            address = resolved.ip

    except Exception:
        return None

    if not isinstance(address, str):
        return None

    try:
        socket.inet_aton(address)

    except OSError:
        return None

    if address == "0.0.0.0":
        return None

    return address


# ============================================================
# PRIMARY INTERFACE DISCOVERY
# ============================================================

def discover_primary_interface(
    interfaces: list[str],
) -> Optional[str]:
    """
    Determine the interface used by the system's routing table
    for the default route.

    This avoids assumptions such as:
        ens33
        eth0
        enp3s0
        wlan0

    The operating system decides which interface is currently
    preferred for outbound network traffic.

    Returns:
        The validated primary interface, or None.
    """

    if not interfaces:
        return None

    interface_set = set(interfaces)

    try:
        route = conf.route.route("0.0.0.0")

    except Exception as exc:
        print(
            f"[WARNING] Unable to determine default route: {exc}"
        )
        return None

    if not route or len(route) < 1:
        return None

    interface = route[0]

    if not isinstance(interface, str):
        return None

    interface = interface.strip()

    # Never trust the route result blindly.
    if interface not in interface_set:
        return None

    if not interface_exists(interface):
        return None

    ipv4 = get_interface_ipv4(interface)

    if ipv4 is None:
        return None

    return interface


# ============================================================
# FALLBACK INTERFACE SELECTION
# ============================================================

def select_fallback_interface(
    interfaces: list[str],
) -> Optional[str]:
    """
    Select a usable interface if the routing table could not
    identify the primary interface.

    The fallback only considers interfaces that have a valid
    IPv4 address.

    This is intentionally conservative.
    """

    candidates: list[str] = []

    for interface in interfaces:

        if interface in EXCLUDED_INTERFACES:
            continue

        if not interface_exists(interface):
            continue

        ipv4 = get_interface_ipv4(interface)

        if ipv4 is None:
            continue

        candidates.append(interface)

    if not candidates:
        return None

    # Deterministic selection.
    return sorted(candidates)[0]


# ============================================================
# INTERFACE SELECTION
# ============================================================

def select_monitoring_interface() -> Optional[str]:
    """
    Discover and select the most appropriate interface.

    Priority:

        1. Discover available interfaces
        2. Use the interface selected by the default route
        3. Fall back to a validated IPv4-capable interface

    No interface name is hard-coded.
    """

    interfaces = discover_interfaces()

    if not interfaces:

        print(
            "[ERROR] No usable network interfaces discovered."
        )

        return None

    print(
        f"[DISCOVERY] Interfaces found: "
        f"{', '.join(interfaces)}"
    )

    primary = discover_primary_interface(
        interfaces
    )

    if primary is not None:

        print(
            f"[DISCOVERY] Primary interface: {primary}"
        )

        return primary

    print(
        "[WARNING] Primary interface could not be "
        "determined."
    )

    fallback = select_fallback_interface(
        interfaces
    )

    if fallback is None:

        print(
            "[ERROR] No IPv4-capable interface "
            "available for monitoring."
        )

        return None

    print(
        f"[DISCOVERY] Fallback interface selected: "
        f"{fallback}"
    )

    return fallback


# ============================================================
# PACKET METADATA VALIDATION
# ============================================================

def valid_ip(value: object) -> bool:
    """
    Validate an IPv4 address representation.
    """

    if not isinstance(value, str):
        return False

    if not (0 < len(value) <= MAX_IP_LENGTH):
        return False

    try:
        socket.inet_aton(value)

    except OSError:
        return False

    return True


def valid_port(value: object) -> bool:
    """
    Validate a network port.
    """

    return (
        isinstance(value, int)
        and 0 <= value <= MAX_PORT
    )


def valid_protocol(value: object) -> bool:
    """
    Validate an IP protocol number.
    """

    return (
        isinstance(value, int)
        and 0 <= value <= MAX_PROTOCOL
    )


def valid_packet_size(value: object) -> bool:
    """
    Validate captured packet size.
    """

    return (
        isinstance(value, int)
        and 0 < value <= MAX_PACKET_SIZE
    )


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(
    packet,
    interface: str,
) -> None:
    """
    Extract sanitized metadata from an IPv4 packet.

    IMPORTANT:
        The payload is never inspected.

    The packet itself is not stored after this callback returns.
    """

    if shutdown_requested:
        return

    # --------------------------------------------------------
    # Layer validation
    # --------------------------------------------------------

    if IP not in packet:
        return

    ip = packet[IP]

    # --------------------------------------------------------
    # Extract IP metadata
    # --------------------------------------------------------

    source_ip = str(ip.src)
    destination_ip = str(ip.dst)
    protocol = int(ip.proto)
    packet_size = len(packet)

    # --------------------------------------------------------
    # Validate metadata
    # --------------------------------------------------------

    if not valid_ip(source_ip):
        return

    if not valid_ip(destination_ip):
        return

    if not valid_protocol(protocol):
        return

    if not valid_packet_size(packet_size):
        return

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )

    # --------------------------------------------------------
    # Default values
    # --------------------------------------------------------

    source_port = "-"
    destination_port = "-"
    tcp_flags = "-"

    # --------------------------------------------------------
    # TCP metadata
    # --------------------------------------------------------

    if TCP in packet:

        tcp = packet[TCP]

        source_port_value = int(tcp.sport)
        destination_port_value = int(tcp.dport)

        if not valid_port(source_port_value):
            return

        if not valid_port(destination_port_value):
            return

        source_port = source_port_value
        destination_port = destination_port_value

        # Only TCP flags are extracted.
        # No TCP payload is inspected.
        tcp_flags = str(tcp.flags)

    # --------------------------------------------------------
    # UDP metadata
    # --------------------------------------------------------

    elif UDP in packet:

        udp = packet[UDP]

        source_port_value = int(udp.sport)
        destination_port_value = int(udp.dport)

        if not valid_port(source_port_value):
            return

        if not valid_port(destination_port_value):
            return

        source_port = source_port_value
        destination_port = destination_port_value

    # --------------------------------------------------------
    # Display metadata
    # --------------------------------------------------------

    print("\n--- Packet Captured ---")
    print(f"Interface       : {interface}")
    print(f"Timestamp       : {timestamp}")
    print(f"Source IP       : {source_ip}")
    print(f"Destination IP  : {destination_ip}")
    print(f"Source Port     : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Protocol        : {protocol}")
    print(f"Packet Size     : {packet_size} bytes")
    print(f"TCP Flags       : {tcp_flags}")


# ============================================================
# PACKET CAPTURE
# ============================================================

def start_capture(interface: str) -> int:
    """
    Start live packet capture on a validated interface.
    """

    if not interface_exists(interface):

        print(
            f"[ERROR] Interface validation failed: "
            f"{interface}"
        )

        return 1

    ipv4 = get_interface_ipv4(interface)

    if ipv4 is None:

        print(
            f"[ERROR] Interface {interface} does not "
            "have a usable IPv4 address."
        )

        return 1

    print()
    print(
        f"[CAPTURE] Interface : {interface}"
    )

    print(
        f"[CAPTURE] IPv4       : {ipv4}"
    )

    print(
        "[CAPTURE] Filter     : IPv4"
    )

    print(
        "[CAPTURE] Storage    : Disabled"
    )

    print()

    try:

        sniff(
            iface=interface,

            # Kernel/libpcap-level filtering reduces the
            # amount of irrelevant traffic delivered to Python.
            filter="ip",

            prn=lambda packet: process_packet(
                packet,
                interface,
            ),

            # Critical security/resource property:
            # Scapy does not retain captured packets.
            store=False,

            stop_filter=lambda _: shutdown_requested,
        )

    except PermissionError:

        print(
            "[ERROR] Packet capture permission denied."
        )

        print(
            "[INFO] Run with the required network "
            "capture privileges."
        )

        return 1

    except OSError as exc:

        print(
            f"[ERROR] Network capture failed: {exc}"
        )

        return 1

    except Exception as exc:

        print(
            f"[ERROR] Unexpected capture failure: {exc}"
        )

        return 1

    return 0


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    # --------------------------------------------------------
    # Privilege check
    # --------------------------------------------------------

    if hasattr(os, "geteuid"):

        if os.geteuid() != 0:

            print(
                "[WARNING] NeuraShield is not running "
                "with elevated capture privileges."
            )

            print(
                "[INFO] Packet capture may fail depending "
                "on system configuration."
            )

    # --------------------------------------------------------
    # Signal handlers
    # --------------------------------------------------------

    signal.signal(
        signal.SIGINT,
        shutdown_handler,
    )

    signal.signal(
        signal.SIGTERM,
        shutdown_handler,
    )

    # --------------------------------------------------------
    # Automatic interface selection
    # --------------------------------------------------------

    interface = select_monitoring_interface()

    if interface is None:
        return 1

    # --------------------------------------------------------
    # Startup display
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("          NEURASHIELD - LIVE MONITORING")
    print("=" * 60)

    print(
        "Interface Discovery : AUTOMATIC"
    )

    print(
        f"Selected Interface  : {interface}"
    )

    ipv4 = get_interface_ipv4(interface)

    print(
        f"Interface IPv4      : {ipv4}"
    )

    print(
        "Payload Inspection  : Disabled"
    )

    print(
        "Raw Packet Storage   : Disabled"
    )

    print(
        "Status              : ACTIVE"
    )

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 60)

    # --------------------------------------------------------
    # Capture
    # --------------------------------------------------------

    result = start_capture(interface)

    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("        NEURASHIELD - STOPPED")
    print("=" * 60)

    return result


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
