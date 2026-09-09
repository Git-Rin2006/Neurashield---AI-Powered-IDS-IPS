from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


INTERFACE = "ens33"


def process_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]

    source_ip = ip.src
    destination_ip = ip.dst
    protocol = ip.proto
    packet_size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    source_port = "-"
    destination_port = "-"
    tcp_flags = "-"

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    print("\n--- Packet Captured ---")
    print(f"Timestamp       : {timestamp}")
    print(f"Source IP       : {source_ip}")
    print(f"Destination IP  : {destination_ip}")
    print(f"Source Port     : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"Protocol        : {protocol}")
    print(f"Packet Size     : {packet_size} bytes")
    print(f"TCP Flags       : {tcp_flags}")


print(f"NeuraShield Packet Monitor")
print(f"Monitoring interface: {INTERFACE}")
print("Press Ctrl+C to stop.\n")

sniff(
    iface=INTERFACE,
    prn=process_packet,
    store=False
)
