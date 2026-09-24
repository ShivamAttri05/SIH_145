from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import sys
import os


def get_protocol(packet):
    """Return the transport protocol of a packet."""

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    return "OTHER"


def get_flow_key(packet):
    """
    Create a unique identifier for a network flow.

    A flow is identified using:

    Source IP
    Destination IP
    Source Port
    Destination Port
    Protocol
    """

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        src_port = 0
        dst_port = 0

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


def process_pcap(pcap_file):
    """Read a PCAP and convert packets into flows."""

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Total packets: {len(packets)}")

    flows = defaultdict(lambda: {
        "first_timestamp": None,
        "last_timestamp": None,
        "packet_count": 0,
        "byte_count": 0
    })

    for packet in packets:

        # Ignore packets that don't contain an IP layer
        if IP not in packet:
            continue

        flow_key = get_flow_key(packet)

        if flow_key is None:
            continue

        timestamp = float(packet.time)
        packet_size = len(packet)

        flow = flows[flow_key]

        # First packet
        if flow["first_timestamp"] is None:
            flow["first_timestamp"] = timestamp

        # Update last packet time
        flow["last_timestamp"] = timestamp

        # Update statistics
        flow["packet_count"] += 1
        flow["byte_count"] += packet_size

    return flows


def display_flows(flows):

    print("\n" + "=" * 90)
    print("NETWORK FLOWS")
    print("=" * 90)

    flow_number = 1

    for flow_key, data in flows.items():

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = flow_key

        duration = (
            data["last_timestamp"]
            - data["first_timestamp"]
        )

        print(f"\nFlow #{flow_number}")

        print(f"Source IP:       {src_ip}")
        print(f"Destination IP:  {dst_ip}")

        print(f"Source Port:     {src_port}")
        print(f"Destination Port:{dst_port}")

        print(f"Protocol:        {protocol}")

        print(f"Packets:         {data['packet_count']}")
        print(f"Bytes:           {data['byte_count']}")

        print(f"Duration:        {duration:.4f} seconds")

        flow_number += 1

    print("\n" + "=" * 90)
    print(f"Total flows: {len(flows)}")
    print("=" * 90)


def main():

    if len(sys.argv) < 2:
        print("Usage:")
        print("python flow_engine.py <pcap_file>")
        return

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        return

    flows = process_pcap(pcap_file)

    display_flows(flows)


if __name__ == "__main__":
    main()