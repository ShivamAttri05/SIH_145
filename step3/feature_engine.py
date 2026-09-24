from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import sys
import os


# ============================================================
# STEP 3 - FLOW FEATURE EXTRACTION
# ============================================================


def get_protocol(packet):
    """
    Identify the transport protocol.
    """

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    else:
        return "OTHER"


def get_flow_key(packet):
    """
    Create a directional flow identifier.

    Flow is identified using:

    Source IP
    Destination IP
    Source Port
    Destination Port
    Protocol
    """

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    if protocol == "TCP":
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif protocol == "UDP":
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


def extract_flows(pcap_file):
    """
    Read packets and group them into flows.
    """

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Total packets: {len(packets)}")

    flows = defaultdict(lambda: {
        "first_timestamp": None,
        "last_timestamp": None,
        "packets": 0,
        "bytes": 0
    })

    for packet in packets:

        # Ignore non-IP packets
        if not packet.haslayer(IP):
            continue

        flow_key = get_flow_key(packet)

        timestamp = float(packet.time)
        packet_size = len(packet)

        # First packet
        if flows[flow_key]["first_timestamp"] is None:
            flows[flow_key]["first_timestamp"] = timestamp

        # Update flow information
        flows[flow_key]["last_timestamp"] = timestamp

        flows[flow_key]["packets"] += 1
        flows[flow_key]["bytes"] += packet_size

    return flows


def calculate_features(flows):
    """
    Convert raw flow information into
    security-analysis features.
    """

    feature_list = []

    for flow_key, flow_data in flows.items():

        src_ip, dst_ip, src_port, dst_port, protocol = flow_key

        # ----------------------------------------------------
        # Duration
        # ----------------------------------------------------

        duration = (
            flow_data["last_timestamp"]
            - flow_data["first_timestamp"]
        )

        # Prevent division by zero
        if duration <= 0:
            duration_for_rate = 0.000001
        else:
            duration_for_rate = duration

        # ----------------------------------------------------
        # Packet rate
        # ----------------------------------------------------

        packets_per_sec = (
            flow_data["packets"]
            / duration_for_rate
        )

        # ----------------------------------------------------
        # Byte rate
        # ----------------------------------------------------

        bytes_per_sec = (
            flow_data["bytes"]
            / duration_for_rate
        )

        # ----------------------------------------------------
        # Average packet size
        # ----------------------------------------------------

        avg_packet_size = (
            flow_data["bytes"]
            / flow_data["packets"]
        )

        # ----------------------------------------------------
        # Create feature record
        # ----------------------------------------------------

        features = {

            "src_ip": src_ip,

            "dst_ip": dst_ip,

            "src_port": src_port,

            "dst_port": dst_port,

            "protocol": protocol,

            "packets": flow_data["packets"],

            "bytes": flow_data["bytes"],

            "duration": duration,

            "packets_per_sec": packets_per_sec,

            "bytes_per_sec": bytes_per_sec,

            "avg_packet_size": avg_packet_size
        }

        feature_list.append(features)

    return feature_list


def display_features(features):
    """
    Display extracted features.
    """

    print("\n")
    print("=" * 110)
    print("FLOW FEATURES")
    print("=" * 110)

    for index, feature in enumerate(features, start=1):

        print(f"\nFeature Record #{index}")

        print(f"Source IP:          {feature['src_ip']}")
        print(f"Destination IP:     {feature['dst_ip']}")

        print(f"Source Port:        {feature['src_port']}")
        print(f"Destination Port:   {feature['dst_port']}")

        print(f"Protocol:           {feature['protocol']}")

        print(f"Packets:            {feature['packets']}")
        print(f"Bytes:              {feature['bytes']}")

        print(f"Duration:           {feature['duration']:.4f} seconds")

        print(
            f"Packets/sec:        "
            f"{feature['packets_per_sec']:.4f}"
        )

        print(
            f"Bytes/sec:          "
            f"{feature['bytes_per_sec']:.4f}"
        )

        print(
            f"Average Packet:     "
            f"{feature['avg_packet_size']:.2f} bytes"
        )

        print("-" * 90)


def main():

    # --------------------------------------------------------
    # Check command-line argument
    # --------------------------------------------------------

    if len(sys.argv) < 2:

        print(
            "Usage: "
            "python step3/feature_engine.py "
            "step1/sample.pcapng"
        )

        return

    pcap_file = sys.argv[1]

    # --------------------------------------------------------
    # Check file
    # --------------------------------------------------------

    if not os.path.exists(pcap_file):

        print(f"\nERROR: PCAP file not found: {pcap_file}")

        return

    # --------------------------------------------------------
    # Extract flows
    # --------------------------------------------------------

    flows = extract_flows(pcap_file)

    # --------------------------------------------------------
    # Calculate features
    # --------------------------------------------------------

    features = calculate_features(flows)

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_features(features)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\n")
    print("=" * 110)

    print(
        f"Total feature records: {len(features)}"
    )

    print("=" * 110)


if __name__ == "__main__":
    main()