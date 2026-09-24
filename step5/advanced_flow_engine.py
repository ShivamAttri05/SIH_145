from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import sys
import os


# ============================================================
# STEP 5
# BIDIRECTIONAL FLOW RECONSTRUCTION
# ============================================================


# ------------------------------------------------------------
# Protocol Detection
# ------------------------------------------------------------

def get_protocol(packet):

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    else:
        return "OTHER"


# ------------------------------------------------------------
# Get packet endpoint information
# ------------------------------------------------------------

def get_endpoint(packet):

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


# ------------------------------------------------------------
# Create canonical bidirectional key
# ------------------------------------------------------------

def get_bidirectional_key(packet):

    src_ip, dst_ip, src_port, dst_port, protocol = (
        get_endpoint(packet)
    )

    endpoint_a = (
        src_ip,
        src_port
    )

    endpoint_b = (
        dst_ip,
        dst_port
    )

    # Sort endpoints so that A → B and B → A
    # generate the same flow key.

    if endpoint_a <= endpoint_b:

        first = endpoint_a
        second = endpoint_b

    else:

        first = endpoint_b
        second = endpoint_a

    return (
        first[0],
        first[1],
        second[0],
        second[1],
        protocol
    )


# ------------------------------------------------------------
# Extract bidirectional flows
# ------------------------------------------------------------

def extract_bidirectional_flows(pcap_file):

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Total packets: {len(packets)}")

    flows = defaultdict(lambda: {

        "first_timestamp": None,

        "last_timestamp": None,

        "forward_packets": 0,

        "reverse_packets": 0,

        "forward_bytes": 0,

        "reverse_bytes": 0,

        "initiator_ip": None,

        "initiator_port": None,

        "responder_ip": None,

        "responder_port": None,

        "protocol": None

    })


    for packet in packets:

        # ----------------------------------------------------
        # Ignore non-IP packets
        # ----------------------------------------------------

        if not packet.haslayer(IP):

            continue


        # ----------------------------------------------------
        # Current packet information
        # ----------------------------------------------------

        src_ip, dst_ip, src_port, dst_port, protocol = (
            get_endpoint(packet)
        )


        flow_key = get_bidirectional_key(packet)


        timestamp = float(packet.time)

        packet_size = len(packet)


        flow = flows[flow_key]


        # ----------------------------------------------------
        # First packet determines initial direction
        # ----------------------------------------------------

        if flow["first_timestamp"] is None:

            flow["first_timestamp"] = timestamp

            flow["initiator_ip"] = src_ip

            flow["initiator_port"] = src_port

            flow["responder_ip"] = dst_ip

            flow["responder_port"] = dst_port

            flow["protocol"] = protocol


        # ----------------------------------------------------
        # Last timestamp
        # ----------------------------------------------------

        flow["last_timestamp"] = timestamp


        # ----------------------------------------------------
        # Determine packet direction
        # ----------------------------------------------------

        if (

            src_ip == flow["initiator_ip"]

            and

            src_port == flow["initiator_port"]

            and

            dst_ip == flow["responder_ip"]

            and

            dst_port == flow["responder_port"]

        ):

            # Forward direction

            flow["forward_packets"] += 1

            flow["forward_bytes"] += packet_size


        else:

            # Reverse direction

            flow["reverse_packets"] += 1

            flow["reverse_bytes"] += packet_size


    return flows


# ============================================================
# FEATURE CALCULATION
# ============================================================

def calculate_features(flows):

    feature_list = []


    for flow_key, flow in flows.items():

        duration = (

            flow["last_timestamp"]

            -

            flow["first_timestamp"]

        )


        # ----------------------------------------------------
        # Total packets
        # ----------------------------------------------------

        total_packets = (

            flow["forward_packets"]

            +

            flow["reverse_packets"]

        )


        # ----------------------------------------------------
        # Total bytes
        # ----------------------------------------------------

        total_bytes = (

            flow["forward_bytes"]

            +

            flow["reverse_bytes"]

        )


        # ----------------------------------------------------
        # Rate calculation
        # ----------------------------------------------------

        if duration > 0:

            packets_per_sec = (
                total_packets
                /
                duration
            )

            bytes_per_sec = (
                total_bytes
                /
                duration
            )

        else:

            packets_per_sec = 0

            bytes_per_sec = 0


        # ----------------------------------------------------
        # Average packet size
        # ----------------------------------------------------

        if total_packets > 0:

            avg_packet_size = (
                total_bytes
                /
                total_packets
            )

        else:

            avg_packet_size = 0


        # ----------------------------------------------------
        # Forward / Reverse byte ratio
        # ----------------------------------------------------

        if flow["reverse_bytes"] > 0:

            forward_reverse_ratio = (

                flow["forward_bytes"]

                /

                flow["reverse_bytes"]

            )

        else:

            forward_reverse_ratio = 0


        # ----------------------------------------------------
        # Forward / Reverse packet ratio
        # ----------------------------------------------------

        if flow["reverse_packets"] > 0:

            forward_reverse_packet_ratio = (

                flow["forward_packets"]

                /

                flow["reverse_packets"]

            )

        else:

            forward_reverse_packet_ratio = 0


        # ----------------------------------------------------
        # Feature record
        # ----------------------------------------------------

        features = {

            "initiator_ip":
                flow["initiator_ip"],

            "initiator_port":
                flow["initiator_port"],

            "responder_ip":
                flow["responder_ip"],

            "responder_port":
                flow["responder_port"],

            "protocol":
                flow["protocol"],

            "forward_packets":
                flow["forward_packets"],

            "reverse_packets":
                flow["reverse_packets"],

            "forward_bytes":
                flow["forward_bytes"],

            "reverse_bytes":
                flow["reverse_bytes"],

            "total_packets":
                total_packets,

            "total_bytes":
                total_bytes,

            "duration":
                duration,

            "packets_per_sec":
                packets_per_sec,

            "bytes_per_sec":
                bytes_per_sec,

            "avg_packet_size":
                avg_packet_size,

            "forward_reverse_byte_ratio":
                forward_reverse_ratio,

            "forward_reverse_packet_ratio":
                forward_reverse_packet_ratio
        }


        feature_list.append(features)


    return feature_list


# ============================================================
# DISPLAY
# ============================================================

def display_features(features):

    print("\n")

    print("=" * 110)

    print("BIDIRECTIONAL NETWORK FLOWS")

    print("=" * 110)


    for index, feature in enumerate(
        features,
        start=1
    ):

        print(
            f"\nFlow #{index}"
        )

        print(
            f"Initiator IP:       "
            f"{feature['initiator_ip']}"
        )

        print(
            f"Initiator Port:     "
            f"{feature['initiator_port']}"
        )

        print(
            f"Responder IP:       "
            f"{feature['responder_ip']}"
        )

        print(
            f"Responder Port:     "
            f"{feature['responder_port']}"
        )

        print(
            f"Protocol:           "
            f"{feature['protocol']}"
        )

        print(
            f"Forward Packets:    "
            f"{feature['forward_packets']}"
        )

        print(
            f"Reverse Packets:    "
            f"{feature['reverse_packets']}"
        )

        print(
            f"Forward Bytes:      "
            f"{feature['forward_bytes']}"
        )

        print(
            f"Reverse Bytes:      "
            f"{feature['reverse_bytes']}"
        )

        print(
            f"Total Packets:      "
            f"{feature['total_packets']}"
        )

        print(
            f"Total Bytes:        "
            f"{feature['total_bytes']}"
        )

        print(
            f"Duration:            "
            f"{feature['duration']:.4f} seconds"
        )

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

        print(
            f"Fwd/Rev Byte Ratio: "
            f"{feature['forward_reverse_byte_ratio']:.4f}"
        )

        print(
            f"Fwd/Rev Packet Ratio:"
            f" {feature['forward_reverse_packet_ratio']:.4f}"
        )

        print("-" * 90)


    print("\n")

    print("=" * 110)

    print(
        f"Total bidirectional flows: "
        f"{len(features)}"
    )

    print("=" * 110)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: "
            "python step5/advanced_flow_engine.py "
            "step1/sample.pcapng"
        )

        return


    pcap_file = sys.argv[1]


    if not os.path.exists(pcap_file):

        print(
            f"\nERROR: PCAP file not found: "
            f"{pcap_file}"
        )

        return


    # --------------------------------------------------------
    # Extract bidirectional flows
    # --------------------------------------------------------

    flows = extract_bidirectional_flows(
        pcap_file
    )


    # --------------------------------------------------------
    # Calculate features
    # --------------------------------------------------------

    features = calculate_features(
        flows
    )


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_features(
        features
    )


if __name__ == "__main__":

    main()