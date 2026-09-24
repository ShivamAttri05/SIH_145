from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import math
import sys
import os


# ============================================================
# STEP 6
# SECURITY-SPECIFIC FEATURE EXTRACTION
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
# Endpoint extraction
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
# Bidirectional flow key
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


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(value):

    if not value:

        return 0.0

    frequency = defaultdict(int)

    for character in value:

        frequency[character] += 1

    length = len(value)

    entropy = 0.0

    for count in frequency.values():

        probability = count / length

        entropy -= (
            probability
            *
            math.log2(probability)
        )

    return entropy


# ============================================================
# PACKET ANALYSIS
# ============================================================

def analyze_packets(pcap_file):

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Total packets: {len(packets)}")


    flows = defaultdict(lambda: {

        "first_timestamp": None,

        "last_timestamp": None,

        "initiator_ip": None,

        "initiator_port": None,

        "responder_ip": None,

        "responder_port": None,

        "protocol": None,

        "forward_packets": 0,

        "reverse_packets": 0,

        "forward_bytes": 0,

        "reverse_bytes": 0,

        "syn_packets": 0,

        "ack_packets": 0,

        "rst_packets": 0,

        "fin_packets": 0,

        "timestamps": [],

        "packet_sizes": [],

        "dns_packets": 0,

        "dns_lengths": [],

        "dns_entropies": []

    })


    for packet in packets:

        # ----------------------------------------------------
        # Ignore non-IP
        # ----------------------------------------------------

        if not packet.haslayer(IP):

            continue


        src_ip, dst_ip, src_port, dst_port, protocol = (
            get_endpoint(packet)
        )


        flow_key = get_bidirectional_key(packet)

        timestamp = float(packet.time)

        packet_size = len(packet)


        flow = flows[flow_key]


        # ----------------------------------------------------
        # First packet
        # ----------------------------------------------------

        if flow["first_timestamp"] is None:

            flow["first_timestamp"] = timestamp

            flow["initiator_ip"] = src_ip

            flow["initiator_port"] = src_port

            flow["responder_ip"] = dst_ip

            flow["responder_port"] = dst_port

            flow["protocol"] = protocol


        # ----------------------------------------------------
        # Last packet
        # ----------------------------------------------------

        flow["last_timestamp"] = timestamp


        # ----------------------------------------------------
        # Store timing information
        # ----------------------------------------------------

        flow["timestamps"].append(timestamp)


        # ----------------------------------------------------
        # Store packet size
        # ----------------------------------------------------

        flow["packet_sizes"].append(packet_size)


        # ----------------------------------------------------
        # Direction
        # ----------------------------------------------------

        is_forward = (

            src_ip == flow["initiator_ip"]

            and

            src_port == flow["initiator_port"]

            and

            dst_ip == flow["responder_ip"]

            and

            dst_port == flow["responder_port"]

        )


        if is_forward:

            flow["forward_packets"] += 1

            flow["forward_bytes"] += packet_size

        else:

            flow["reverse_packets"] += 1

            flow["reverse_bytes"] += packet_size


        # ====================================================
        # TCP FEATURES
        # ====================================================

        if protocol == "TCP":

            flags = packet[TCP].flags


            if flags & 0x02:

                flow["syn_packets"] += 1


            if flags & 0x10:

                flow["ack_packets"] += 1


            if flags & 0x04:

                flow["rst_packets"] += 1


            if flags & 0x01:

                flow["fin_packets"] += 1


        # ====================================================
        # DNS FEATURES
        # ====================================================

        if packet.haslayer(UDP):

            if (
                packet[UDP].sport == 53
                or
                packet[UDP].dport == 53
            ):

                flow["dns_packets"] += 1


                # --------------------------------------------
                # DNS payload approximation
                # --------------------------------------------

                try:

                    dns_payload = bytes(
                        packet[UDP].payload
                    )

                    dns_length = len(
                        dns_payload
                    )

                    flow["dns_lengths"].append(
                        dns_length
                    )


                    # Convert payload to text where possible
                    dns_text = ""

                    for byte in dns_payload:

                        if 32 <= byte <= 126:

                            dns_text += chr(byte)


                    if dns_text:

                        entropy = calculate_entropy(
                            dns_text
                        )

                        flow["dns_entropies"].append(
                            entropy
                        )

                except Exception:

                    pass


    return flows


# ============================================================
# FEATURE CALCULATION
# ============================================================

def calculate_security_features(flows):

    features_list = []


    for flow_key, flow in flows.items():

        total_packets = (

            flow["forward_packets"]

            +

            flow["reverse_packets"]

        )


        total_bytes = (

            flow["forward_bytes"]

            +

            flow["reverse_bytes"]

        )


        duration = (

            flow["last_timestamp"]

            -

            flow["first_timestamp"]

        )


        # ----------------------------------------------------
        # Packet rate
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
        # SYN ratio
        # ----------------------------------------------------

        if total_packets > 0:

            syn_ratio = (
                flow["syn_packets"]
                /
                total_packets
            )

            ack_ratio = (
                flow["ack_packets"]
                /
                total_packets
            )

            rst_ratio = (
                flow["rst_packets"]
                /
                total_packets
            )

            fin_ratio = (
                flow["fin_packets"]
                /
                total_packets
            )

        else:

            syn_ratio = 0

            ack_ratio = 0

            rst_ratio = 0

            fin_ratio = 0


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
        # Packet size standard deviation
        # ----------------------------------------------------

        if len(flow["packet_sizes"]) > 1:

            mean_size = (
                sum(flow["packet_sizes"])
                /
                len(flow["packet_sizes"])
            )

            variance = (

                sum(
                    (
                        size - mean_size
                    ) ** 2

                    for size
                    in flow["packet_sizes"]
                )

                /

                len(flow["packet_sizes"])

            )

            packet_size_std = math.sqrt(
                variance
            )

        else:

            packet_size_std = 0


        # ----------------------------------------------------
        # Inter-arrival time
        # ----------------------------------------------------

        timestamps = sorted(
            flow["timestamps"]
        )


        inter_arrivals = []


        for i in range(
            1,
            len(timestamps)
        ):

            difference = (
                timestamps[i]
                -
                timestamps[i - 1]
            )

            inter_arrivals.append(
                difference
            )


        if inter_arrivals:

            average_inter_arrival = (

                sum(inter_arrivals)
                /
                len(inter_arrivals)

            )

        else:

            average_inter_arrival = 0


        # ----------------------------------------------------
        # DNS features
        # ----------------------------------------------------

        dns_packet_count = flow["dns_packets"]


        if flow["dns_lengths"]:

            average_dns_length = (

                sum(flow["dns_lengths"])
                /
                len(flow["dns_lengths"])

            )

        else:

            average_dns_length = 0


        if flow["dns_entropies"]:

            average_dns_entropy = (

                sum(flow["dns_entropies"])
                /
                len(flow["dns_entropies"])

            )

        else:

            average_dns_entropy = 0


        # ----------------------------------------------------
        # Security feature record
        # ----------------------------------------------------

        feature = {

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

            "packet_size_std":
                packet_size_std,

            "syn_packets":
                flow["syn_packets"],

            "ack_packets":
                flow["ack_packets"],

            "rst_packets":
                flow["rst_packets"],

            "fin_packets":
                flow["fin_packets"],

            "syn_ratio":
                syn_ratio,

            "ack_ratio":
                ack_ratio,

            "rst_ratio":
                rst_ratio,

            "fin_ratio":
                fin_ratio,

            "average_inter_arrival":
                average_inter_arrival,

            "dns_packet_count":
                dns_packet_count,

            "average_dns_length":
                average_dns_length,

            "average_dns_entropy":
                average_dns_entropy

        }


        features_list.append(
            feature
        )


    return features_list


# ============================================================
# DISPLAY
# ============================================================

def display_features(features):

    print("\n")

    print("=" * 110)

    print(
        "SECURITY FEATURES"
    )

    print("=" * 110)


    for index, feature in enumerate(
        features,
        start=1
    ):

        print(
            f"\nFlow #{index}"
        )

        print(
            f"Initiator:          "
            f"{feature['initiator_ip']}:"
            f"{feature['initiator_port']}"
        )

        print(
            f"Responder:          "
            f"{feature['responder_ip']}:"
            f"{feature['responder_port']}"
        )

        print(
            f"Protocol:           "
            f"{feature['protocol']}"
        )

        print("-" * 90)

        print(
            f"Total Packets:      "
            f"{feature['total_packets']}"
        )

        print(
            f"Total Bytes:        "
            f"{feature['total_bytes']}"
        )

        print(
            f"Duration:           "
            f"{feature['duration']:.4f} sec"
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
            f"{feature['avg_packet_size']:.2f}"
        )

        print(
            f"Packet Size Std:    "
            f"{feature['packet_size_std']:.2f}"
        )

        print("-" * 90)

        print(
            f"SYN Packets:        "
            f"{feature['syn_packets']}"
        )

        print(
            f"ACK Packets:        "
            f"{feature['ack_packets']}"
        )

        print(
            f"RST Packets:        "
            f"{feature['rst_packets']}"
        )

        print(
            f"FIN Packets:        "
            f"{feature['fin_packets']}"
        )

        print(
            f"SYN Ratio:          "
            f"{feature['syn_ratio']:.4f}"
        )

        print(
            f"ACK Ratio:          "
            f"{feature['ack_ratio']:.4f}"
        )

        print(
            f"RST Ratio:          "
            f"{feature['rst_ratio']:.4f}"
        )

        print(
            f"FIN Ratio:          "
            f"{feature['fin_ratio']:.4f}"
        )

        print("-" * 90)

        print(
            f"Avg Inter-arrival:  "
            f"{feature['average_inter_arrival']:.4f} sec"
        )

        print(
            f"DNS Packets:        "
            f"{feature['dns_packet_count']}"
        )

        print(
            f"Avg DNS Length:     "
            f"{feature['average_dns_length']:.2f}"
        )

        print(
            f"Avg DNS Entropy:    "
            f"{feature['average_dns_entropy']:.4f}"
        )

        print("-" * 90)


    print("\n")

    print("=" * 110)

    print(
        f"Total security feature records: "
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
            "python step6/security_features.py "
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
    # Analyze packets
    # --------------------------------------------------------

    flows = analyze_packets(
        pcap_file
    )


    # --------------------------------------------------------
    # Calculate security features
    # --------------------------------------------------------

    features = calculate_security_features(
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