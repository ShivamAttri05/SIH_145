from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import sys
import os


# ============================================================
# STEP 7
# SOURCE-LEVEL BEHAVIORAL ANALYSIS
# ============================================================


# ------------------------------------------------------------
# Protocol detection
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
# FLOW EXTRACTION
# ============================================================

def extract_flows(pcap_file):

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(
        f"Total packets: {len(packets)}"
    )


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

        "reverse_bytes": 0

    })


    for packet in packets:

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


    return flows


# ============================================================
# SOURCE BEHAVIOR ANALYSIS
# ============================================================

def analyze_source_behavior(flows):

    sources = defaultdict(lambda: {

        "destination_ips": set(),

        "destination_ports": set(),

        "connections": [],

        "total_bytes_sent": 0,

        "total_bytes_received": 0,

        "total_packets_sent": 0,

        "total_packets_received": 0

    })


    # --------------------------------------------------------
    # Aggregate every flow by initiator
    # --------------------------------------------------------

    for flow_key, flow in flows.items():

        source_ip = flow["initiator_ip"]

        destination_ip = flow["responder_ip"]

        destination_port = flow["responder_port"]


        source = sources[source_ip]


        # ----------------------------------------------------
        # Destination tracking
        # ----------------------------------------------------

        source["destination_ips"].add(
            destination_ip
        )


        if destination_port != 0:

            source["destination_ports"].add(
                destination_port
            )


        # ----------------------------------------------------
        # Connection timing
        # ----------------------------------------------------

        source["connections"].append(
            flow["first_timestamp"]
        )


        # ----------------------------------------------------
        # Traffic direction
        # ----------------------------------------------------

        source["total_bytes_sent"] += (
            flow["forward_bytes"]
        )

        source["total_bytes_received"] += (
            flow["reverse_bytes"]
        )


        source["total_packets_sent"] += (
            flow["forward_packets"]
        )

        source["total_packets_received"] += (
            flow["reverse_packets"]
        )


    return sources


# ============================================================
# CALCULATE BEHAVIOR FEATURES
# ============================================================

def calculate_behavior_features(sources):

    behavior_features = []


    for source_ip, source in sources.items():

        # ----------------------------------------------------
        # Unique destinations
        # ----------------------------------------------------

        unique_destination_ips = len(
            source["destination_ips"]
        )


        # ----------------------------------------------------
        # Unique ports
        # ----------------------------------------------------

        unique_destination_ports = len(
            source["destination_ports"]
        )


        # ----------------------------------------------------
        # Connections
        # ----------------------------------------------------

        total_connections = len(
            source["connections"]
        )


        # ----------------------------------------------------
        # Connection rate
        # ----------------------------------------------------

        timestamps = sorted(
            source["connections"]
        )


        if len(timestamps) >= 2:

            time_span = (
                timestamps[-1]
                -
                timestamps[0]
            )

            if time_span > 0:

                connections_per_second = (
                    total_connections
                    /
                    time_span
                )

            else:

                connections_per_second = 0

        else:

            connections_per_second = 0


        # ----------------------------------------------------
        # Outbound / inbound ratio
        # ----------------------------------------------------

        bytes_sent = (
            source["total_bytes_sent"]
        )

        bytes_received = (
            source["total_bytes_received"]
        )


        if bytes_received > 0:

            outbound_inbound_ratio = (
                bytes_sent
                /
                bytes_received
            )

        else:

            outbound_inbound_ratio = 0


        # ----------------------------------------------------
        # Packet ratio
        # ----------------------------------------------------

        packets_sent = (
            source["total_packets_sent"]
        )

        packets_received = (
            source["total_packets_received"]
        )


        if packets_received > 0:

            packet_direction_ratio = (
                packets_sent
                /
                packets_received
            )

        else:

            packet_direction_ratio = 0


        # ----------------------------------------------------
        # Feature record
        # ----------------------------------------------------

        feature = {

            "source_ip":
                source_ip,

            "unique_destination_ips":
                unique_destination_ips,

            "unique_destination_ports":
                unique_destination_ports,

            "total_connections":
                total_connections,

            "connections_per_second":
                connections_per_second,

            "total_bytes_sent":
                bytes_sent,

            "total_bytes_received":
                bytes_received,

            "outbound_inbound_ratio":
                outbound_inbound_ratio,

            "total_packets_sent":
                packets_sent,

            "total_packets_received":
                packets_received,

            "packet_direction_ratio":
                packet_direction_ratio

        }


        behavior_features.append(
            feature
        )


    return behavior_features


# ============================================================
# DISPLAY
# ============================================================

def display_behavior(
    behavior_features
):

    print("\n")

    print("=" * 110)

    print(
        "SOURCE-LEVEL BEHAVIORAL FEATURES"
    )

    print("=" * 110)


    for index, feature in enumerate(
        behavior_features,
        start=1
    ):

        print(
            f"\nSource #{index}"
        )

        print(
            f"Source IP:              "
            f"{feature['source_ip']}"
        )

        print("-" * 90)

        print(
            f"Unique Destination IPs: "
            f"{feature['unique_destination_ips']}"
        )

        print(
            f"Unique Destination Ports:"
            f" {feature['unique_destination_ports']}"
        )

        print(
            f"Total Connections:      "
            f"{feature['total_connections']}"
        )

        print(
            f"Connections/sec:        "
            f"{feature['connections_per_second']:.4f}"
        )

        print("-" * 90)

        print(
            f"Bytes Sent:             "
            f"{feature['total_bytes_sent']}"
        )

        print(
            f"Bytes Received:         "
            f"{feature['total_bytes_received']}"
        )

        print(
            f"Outbound/Inbound Ratio: "
            f"{feature['outbound_inbound_ratio']:.4f}"
        )

        print(
            f"Packets Sent:           "
            f"{feature['total_packets_sent']}"
        )

        print(
            f"Packets Received:       "
            f"{feature['total_packets_received']}"
        )

        print(
            f"Packet Direction Ratio: "
            f"{feature['packet_direction_ratio']:.4f}"
        )

        print("-" * 90)


    print("\n")

    print("=" * 110)

    print(
        f"Total sources analyzed: "
        f"{len(behavior_features)}"
    )

    print("=" * 110)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: "
            "python step7/behavior_engine.py "
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
    # Extract flows
    # --------------------------------------------------------

    flows = extract_flows(
        pcap_file
    )


    # --------------------------------------------------------
    # Analyze sources
    # --------------------------------------------------------

    sources = analyze_source_behavior(
        flows
    )


    # --------------------------------------------------------
    # Calculate behavioral features
    # --------------------------------------------------------

    behavior_features = (
        calculate_behavior_features(
            sources
        )
    )


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_behavior(
        behavior_features
    )


if __name__ == "__main__":

    main()