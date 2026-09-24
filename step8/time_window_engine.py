from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import sys
import os


# ============================================================
# STEP 8
# TIME-WINDOW BEHAVIORAL ANALYSIS
# ============================================================


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

WINDOW_SIZE = 10.0


# ============================================================
# PROTOCOL DETECTION
# ============================================================

def get_protocol(packet):

    if packet.haslayer(TCP):

        return "TCP"

    elif packet.haslayer(UDP):

        return "UDP"

    else:

        return "OTHER"


# ============================================================
# ENDPOINT EXTRACTION
# ============================================================

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


# ============================================================
# CREATE TIME WINDOWS
# ============================================================

def create_windows(packets):

    if not packets:

        return {}


    # --------------------------------------------------------
    # Find beginning of capture
    # --------------------------------------------------------

    first_timestamp = float(
        packets[0].time
    )


    windows = defaultdict(list)


    # --------------------------------------------------------
    # Assign every packet to a window
    # --------------------------------------------------------

    for packet in packets:

        if not packet.haslayer(IP):

            continue


        timestamp = float(
            packet.time
        )


        relative_time = (
            timestamp
            -
            first_timestamp
        )


        window_number = int(
            relative_time
            /
            WINDOW_SIZE
        )


        windows[window_number].append(
            packet
        )


    return windows


# ============================================================
# ANALYZE A SINGLE WINDOW
# ============================================================

def analyze_window(packets):

    sources = defaultdict(lambda: {

        "destination_ips": set(),

        "destination_ports": set(),

        "packets": 0,

        "bytes": 0,

        "first_timestamp": None,

        "last_timestamp": None,

        "tcp_packets": 0,

        "syn_packets": 0,

        "ack_packets": 0,

        "rst_packets": 0,

        "fin_packets": 0

    })


    for packet in packets:

        if not packet.haslayer(IP):

            continue


        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = get_endpoint(packet)


        timestamp = float(
            packet.time
        )


        packet_size = len(
            packet
        )


        source = sources[
            src_ip
        ]


        # ----------------------------------------------------
        # Destination tracking
        # ----------------------------------------------------

        source[
            "destination_ips"
        ].add(
            dst_ip
        )


        if dst_port != 0:

            source[
                "destination_ports"
            ].add(
                dst_port
            )


        # ----------------------------------------------------
        # Traffic
        # ----------------------------------------------------

        source[
            "packets"
        ] += 1


        source[
            "bytes"
        ] += packet_size


        # ----------------------------------------------------
        # Timing
        # ----------------------------------------------------

        if (
            source["first_timestamp"]
            is None
        ):

            source[
                "first_timestamp"
            ] = timestamp


        source[
            "last_timestamp"
        ] = timestamp


        # ====================================================
        # TCP FLAGS
        # ====================================================

        if protocol == "TCP":

            source[
                "tcp_packets"
            ] += 1


            flags = packet[
                TCP
            ].flags


            if flags & 0x02:

                source[
                    "syn_packets"
                ] += 1


            if flags & 0x10:

                source[
                    "ack_packets"
                ] += 1


            if flags & 0x04:

                source[
                    "rst_packets"
                ] += 1


            if flags & 0x01:

                source[
                    "fin_packets"
                ] += 1


    return sources


# ============================================================
# CALCULATE WINDOW FEATURES
# ============================================================

def calculate_window_features(
    sources
):

    results = []


    for source_ip, source in sources.items():

        packets = source[
            "packets"
        ]


        bytes_total = source[
            "bytes"
        ]


        # ----------------------------------------------------
        # Duration
        # ----------------------------------------------------

        duration = (

            source["last_timestamp"]

            -

            source["first_timestamp"]

        )


        # ----------------------------------------------------
        # Packet rate
        # ----------------------------------------------------

        if duration > 0:

            packets_per_sec = (

                packets
                /
                duration

            )

            bytes_per_sec = (

                bytes_total
                /
                duration

            )

        else:

            packets_per_sec = 0

            bytes_per_sec = 0


        # ----------------------------------------------------
        # TCP ratios
        # ----------------------------------------------------

        if packets > 0:

            syn_ratio = (

                source["syn_packets"]
                /
                packets

            )

            ack_ratio = (

                source["ack_packets"]
                /
                packets

            )

            rst_ratio = (

                source["rst_packets"]
                /
                packets

            )

            fin_ratio = (

                source["fin_packets"]
                /
                packets

            )

        else:

            syn_ratio = 0

            ack_ratio = 0

            rst_ratio = 0

            fin_ratio = 0


        # ----------------------------------------------------
        # Feature record
        # ----------------------------------------------------

        result = {

            "source_ip":
                source_ip,

            "packets":
                packets,

            "bytes":
                bytes_total,

            "unique_destination_ips":
                len(
                    source[
                        "destination_ips"
                    ]
                ),

            "unique_destination_ports":
                len(
                    source[
                        "destination_ports"
                    ]
                ),

            "duration":
                duration,

            "packets_per_sec":
                packets_per_sec,

            "bytes_per_sec":
                bytes_per_sec,

            "tcp_packets":
                source[
                    "tcp_packets"
                ],

            "syn_packets":
                source[
                    "syn_packets"
                ],

            "ack_packets":
                source[
                    "ack_packets"
                ],

            "rst_packets":
                source[
                    "rst_packets"
                ],

            "fin_packets":
                source[
                    "fin_packets"
                ],

            "syn_ratio":
                syn_ratio,

            "ack_ratio":
                ack_ratio,

            "rst_ratio":
                rst_ratio,

            "fin_ratio":
                fin_ratio

        }


        results.append(
            result
        )


    return results


# ============================================================
# DISPLAY WINDOW
# ============================================================

def display_window(
    window_number,
    features
):

    start_time = (
        window_number
        *
        WINDOW_SIZE
    )


    end_time = (
        start_time
        +
        WINDOW_SIZE
    )


    print("\n")

    print("=" * 110)

    print(
        f"TIME WINDOW #{window_number + 1}"
    )

    print(
        f"Relative Time: "
        f"{start_time:.2f}s → "
        f"{end_time:.2f}s"
    )

    print("=" * 110)


    if not features:

        print(
            "No IP traffic in this window."
        )

        return


    for index, feature in enumerate(
        features,
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
            f"Packets:                "
            f"{feature['packets']}"
        )

        print(
            f"Bytes:                  "
            f"{feature['bytes']}"
        )

        print(
            f"Unique Destination IPs: "
            f"{feature['unique_destination_ips']}"
        )

        print(
            f"Unique Destination Ports:"
            f" {feature['unique_destination_ports']}"
        )

        print(
            f"Packets/sec:            "
            f"{feature['packets_per_sec']:.4f}"
        )

        print(
            f"Bytes/sec:              "
            f"{feature['bytes_per_sec']:.4f}"
        )

        print("-" * 90)


        print(
            f"TCP Packets:            "
            f"{feature['tcp_packets']}"
        )

        print(
            f"SYN Packets:            "
            f"{feature['syn_packets']}"
        )

        print(
            f"ACK Packets:            "
            f"{feature['ack_packets']}"
        )

        print(
            f"RST Packets:            "
            f"{feature['rst_packets']}"
        )

        print(
            f"FIN Packets:            "
            f"{feature['fin_packets']}"
        )


        print(
            f"SYN Ratio:              "
            f"{feature['syn_ratio']:.4f}"
        )

        print(
            f"ACK Ratio:              "
            f"{feature['ack_ratio']:.4f}"
        )

        print(
            f"RST Ratio:              "
            f"{feature['rst_ratio']:.4f}"
        )

        print(
            f"FIN Ratio:              "
            f"{feature['fin_ratio']:.4f}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: "
            "python step8/time_window_engine.py "
            "step1/sample.pcapng"
        )

        return


    pcap_file = sys.argv[1]


    if not os.path.exists(
        pcap_file
    ):

        print(
            f"\nERROR: PCAP file not found: "
            f"{pcap_file}"
        )

        return


    # --------------------------------------------------------
    # Read PCAP
    # --------------------------------------------------------

    print(
        f"\nReading PCAP: {pcap_file}"
    )


    packets = rdpcap(
        pcap_file
    )


    print(
        f"Total packets: "
        f"{len(packets)}"
    )


    # --------------------------------------------------------
    # Create windows
    # --------------------------------------------------------

    windows = create_windows(
        packets
    )


    print(
        f"Total time windows: "
        f"{len(windows)}"
    )


    # --------------------------------------------------------
    # Process each window
    # --------------------------------------------------------

    for window_number in sorted(
        windows.keys()
    ):

        window_packets = windows[
            window_number
        ]


        sources = analyze_window(
            window_packets
        )


        features = calculate_window_features(
            sources
        )


        display_window(
            window_number,
            features
        )


    print("\n")

    print("=" * 110)

    print(
        "TIME-WINDOW ANALYSIS COMPLETE"
    )

    print("=" * 110)


if __name__ == "__main__":

    main()