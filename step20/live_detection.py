import time
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

from step16.detection_service import DetectionService


INTERFACE = (
    r"\Device\NPF_"
    r"{45531478-3B92-4A0E-BCC9-39C804F74A7F}"
)

WINDOW_SIZE = 10.0


def create_source_record():

    return {
        "packets": 0,
        "bytes": 0,
        "destination_ips": set(),
        "destination_ports": set(),
        "timestamps": [],
        "tcp_packets": 0,
        "syn_packets": 0,
        "ack_packets": 0,
        "rst_packets": 0,
        "fin_packets": 0,
        "dns_packets": 0,
        "packet_objects": [],
    }


def process_packet(
    record,
    packet,
    capture_time,
):

    if IP not in packet:
        return

    record["packets"] += 1

    record["bytes"] += len(packet)

    record["destination_ips"].add(
        packet[IP].dst
    )

    record["timestamps"].append(
        capture_time
    )

    record["packet_objects"].append(
        packet
    )

    if TCP in packet:

        record["tcp_packets"] += 1

        record["destination_ports"].add(
            packet[TCP].dport
        )

        flags = packet[TCP].flags

        if flags & 0x02:
            record["syn_packets"] += 1

        if flags & 0x10:
            record["ack_packets"] += 1

        if flags & 0x04:
            record["rst_packets"] += 1

        if flags & 0x01:
            record["fin_packets"] += 1

    elif UDP in packet:

        if (
            packet[UDP].sport == 53
            or packet[UDP].dport == 53
        ):

            record["destination_ports"].add(
                53
            )

            record["dns_packets"] += 1


def build_features(record):

    packets = record["packets"]

    total_bytes = record["bytes"]

    timestamps = sorted(
        record["timestamps"]
    )

    if len(timestamps) >= 2:

        duration = (
            timestamps[-1]
            - timestamps[0]
        )

    else:

        duration = 0.0

    if duration > 0:

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            total_bytes / duration
        )

    else:

        packets_per_sec = 0.0
        bytes_per_sec = 0.0

    tcp_packets = record["tcp_packets"]

    if tcp_packets > 0:

        syn_ratio = (
            record["syn_packets"]
            / tcp_packets
        )

        ack_ratio = (
            record["ack_packets"]
            / tcp_packets
        )

        rst_ratio = (
            record["rst_packets"]
            / tcp_packets
        )

        fin_ratio = (
            record["fin_packets"]
            / tcp_packets
        )

    else:

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0

    if len(timestamps) >= 2:

        intervals = [
            timestamps[i]
            - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        average_inter_arrival = (
            sum(intervals)
            / len(intervals)
        )

    else:

        average_inter_arrival = 0.0

    return {

        "packets": packets,

        "bytes": total_bytes,

        "unique_destination_ips": len(
            record["destination_ips"]
        ),

        "unique_destination_ports": len(
            record["destination_ports"]
        ),

        "duration": duration,

        "packets_per_sec": packets_per_sec,

        "bytes_per_sec": bytes_per_sec,

        "tcp_packets": tcp_packets,

        "syn_packets": record["syn_packets"],

        "ack_packets": record["ack_packets"],

        "rst_packets": record["rst_packets"],

        "fin_packets": record["fin_packets"],

        "syn_ratio": syn_ratio,

        "ack_ratio": ack_ratio,

        "rst_ratio": rst_ratio,

        "fin_ratio": fin_ratio,

        "dns_packets": record["dns_packets"],

        "average_inter_arrival": average_inter_arrival,
    }


def process_window(
    packets,
    detector,
):

    print()
    print("=" * 70)
    print("LIVE THREAT DETECTION")
    print("=" * 70)

    print(
        "Timestamp:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print(
        "Packets captured:",
        len(packets)
    )

    source_records = {}

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src

        if source_ip not in source_records:

            source_records[source_ip] = (
                create_source_record()
            )

        capture_time = getattr(
            packet,
            "_live_capture_time",
            time.monotonic()
        )

        process_packet(
            source_records[source_ip],
            packet,
            capture_time
        )

    print(
        "Unique source IPs:",
        len(source_records)
    )

    for source_ip, record in source_records.items():

        features = build_features(record)

        packet_objects = record[
            "packet_objects"
        ]

        print()
        print("-" * 70)
        print(
            f"SOURCE: {source_ip}"
        )
        print("-" * 70)

        print(
            f"Packets       : "
            f"{features['packets']}"
        )

        print(
            f"Bytes         : "
            f"{features['bytes']}"
        )

        print(
            f"Destinations  : "
            f"{features['unique_destination_ips']}"
        )

        print(
            f"Dest ports    : "
            f"{features['unique_destination_ports']}"
        )

        print(
            f"Packets/sec   : "
            f"{features['packets_per_sec']:.2f}"
        )

        print(
            f"Bytes/sec     : "
            f"{features['bytes_per_sec']:.2f}"
        )

        print(
            f"TCP packets   : "
            f"{features['tcp_packets']}"
        )

        print(
            f"SYN ratio     : "
            f"{features['syn_ratio']:.4f}"
        )

        print(
            f"DNS packets   : "
            f"{features['dns_packets']}"
        )

        print()

        try:

            result = (
                detector.analyze_with_packets(
                    features,
                    packet_objects
                )
            )

        except Exception as error:

            print(
                "DETECTION ERROR:",
                error
            )

            continue

        print(
            "THREAT CLASS  :",
            result.get(
                "threat_class",
                "UNKNOWN"
            )
        )

        print(
            "CONFIDENCE    :",
            result.get(
                "confidence",
                0.0
            )
        )

        print(
            "ML CONTRIBUTION:",
            result.get(
                "ml_risk_contribution",
                0.0
            )
        )

        print(
            "RULE CONTRIBUTION:",
            result.get(
                "rule_contribution",
                0.0
            )
        )

        print(
            "BEHAVIOR CONTRIBUTION:",
            result.get(
                "behavior_contribution",
                0.0
            )
        )

        print(
            "C2 CONTRIBUTION:",
            result.get(
                "c2_risk_contribution",
                0.0
            )
        )

        print(
            "RISK SCORE    :",
            result.get(
                "risk_score",
                0.0
            )
        )

        print(
            "SEVERITY      :",
            result.get(
                "severity",
                "UNKNOWN"
            )
        )

        print(
            "C2 CLASS      :",
            result.get(
                "c2_intelligence",
                {}
            ).get(
                "c2_classification",
                "C2_UNLIKELY"
            )
        )

        print(
            "C2 SCORE      :",
            result.get(
                "c2_intelligence",
                {}
            ).get(
                "c2_behavior_score",
                0.0
            )
        )

        evidence = result.get(
            "evidence",
            []
        )

        if evidence:

            print()
            print("EVIDENCE:")

            for item in evidence:

                print(
                    f"  {item}"
                )

    print()
    print("=" * 70)


def capture_window():

    packets = []

    window_start = time.monotonic()

    window_end = (
        window_start
        + WINDOW_SIZE
    )

    def capture_handler(packet):

        capture_time = time.monotonic()

        if capture_time <= window_end:

            packet._live_capture_time = (
                capture_time
            )

            packets.append(packet)

    sniff(
        iface=INTERFACE,
        prn=capture_handler,
        filter="ip",
        store=False,
        timeout=WINDOW_SIZE
    )

    return packets


def main():

    print("=" * 70)
    print("SIH LIVE THREAT DETECTION")
    print("=" * 70)

    print(
        f"Interface   : {INTERFACE}"
    )

    print(
        f"Window size : {WINDOW_SIZE} seconds"
    )

    print()

    print(
        "Loading DetectionService..."
    )

    detector = DetectionService()

    print(
        "DetectionService loaded."
    )

    print()

    print(
        "Capturing live traffic..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print("=" * 70)

    try:

        while True:

            packets = capture_window()

            process_window(
                packets,
                detector
            )

    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print("LIVE DETECTION STOPPED")
        print("=" * 70)


if __name__ == "__main__":

    main()