from typing import Any

from scapy.all import IP, TCP, UDP, DNS

# ============================================================
# CANONICAL ML FEATURE SCHEMA
# ============================================================

FEATURE_COLUMNS = [
    "packets",
    "bytes",
    "unique_destination_ips",
    "unique_destination_ports",
    "duration",
    "packets_per_sec",
    "bytes_per_sec",
    "tcp_packets",
    "syn_packets",
    "ack_packets",
    "rst_packets",
    "fin_packets",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "dns_packets",
    "average_inter_arrival",
]

def calculate_packet_timing(packets: list) -> float:
    """
    Calculate the average inter-arrival time between
    IP packets.

    Returns:
        Average time in seconds between consecutive packets.
        Returns 0.0 when fewer than two packets are available.
    """

    timestamps = []

    for packet in packets:
        if packet.haslayer(IP):
            timestamps.append(float(packet.time))

    if len(timestamps) < 2:
        return 0.0

    timestamps.sort()

    intervals = [
        timestamps[index] - timestamps[index - 1]
        for index in range(1, len(timestamps))
    ]

    return sum(intervals) / len(intervals)

def count_dns_packets(packets: list) -> int:
    """
    Count packets containing a DNS layer.
    """

    return sum(
        1
        for packet in packets
        if packet.haslayer(DNS)
    )

def analyze_packet_metadata(packets: list) -> dict[str, float]:
    """
    Extract packet-level timing and DNS metadata.
    """

    return {
        "dns_packets": count_dns_packets(packets),
        "average_inter_arrival": calculate_packet_timing(
            packets
        ),
    }

def create_feature_record(
    packets: int,
    bytes_total: int,
    unique_destination_ips: int,
    unique_destination_ports: int,
    duration: float,
    packets_per_sec: float,
    bytes_per_sec: float,
    tcp_packets: int,
    syn_packets: int,
    ack_packets: int,
    rst_packets: int,
    fin_packets: int,
    syn_ratio: float,
    ack_ratio: float,
    rst_ratio: float,
    fin_ratio: float,
    dns_packets: int,
    average_inter_arrival: float,
) -> dict[str, Any]:
    """
    Create a security feature record using the canonical
    18-feature schema expected by the ML model.
    """

    return {
        "packets": packets,
        "bytes": bytes_total,
        "unique_destination_ips": unique_destination_ips,
        "unique_destination_ports": unique_destination_ports,
        "duration": duration,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "tcp_packets": tcp_packets,
        "syn_packets": syn_packets,
        "ack_packets": ack_packets,
        "rst_packets": rst_packets,
        "fin_packets": fin_packets,
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
        "rst_ratio": rst_ratio,
        "fin_ratio": fin_ratio,
        "dns_packets": dns_packets,
        "average_inter_arrival": average_inter_arrival,
    }


def validate_feature_record(features: dict[str, Any]) -> None:
    """
    Validate that a feature record contains exactly the
    features required by the detection model.
    """

    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in features
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    extra = [
        key
        for key in features
        if key not in FEATURE_COLUMNS
    ]

    if extra:
        raise ValueError(
            f"Unexpected features: {extra}"
        )