from scapy.all import rdpcap, IP, TCP, UDP, DNS
from statistics import mean

from step16.detection_service import DetectionService
from step20.feature_engine.security_features import (
    create_feature_record,
    validate_feature_record,
)


PCAPS = [
    ("NORMAL DNS", "step21/generated/normal_dns.pcap"),
    ("DGA DNS", "step21/generated/dga_dns.pcap"),
    ("DNS TUNNEL", "step21/generated/dns_tunnel.pcap"),
]


def build_features(packets):

    packet_count = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    destination_ips = set()
    destination_ports = set()

    tcp_packets = 0
    syn_packets = 0
    ack_packets = 0
    rst_packets = 0
    fin_packets = 0

    dns_packets = 0
    timestamps = []

    for packet in packets:

        if hasattr(packet, "time"):
            timestamps.append(float(packet.time))

        if IP in packet:

            destination_ips.add(
                packet[IP].dst
            )

        if TCP in packet:

            tcp_packets += 1

            destination_ports.add(
                packet[TCP].dport
            )

            flags = int(packet[TCP].flags)

            if flags & 0x02:
                syn_packets += 1

            if flags & 0x10:
                ack_packets += 1

            if flags & 0x04:
                rst_packets += 1

            if flags & 0x01:
                fin_packets += 1

        elif UDP in packet:

            destination_ports.add(
                packet[UDP].dport
            )

        if DNS in packet:

            if packet[DNS].qd is not None:
                dns_packets += 1

    if timestamps:

        duration = max(timestamps) - min(timestamps)

    else:

        duration = 0.0

    if duration > 0:

        packets_per_sec = (
            packet_count / duration
        )

        bytes_per_sec = (
            total_bytes / duration
        )

    else:

        packets_per_sec = 0.0
        bytes_per_sec = 0.0

    if len(timestamps) >= 2:

        timestamps.sort()

        inter_arrivals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        average_inter_arrival = mean(
            inter_arrivals
        )

    else:

        average_inter_arrival = 0.0

    if tcp_packets > 0:

        syn_ratio = syn_packets / tcp_packets
        ack_ratio = ack_packets / tcp_packets
        rst_ratio = rst_packets / tcp_packets
        fin_ratio = fin_packets / tcp_packets

    else:

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0

    features = create_feature_record(
        packets=packet_count,
        bytes_total=total_bytes,
        unique_destination_ips=len(destination_ips),
        unique_destination_ports=len(destination_ports),
        duration=duration,
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        tcp_packets=tcp_packets,
        syn_packets=syn_packets,
        ack_packets=ack_packets,
        rst_packets=rst_packets,
        fin_packets=fin_packets,
        syn_ratio=syn_ratio,
        ack_ratio=ack_ratio,
        rst_ratio=rst_ratio,
        fin_ratio=fin_ratio,
        dns_packets=dns_packets,
        average_inter_arrival=average_inter_arrival,
    )

    validate_feature_record(features)

    return features


def run_test(label, path, service):

    print()
    print("=" * 70)
    print(label)
    print("=" * 70)

    packets = rdpcap(path)

    print(
        f"Packets loaded : {len(packets)}"
    )

    features = build_features(packets)

    print()
    print("FEATURES")
    print("-" * 70)

    for key, value in features.items():

        print(
            f"{key:30}: {value}"
        )

    result = service.analyze_with_packets(
        features,
        packets,
    )

    print()
    print("FINAL DETECTION")
    print("-" * 70)

    print(
        f"Threat class          : "
        f"{result['threat_class']}"
    )

    print(
        f"Confidence            : "
        f"{result['confidence']}"
    )

    print(
        f"ML risk contribution  : "
        f"{result['ml_risk_contribution']}"
    )

    print(
        f"Rule contribution     : "
        f"{result['rule_contribution']}"
    )

    print(
        f"Behavior contribution : "
        f"{result['behavior_contribution']}"
    )

    print(
        f"C2 risk contribution  : "
        f"{result['c2_risk_contribution']}"
    )

    print(
        f"Risk score            : "
        f"{result['risk_score']}"
    )

    print(
        f"Severity              : "
        f"{result['severity']}"
    )

    dns = result.get(
        "dns_intelligence",
        {}
    )

    print()
    print("DNS INTELLIGENCE")
    print("-" * 70)

    print(
        f"DGA score             : "
        f"{dns.get('dga_score', 0.0)}"
    )

    print(
        f"DGA classification    : "
        f"{dns.get('dga_classification', 'UNKNOWN')}"
    )

    print(
        f"Tunnel score          : "
        f"{dns.get('tunnel_score', 0.0)}"
    )

    print(
        f"Tunnel classification : "
        f"{dns.get('tunnel_classification', 'UNKNOWN')}"
    )

    print()
    print("EVIDENCE")
    print("-" * 70)

    for evidence in result.get(
        "evidence",
        []
    ):

        print(
            f"  {evidence}"
        )

if __name__ == "__main__":

    print("=" * 70)
    print("STEP 21 - FULL DNS DETECTION VALIDATION")
    print("=" * 70)

    service = DetectionService()

    for label, path in PCAPS:

        run_test(
            label,
            path,
            service
        )

    print()
    print("=" * 70)
    print(
        "FULL DNS DETECTION VALIDATION COMPLETE"
    )
    print("=" * 70)