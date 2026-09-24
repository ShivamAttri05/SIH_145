from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP

from step16.detection_service import DetectionService
from step20.feature_engine.security_features import create_feature_record


PCAP_DIR = Path("step22/generated")


def build_features(packets):

    packet_count = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    source_ips = set()
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

            timestamps.append(
                float(packet.time)
            )

        if IP in packet:

            source_ips.add(
                packet[IP].src
            )

            destination_ips.add(
                packet[IP].dst
            )

        if TCP in packet:

            tcp_packets += 1

            destination_ports.add(
                packet[TCP].dport
            )

            flags = packet[TCP].flags

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

            if packet[UDP].dport == 53:
                dns_packets += 1

    if timestamps:

        duration = (
            max(timestamps)
            - min(timestamps)
        )

    else:

        duration = 0.0

    if duration <= 0:

        duration = 0.001

    packets_per_sec = (
        packet_count / duration
    )

    bytes_per_sec = (
        total_bytes / duration
    )

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

    syn_ratio = (
        syn_packets / tcp_packets
        if tcp_packets
        else 0.0
    )

    ack_ratio = (
        ack_packets / tcp_packets
        if tcp_packets
        else 0.0
    )

    rst_ratio = (
        rst_packets / tcp_packets
        if tcp_packets
        else 0.0
    )

    fin_ratio = (
        fin_packets / tcp_packets
        if tcp_packets
        else 0.0
    )

    return create_feature_record(
        packets=packet_count,
        bytes_total=total_bytes,
        unique_destination_ips=len(
            destination_ips
        ),
        unique_destination_ports=len(
            destination_ports
        ),
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


def analyze_pcap(
    service,
    filename
):

    print()
    print("=" * 70)
    print(filename.upper())
    print("=" * 70)

    packets = rdpcap(
        str(PCAP_DIR / filename)
    )

    features = build_features(
        packets
    )

    result = service.analyze_with_packets(
        features,
        packets
    )

    print(
        f"Packets              : "
        f"{len(packets)}"
    )

    print()
    print("FINAL DETECTION")
    print("-" * 70)

    print(
        f"Threat class         : "
        f"{result['threat_class']}"
    )

    print(
        f"Confidence           : "
        f"{result['confidence']}"
    )

    print(
        f"ML contribution      : "
        f"{result['ml_risk_contribution']}"
    )

    print(
        f"Rule contribution    : "
        f"{result['rule_contribution']}"
    )

    print(
        f"Behavior contribution: "
        f"{result['behavior_contribution']}"
    )

    print(
        f"C2 contribution      : "
        f"{result['c2_risk_contribution']}"
    )

    print(
        f"Risk score           : "
        f"{result['risk_score']}"
    )

    print(
        f"Severity             : "
        f"{result['severity']}"
    )

    c2 = result.get(
        "c2_intelligence",
        {}
    )

    print()
    print("C2 INTELLIGENCE")
    print("-" * 70)

    print(
        f"C2 score             : "
        f"{c2.get('c2_behavior_score', 0.0)}"
    )

    print(
        f"C2 classification    : "
        f"{c2.get('c2_classification', 'UNKNOWN')}"
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
    print("STEP 22 - FULL C2 DETECTION VALIDATION")
    print("=" * 70)

    service = DetectionService()

    analyze_pcap(
        service,
        "normal_dns.pcap"
    )

    analyze_pcap(
        service,
        "c2_beacon.pcap"
    )

    analyze_pcap(
        service,
        "port_scan.pcap"
    )

    print()
    print("=" * 70)
    print("FULL C2 DETECTION VALIDATION COMPLETE")
    print("=" * 70)