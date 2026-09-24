from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP

from step16.detection_service import DetectionService
from step20.feature_engine.security_features import (
    create_feature_record,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCENARIOS = {
    "NORMAL": PROJECT_ROOT / "step9" / "generated" / "normal.pcap",
    "SYN FLOOD": PROJECT_ROOT / "step9" / "generated" / "syn_flood.pcap",
    "PORT SCAN": PROJECT_ROOT / "step9" / "generated" / "port_scan.pcap",
    "DNS BURST": PROJECT_ROOT / "step9" / "generated" / "dns_burst.pcap",
    "C2 BEACON": PROJECT_ROOT / "step20" / "c2_engine" / "generated" / "beacon.pcap",
    "TLS CLIENT HELLO": PROJECT_ROOT / "step20" / "tls_engine" / "generated" / "tls_client_hello.pcap",
}


def build_features(packets):
    timestamps = []
    destination_ips = set()
    destination_ports = set()

    total_bytes = 0

    tcp_packets = 0
    syn_packets = 0
    ack_packets = 0
    rst_packets = 0
    fin_packets = 0

    for packet in packets:

        if IP not in packet:
            continue

        timestamps.append(float(packet.time))

        destination_ips.add(
            packet[IP].dst
        )

        total_bytes += len(packet)

        if TCP in packet:

            tcp_packets += 1

            if packet[TCP].flags & 0x02:
                syn_packets += 1

            if packet[TCP].flags & 0x10:
                ack_packets += 1

            if packet[TCP].flags & 0x04:
                rst_packets += 1

            if packet[TCP].flags & 0x01:
                fin_packets += 1

            destination_ports.add(
                int(packet[TCP].dport)
            )

        elif UDP in packet:

            destination_ports.add(
                int(packet[UDP].dport)
            )

    timestamps.sort()

    if len(timestamps) >= 2:

        duration = (
            timestamps[-1]
            - timestamps[0]
        )

        intervals = [
            timestamps[index]
            - timestamps[index - 1]
            for index in range(1, len(timestamps))
        ]

        average_inter_arrival = (
            sum(intervals)
            / len(intervals)
        )

    else:

        duration = 0.0
        average_inter_arrival = 0.0

    if duration > 0:

        packets_per_sec = (
            len(packets)
            / duration
        )

        bytes_per_sec = (
            total_bytes
            / duration
        )

    else:

        packets_per_sec = 0.0
        bytes_per_sec = 0.0

    if tcp_packets > 0:

        syn_ratio = (
            syn_packets
            / tcp_packets
        )

        ack_ratio = (
            ack_packets
            / tcp_packets
        )

        rst_ratio = (
            rst_packets
            / tcp_packets
        )

        fin_ratio = (
            fin_packets
            / tcp_packets
        )

    else:

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0

    dns_packets = sum(
        1
        for packet in packets
        if packet.haslayer("DNS")
    )

    return create_feature_record(

        packets=len(packets),

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


def test_scenario(
    detector,
    scenario_name,
    pcap_file,
):

    print()
    print("=" * 70)
    print(scenario_name)
    print("=" * 70)

    print(
        f"PCAP: {pcap_file}"
    )

    if not pcap_file.exists():

        print(
            "ERROR: PCAP FILE NOT FOUND"
        )

        return None

    packets = rdpcap(
        str(pcap_file)
    )

    print(
        f"Packets: {len(packets)}"
    )

    features = build_features(
        packets
    )

    result = detector.analyze_with_packets(
        features,
        packets
    )

    c2 = result.get(
        "c2_intelligence",
        {}
    )

    print()
    print("PRIMARY DETECTION")
    print("-" * 70)

    print(
        "Threat Class:",
        result["threat_class"]
    )

    print(
        "Confidence:",
        result["confidence"]
    )

    print(
        "ML Contribution:",
        result["ml_risk_contribution"]
    )

    print(
        "Rule Contribution:",
        result["rule_contribution"]
    )

    print(
        "Behavior Contribution:",
        result["behavior_contribution"]
    )

    print(
        "C2 Contribution:",
        result.get(
            "c2_risk_contribution",
            0.0
        )
    )

    print(
        "Risk Score:",
        result["risk_score"]
    )

    print(
        "Severity:",
        result["severity"]
    )

    print()
    print("C2 INTELLIGENCE")
    print("-" * 70)

    print(
        "C2 Classification:",
        c2.get(
            "c2_classification",
            "C2_UNLIKELY"
        )
    )

    print(
        "C2 Behavior Score:",
        c2.get(
            "c2_behavior_score",
            0.0
        )
    )

    print()
    print("EVIDENCE")
    print("-" * 70)

    for evidence in result.get(
        "evidence",
        []
    ):

        print(
            evidence
        )

    return result


def main():

    print()
    print("=" * 70)
    print("STEP 20.12.16")
    print("UNIFIED RISK REGRESSION TEST")
    print("=" * 70)

    print()
    print(
        "Testing all security scenarios..."
    )

    detector = DetectionService()

    results = {}

    for scenario_name, pcap_file in SCENARIOS.items():

        result = test_scenario(
            detector,
            scenario_name,
            pcap_file,
        )

        results[
            scenario_name
        ] = result

    print()
    print()
    print("=" * 70)
    print("REGRESSION SUMMARY")
    print("=" * 70)

    print()

    for scenario_name, result in results.items():

        if result is None:

            print(
                f"{scenario_name:<20} FAILED"
            )

            continue

        print(
            f"{scenario_name:<20} "
            f"{result['threat_class']:<20} "
            f"Risk={result['risk_score']:<6} "
            f"{result['severity']}"
        )

    print()
    print("=" * 70)
    print("REGRESSION TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()