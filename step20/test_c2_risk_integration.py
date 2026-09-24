from scapy.all import rdpcap, IP, TCP, UDP

from step16.detection_service import DetectionService
from step20.feature_engine.security_features import (
    create_feature_record,
)


PCAP_FILE = (
    "step20/c2_engine/generated/beacon.pcap"
)


print("=" * 70)
print("C2 RISK INTEGRATION TEST")
print("=" * 70)


# ============================================================
# LOAD PCAP
# ============================================================

packets = rdpcap(
    PCAP_FILE
)

print(
    f"Packets loaded: {len(packets)}"
)


# ============================================================
# BASIC FEATURE EXTRACTION
# ============================================================

timestamps = []

destination_ips = set()
destination_ports = set()

total_bytes = 0

tcp_packets = 0
syn_packets = 0
ack_packets = 0
rst_packets = 0
fin_packets = 0

duration = 0.0


for packet in packets:

    if IP not in packet:
        continue

    timestamps.append(
        float(packet.time)
    )

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


# ============================================================
# TIMING
# ============================================================

timestamps.sort()


if len(timestamps) >= 2:

    duration = (
        timestamps[-1]
        - timestamps[0]
    )

    intervals = [
        timestamps[index]
        - timestamps[index - 1]
        for index in range(
            1,
            len(timestamps)
        )
    ]

    average_inter_arrival = (
        sum(intervals)
        / len(intervals)
    )

else:

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


# ============================================================
# RATIOS
# ============================================================

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


# ============================================================
# DNS
# ============================================================

dns_packets = sum(
    1
    for packet in packets
    if packet.haslayer("DNS")
)


# ============================================================
# CREATE CANONICAL FEATURE RECORD
# ============================================================

features = create_feature_record(

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

    average_inter_arrival=(
        average_inter_arrival
    ),
)


# ============================================================
# DETECTION SERVICE
# ============================================================

detector = DetectionService()


# ============================================================
# FULL ANALYSIS
# ============================================================

result = detector.analyze_with_packets(
    features,
    packets
)


# ============================================================
# PRIMARY DETECTION
# ============================================================

print()
print("-" * 70)
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
    "C2 Risk Contribution:",
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


# ============================================================
# C2 INTELLIGENCE
# ============================================================

c2 = result.get(
    "c2_intelligence",
    {}
)

print()
print("-" * 70)
print("C2 INTELLIGENCE")
print("-" * 70)

print(
    "C2 Classification:",
    c2.get(
        "c2_classification"
    )
)

print(
    "C2 Behavior Score:",
    c2.get(
        "c2_behavior_score"
    )
)


# ============================================================
# EVIDENCE
# ============================================================

print()
print("-" * 70)
print("EVIDENCE")
print("-" * 70)

for evidence in result.get(
    "evidence",
    []
):

    print(
        evidence
    )


print()
print("=" * 70)
print("TEST COMPLETE")
print("=" * 70)