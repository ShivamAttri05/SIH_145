from scapy.all import rdpcap

from step20.dns_engine.dns_features import analyze_dns_packets
from step20.dns_engine.dns_aggregate import aggregate_dns_features
from step20.dns_engine.dga_detector import calculate_dga_score
from step20.dns_engine.dns_tunnel_detector import calculate_tunnel_score


PCAPS = [
    ("NORMAL DNS", "step21/generated/normal_dns.pcap"),
    ("DGA DNS", "step21/generated/dga_dns.pcap"),
    ("DNS TUNNEL", "step21/generated/dns_tunnel.pcap"),
]


def test_pcap(label, path):

    print()
    print("=" * 70)
    print(label)
    print("=" * 70)

    packets = rdpcap(path)

    print(f"Packets loaded : {len(packets)}")

    query_features = analyze_dns_packets(packets)

    print(f"DNS queries    : {len(query_features)}")

    if not query_features:
        print("No DNS query features detected.")
        return

    aggregate = aggregate_dns_features(query_features)

    dga_result = calculate_dga_score(aggregate)
    tunnel_result = calculate_tunnel_score(aggregate)

    print()
    print("DNS AGGREGATE")
    print("-" * 70)

    for key, value in aggregate.items():
        print(f"{key:30}: {value}")

    print()
    print("DGA DETECTION")
    print("-" * 70)
    print(f"Score          : {dga_result['dga_score']}")
    print(f"Classification  : {dga_result['classification']}")

    print("Evidence:")

    for evidence in dga_result["evidence"]:
        print(f"  {evidence}")

    print()
    print("DNS TUNNEL DETECTION")
    print("-" * 70)
    print(f"Score          : {tunnel_result['tunnel_score']}")
    print(f"Classification  : {tunnel_result['classification']}")

    print("Evidence:")

    for evidence in tunnel_result["evidence"]:
        print(f"  {evidence}")


if __name__ == "__main__":

    print("=" * 70)
    print("STEP 21 - DNS INTELLIGENCE VALIDATION")
    print("=" * 70)

    for label, path in PCAPS:
        test_pcap(label, path)

    print()
    print("=" * 70)
    print("DNS intelligence validation complete.")
    print("=" * 70)