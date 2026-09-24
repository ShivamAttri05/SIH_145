from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
import random
import string


OUTPUT_DIR = "step21/generated"


def normal_dns():
    packets = []

    domains = [
        "google.com",
        "youtube.com",
        "microsoft.com",
        "github.com",
        "wikipedia.org",
        "amazon.com",
        "example.com",
    ]

    timestamp = 0.0

    for domain in domains:
        packet = (
            IP(src="10.10.10.10", dst="8.8.8.8")
            / UDP(sport=40000 + len(packets), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
        )

        packet.time = timestamp
        timestamp += random.uniform(0.5, 2.0)

        packets.append(packet)

    wrpcap(
        f"{OUTPUT_DIR}/normal_dns.pcap",
        packets
    )

    print(
        f"normal_dns.pcap -> {len(packets)} packets"
    )


def random_label(length):
    characters = string.ascii_lowercase + string.digits

    return "".join(
        random.choice(characters)
        for _ in range(length)
    )


def dga_dns():
    packets = []

    timestamp = 0.0

    for i in range(30):

        domain = (
            random_label(random.randint(35, 55))
            + ".com"
        )

        packet = (
            IP(src="10.10.10.20", dst="8.8.8.8")
            / UDP(sport=41000 + i, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
        )

        packet.time = timestamp
        timestamp += random.uniform(0.05, 0.2)

        packets.append(packet)

    wrpcap(
        f"{OUTPUT_DIR}/dga_dns.pcap",
        packets
    )

    print(
        f"dga_dns.pcap -> {len(packets)} packets"
    )


def tunnel_dns():
    packets = []

    timestamp = 0.0

    for i in range(30):

        encoded_data = random_label(
            random.randint(70, 100)
        )

        domain = (
            encoded_data
            + ".data.example.com"
        )

        packet = (
            IP(src="10.10.10.30", dst="8.8.8.8")
            / UDP(sport=42000 + i, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
        )

        packet.time = timestamp
        timestamp += random.uniform(0.05, 0.15)

        packets.append(packet)

    wrpcap(
        f"{OUTPUT_DIR}/dns_tunnel.pcap",
        packets
    )

    print(
        f"dns_tunnel.pcap -> {len(packets)} packets"
    )


if __name__ == "__main__":

    print("=" * 60)
    print("STEP 21 - DNS TEST TRAFFIC GENERATOR")
    print("=" * 60)

    normal_dns()
    dga_dns()
    tunnel_dns()

    print("=" * 60)
    print("DNS test PCAP generation complete.")
    print("=" * 60)