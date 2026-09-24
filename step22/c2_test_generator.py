from scapy.all import IP, UDP, TCP, DNS, DNSQR, wrpcap
from pathlib import Path
import random
import time


OUTPUT_DIR = Path("step22/generated")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


SOURCE_IP = "10.20.20.10"
C2_IP = "203.0.113.50"
DNS_IP = "8.8.8.8"


def generate_c2_beacon():
    packets = []

    base_time = time.time()

    for i in range(12):

        packet = (
            IP(
                src=SOURCE_IP,
                dst=C2_IP
            )
            /
            TCP(
                sport=40000 + i,
                dport=443,
                flags="PA"
            )
            /
            b"BEACON"
        )

        packet.time = base_time + (i * 10)

        packets.append(packet)

    output = OUTPUT_DIR / "c2_beacon.pcap"

    wrpcap(
        str(output),
        packets
    )

    print(
        f"c2_beacon.pcap -> "
        f"{len(packets)} packets"
    )


def generate_normal_dns():
    packets = []

    domains = [
        "google.com",
        "youtube.com",
        "microsoft.com",
        "github.com",
        "wikipedia.org",
        "amazon.com",
        "cloudflare.com",
        "reddit.com",
    ]

    base_time = time.time()

    current_time = base_time

    for i, domain in enumerate(domains):

        current_time += random.uniform(
            1.0,
            5.0
        )

        packet = (
            IP(
                src=SOURCE_IP,
                dst=DNS_IP
            )
            /
            UDP(
                sport=50000 + i,
                dport=53
            )
            /
            DNS(
                rd=1,
                qd=DNSQR(
                    qname=domain
                )
            )
        )

        packet.time = current_time

        packets.append(packet)

    output = OUTPUT_DIR / "normal_dns.pcap"

    wrpcap(
        str(output),
        packets
    )

    print(
        f"normal_dns.pcap -> "
        f"{len(packets)} packets"
    )


def generate_port_scan():
    packets = []

    base_time = time.time()

    for i in range(20):

        packet = (
            IP(
                src=SOURCE_IP,
                dst="10.20.20.50"
            )
            /
            TCP(
                sport=45000 + i,
                dport=1000 + i,
                flags="S"
            )
        )

        packet.time = base_time + (i * 0.2)

        packets.append(packet)

    output = OUTPUT_DIR / "port_scan.pcap"

    wrpcap(
        str(output),
        packets
    )

    print(
        f"port_scan.pcap -> "
        f"{len(packets)} packets"
    )


if __name__ == "__main__":

    print("=" * 70)
    print("STEP 22 - C2 TEST TRAFFIC GENERATOR")
    print("=" * 70)

    generate_c2_beacon()
    generate_normal_dns()
    generate_port_scan()

    print()
    print("Generation complete.")