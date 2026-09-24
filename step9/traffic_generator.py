from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
import random
import time
import os


OUTPUT_DIR = "step9/generated"


def ensure_output_directory():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# NORMAL TRAFFIC
# ============================================================

def generate_normal_traffic():
    packets = []

    source_ip = "192.168.100.10"
    destination_ip = "192.168.100.20"

    base_time = time.time()

    # Irregular application-like inter-arrival times.
    intervals = [
        0.08,
        0.17,
        0.05,
        0.24,
        0.11,
        0.31,
        0.07,
        0.19,
        0.13,
        0.28,
        0.06,
        0.16,
        0.22,
        0.09,
        0.34,
        0.12,
        0.21,
        0.07,
        0.26,
        0.15,
    ]

    current_time = base_time

    for i, interval in enumerate(intervals):

        current_time += interval

        payload = (
            f"GET /index.html?id={i} "
            "HTTP/1.1\r\n"
            "Host: internal.example\r\n"
            "\r\n"
        )

        packet = (
            IP(
                src=source_ip,
                dst=destination_ip
            )
            / TCP(
                sport=random.randint(40000, 50000),
                dport=80,
                seq=i * 100,
                ack=i * 50,
                flags="PA"
            )
            / payload
        )

        packet.time = current_time

        packets.append(packet)

    return packets

# ============================================================
# TCP SYN FLOOD PATTERN
# ============================================================

def generate_syn_flood():

    packets = []

    destination_ip = "192.168.100.20"

    for i in range(200):

        source_ip = f"10.0.0.{random.randint(1, 254)}"

        source_port = random.randint(1024, 65535)

        packet = IP(
            src=source_ip,
            dst=destination_ip
        ) / TCP(
            sport=source_port,
            dport=80,
            flags="S"
        )

        packets.append(packet)

    return packets


# ============================================================
# PORT SCAN PATTERN
# ============================================================

def generate_port_scan():

    packets = []

    source_ip = "192.168.100.50"
    destination_ip = "192.168.100.20"

    ports = [
        21, 22, 23, 25, 53,
        80, 110, 135, 139, 143,
        443, 445, 587, 993, 995,
        1433, 3306, 3389, 5432, 8080
    ]

    for port in ports:

        packet = IP(
            src=source_ip,
            dst=destination_ip
        ) / TCP(
            sport=random.randint(40000, 50000),
            dport=port,
            flags="S"
        )

        packets.append(packet)

    return packets


# ============================================================
# DNS BURST
# ============================================================

def generate_dns_burst():

    packets = []

    source_ip = "192.168.100.60"
    dns_server = "192.168.100.1"

    domains = [
        "example.com",
        "google.com",
        "github.com",
        "microsoft.com",
        "python.org",
        "openai.com",
        "cloudflare.com",
        "wikipedia.org",
        "stackoverflow.com",
        "amazon.com"
    ]

    for i in range(30):

        domain = random.choice(domains)

        packet = (
            IP(
                src=source_ip,
                dst=dns_server
            )
            / UDP(
                sport=random.randint(40000, 50000),
                dport=53
            )
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
        )

        packets.append(packet)

    return packets


# ============================================================
# MAIN
# ============================================================

def main():

    ensure_output_directory()

    print()
    print("=" * 70)
    print("STEP 9 - CONTROLLED TRAFFIC GENERATOR")
    print("=" * 70)
    print()

    print("Generating normal traffic...")
    normal = generate_normal_traffic()

    print("Generating TCP SYN flood pattern...")
    syn_flood = generate_syn_flood()

    print("Generating port scan pattern...")
    port_scan = generate_port_scan()

    print("Generating DNS burst...")
    dns_burst = generate_dns_burst()

    print()

    normal_file = os.path.join(
        OUTPUT_DIR,
        "normal.pcap"
    )

    syn_file = os.path.join(
        OUTPUT_DIR,
        "syn_flood.pcap"
    )

    scan_file = os.path.join(
        OUTPUT_DIR,
        "port_scan.pcap"
    )

    dns_file = os.path.join(
        OUTPUT_DIR,
        "dns_burst.pcap"
    )

    wrpcap(normal_file, normal)
    wrpcap(syn_file, syn_flood)
    wrpcap(scan_file, port_scan)
    wrpcap(dns_file, dns_burst)

    print("Generated PCAP files:")
    print()

    print(f"Normal traffic : {normal_file}")
    print(f"SYN flood      : {syn_file}")
    print(f"Port scan      : {scan_file}")
    print(f"DNS burst      : {dns_file}")

    print()
    print("=" * 70)
    print("TRAFFIC GENERATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()