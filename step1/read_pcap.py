import os
import sys

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP
except ImportError:
    print("Error: scapy is not installed.")
    print("Please install scapy using: pip install scapy")
    print("Or run using the virtual environment: .venv\\Scripts\\python read_pcap.py")
    sys.exit(1)


def find_pcap_file():
    """Find a PCAP or PCAPNG file from arguments or the current directory."""
    if len(sys.argv) > 1:
        return sys.argv[1]

    # Check common default filenames
    candidates = ["sample.pcap", "sample.pcapng"]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    # Look for any .pcap or .pcapng file in current directory
    for f in os.listdir("."):
        if f.lower().endswith((".pcap", ".pcapng")):
            return f

    return "sample.pcapng"


def read_pcap(file_path):
    """Read and display information for each packet in the PCAP file."""
    if not os.path.exists(file_path):
        print(f"Error: PCAP file '{file_path}' not found.")
        print("Usage: python read_pcap.py [path_to_pcap_file]")
        return

    with PcapReader(file_path) as reader:
        for i, pkt in enumerate(reader, 1):
            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "N/A"
            src_port = "N/A"
            dst_port = "N/A"
            packet_size = f"{len(pkt)} bytes"

            # Check for Network Layer (IPv4 / IPv6 / ARP)
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt.sprintf("%IP.proto%").upper()
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                protocol = pkt.sprintf("%IPv6.nh%").upper()
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                protocol = "ARP"

            # Check for Transport Layer (TCP / UDP / ICMP)
            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            # Print formatted packet details
            print(f"Packet #{i}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Protocol: {protocol}")
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Packet Size: {packet_size}")
            print()


if __name__ == "__main__":
    pcap_path = find_pcap_file()
    read_pcap(pcap_path)
