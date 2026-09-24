from scapy.all import sniff, IP, TCP, UDP


INTERFACE = r"\Device\NPF_{45531478-3B92-4A0E-BCC9-39C804F74A7F}"


def packet_handler(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = packet[IP].proto
    packet_length = len(packet)

    print("-" * 70)
    print(f"Source      : {source_ip}")
    print(f"Destination : {destination_ip}")
    print(f"Protocol    : {protocol}")
    print(f"Length      : {packet_length} bytes")

    if TCP in packet:
        print(f"TCP         : {packet[TCP].sport} -> {packet[TCP].dport}")

    elif UDP in packet:
        print(f"UDP         : {packet[UDP].sport} -> {packet[UDP].dport}")


print("=" * 70)
print("SIH LIVE PACKET CAPTURE TEST")
print("=" * 70)
print(f"Interface: {INTERFACE}")
print()
print("Capturing 10 IP packets...")
print("Press Ctrl+C to stop.")
print("=" * 70)


sniff(
    iface=INTERFACE,
    prn=packet_handler,
    filter="ip",
    count=10,
    store=False
)


print()
print("=" * 70)
print("CAPTURE COMPLETE")
print("=" * 70)