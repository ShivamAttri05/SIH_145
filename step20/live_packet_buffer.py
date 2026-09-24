import time
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP


INTERFACE = r"\Device\NPF_{45531478-3B92-4A0E-BCC9-39C804F74A7F}"

WINDOW_SIZE = 10.0


def create_source_record():

    return {
        "packets": 0,
        "bytes": 0,
        "destination_ips": set(),
        "destination_ports": set(),
        "timestamps": [],
        "tcp_packets": 0,
        "syn_packets": 0,
        "ack_packets": 0,
        "rst_packets": 0,
        "fin_packets": 0,
        "dns_packets": 0,
    }


def process_packet(record, packet, capture_time):

    if IP not in packet:
        return

    record["packets"] += 1

    record["bytes"] += len(packet)

    record["destination_ips"].add(
        packet[IP].dst
    )

    record["timestamps"].append(
        capture_time
    )

    if TCP in packet:

        record["tcp_packets"] += 1

        record["destination_ports"].add(
            packet[TCP].dport
        )

        flags = packet[TCP].flags

        if flags & 0x02:
            record["syn_packets"] += 1

        if flags & 0x10:
            record["ack_packets"] += 1

        if flags & 0x04:
            record["rst_packets"] += 1

        if flags & 0x01:
            record["fin_packets"] += 1

    elif UDP in packet:

        if packet[UDP].dport == 53:

            record["destination_ports"].add(53)

            record["dns_packets"] += 1

        elif packet[UDP].sport == 53:

            record["destination_ports"].add(53)

            record["dns_packets"] += 1


def build_features(record):

    packets = record["packets"]

    total_bytes = record["bytes"]

    timestamps = sorted(
        record["timestamps"]
    )

    if len(timestamps) >= 2:

        duration = (
            timestamps[-1]
            - timestamps[0]
        )

    else:

        duration = 0.0

    if duration > 0:

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            total_bytes / duration
        )

    else:

        packets_per_sec = 0.0

        bytes_per_sec = 0.0

    tcp_packets = record["tcp_packets"]

    if tcp_packets > 0:

        syn_ratio = (
            record["syn_packets"]
            / tcp_packets
        )

        ack_ratio = (
            record["ack_packets"]
            / tcp_packets
        )

        rst_ratio = (
            record["rst_packets"]
            / tcp_packets
        )

        fin_ratio = (
            record["fin_packets"]
            / tcp_packets
        )

    else:

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0

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

    return {

        "packets": packets,

        "bytes": total_bytes,

        "unique_destination_ips": len(
            record["destination_ips"]
        ),

        "unique_destination_ports": len(
            record["destination_ports"]
        ),

        "duration": duration,

        "packets_per_sec": packets_per_sec,

        "bytes_per_sec": bytes_per_sec,

        "tcp_packets": tcp_packets,

        "syn_packets": record["syn_packets"],

        "ack_packets": record["ack_packets"],

        "rst_packets": record["rst_packets"],

        "fin_packets": record["fin_packets"],

        "syn_ratio": syn_ratio,

        "ack_ratio": ack_ratio,

        "rst_ratio": rst_ratio,

        "fin_ratio": fin_ratio,

        "dns_packets": record["dns_packets"],

        "average_inter_arrival": average_inter_arrival,
    }


def process_window(packets):

    print()
    print("=" * 70)
    print("LIVE FEATURE EXTRACTION")
    print("=" * 70)

    print(
        f"Timestamp : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"Packets captured : {len(packets)}"
    )

    source_records = {}

    capture_start = time.monotonic()

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src

        if source_ip not in source_records:

            source_records[source_ip] = (
                create_source_record()
            )

        # Use the packet's stored capture timestamp.
        capture_time = getattr(
            packet,
            "_live_capture_time",
            capture_start
        )

        process_packet(
            source_records[source_ip],
            packet,
            capture_time
        )

    print(
        f"Unique source IPs : "
        f"{len(source_records)}"
    )

    print()

    for source_ip, record in source_records.items():

        features = build_features(record)

        print("-" * 70)

        print(
            f"Source IP: {source_ip}"
        )

        print(
            f"Packets: "
            f"{features['packets']}"
        )

        print(
            f"Bytes: "
            f"{features['bytes']}"
        )

        print(
            f"Unique destinations: "
            f"{features['unique_destination_ips']}"
        )

        print(
            f"Unique destination ports: "
            f"{features['unique_destination_ports']}"
        )

        print(
            f"Duration: "
            f"{features['duration']:.6f} sec"
        )

        print(
            f"Packets/sec: "
            f"{features['packets_per_sec']:.2f}"
        )

        print(
            f"Bytes/sec: "
            f"{features['bytes_per_sec']:.2f}"
        )

        print(
            f"TCP packets: "
            f"{features['tcp_packets']}"
        )

        print(
            f"SYN packets: "
            f"{features['syn_packets']}"
        )

        print(
            f"ACK packets: "
            f"{features['ack_packets']}"
        )

        print(
            f"RST packets: "
            f"{features['rst_packets']}"
        )

        print(
            f"FIN packets: "
            f"{features['fin_packets']}"
        )

        print(
            f"SYN ratio: "
            f"{features['syn_ratio']:.4f}"
        )

        print(
            f"ACK ratio: "
            f"{features['ack_ratio']:.4f}"
        )

        print(
            f"RST ratio: "
            f"{features['rst_ratio']:.4f}"
        )

        print(
            f"FIN ratio: "
            f"{features['fin_ratio']:.4f}"
        )

        print(
            f"DNS packets: "
            f"{features['dns_packets']}"
        )

        print(
            f"Average inter-arrival: "
            f"{features['average_inter_arrival']:.6f} sec"
        )

    print()
    print("=" * 70)


def capture_window():

    packets = []

    window_start = time.monotonic()

    window_end = (
        window_start
        + WINDOW_SIZE
    )

    def capture_handler(packet):

        capture_time = time.monotonic()

        if capture_time <= window_end:

            packet._live_capture_time = (
                capture_time
            )

            packets.append(packet)

    sniff(
        iface=INTERFACE,
        prn=capture_handler,
        filter="ip",
        store=False,
        timeout=WINDOW_SIZE
    )

    return packets


print("=" * 70)
print("SIH LIVE FEATURE EXTRACTION")
print("=" * 70)

print(
    f"Interface   : {INTERFACE}"
)

print(
    f"Window size : {WINDOW_SIZE} seconds"
)

print()
print("Capturing live traffic...")
print("Press Ctrl+C to stop.")
print("=" * 70)


try:

    while True:

        packets = capture_window()

        process_window(packets)

except KeyboardInterrupt:

    print()
    print("=" * 70)
    print("LIVE CAPTURE STOPPED")
    print("=" * 70)