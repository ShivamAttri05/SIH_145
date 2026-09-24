from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import defaultdict
import math
import csv
import os
import sys


WINDOW_SIZE = 10.0

OUTPUT_DIR = "step10/dataset"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "network_dataset.csv"
)


# ============================================================
# PACKET HELPERS
# ============================================================

def get_packet_source(packet):

    if IP in packet:
        return packet[IP].src

    return None


def get_packet_destination(packet):

    if IP in packet:
        return packet[IP].dst

    return None


def get_packet_size(packet):

    return len(packet)


def get_destination_port(packet):

    if TCP in packet:
        return packet[TCP].dport

    if UDP in packet:
        return packet[UDP].dport

    return None


def is_tcp(packet):

    return TCP in packet


def get_tcp_flags(packet):

    if TCP not in packet:
        return set()

    flags = packet[TCP].flags

    result = set()

    if flags & 0x02:
        result.add("SYN")

    if flags & 0x10:
        result.add("ACK")

    if flags & 0x04:
        result.add("RST")

    if flags & 0x01:
        result.add("FIN")

    return result


def is_dns(packet):

    return DNS in packet


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(pcap_file, label):

    print()
    print("=" * 100)
    print(f"Processing: {pcap_file}")
    print(f"Label:      {label}")
    print("=" * 100)

    packets = rdpcap(pcap_file)

    if len(packets) == 0:
        return []

    print(f"Total packets: {len(packets)}")

    first_timestamp = float(packets[0].time)

    windows = defaultdict(list)

    for packet in packets:

        if IP not in packet:
            continue

        relative_time = float(packet.time) - first_timestamp

        window_id = int(
            relative_time // WINDOW_SIZE
        )

        source_ip = get_packet_source(packet)

        windows[(window_id, source_ip)].append(packet)

    records = []

    for (window_id, source_ip), source_packets in sorted(
        windows.items()
    ):

        timestamps = [
            float(packet.time)
            for packet in source_packets
        ]

        start_time = min(timestamps)
        end_time = max(timestamps)

        duration = end_time - start_time

        if duration > 0:
            packets_per_sec = (
                len(source_packets) / duration
            )

            bytes_per_sec = (
                sum(
                    get_packet_size(packet)
                    for packet in source_packets
                )
                / duration
            )

        else:
            packets_per_sec = 0.0
            bytes_per_sec = 0.0

        destination_ips = set()
        destination_ports = set()

        tcp_packets = 0
        syn_packets = 0
        ack_packets = 0
        rst_packets = 0
        fin_packets = 0

        dns_packets = 0
        total_bytes = 0

        packet_timestamps = []

        for packet in source_packets:

            total_bytes += get_packet_size(packet)

            destination_ip = get_packet_destination(packet)

            if destination_ip:
                destination_ips.add(destination_ip)

            destination_port = get_destination_port(packet)

            if destination_port is not None:
                destination_ports.add(destination_port)

            if is_tcp(packet):

                tcp_packets += 1

                flags = get_tcp_flags(packet)

                if "SYN" in flags:
                    syn_packets += 1

                if "ACK" in flags:
                    ack_packets += 1

                if "RST" in flags:
                    rst_packets += 1

                if "FIN" in flags:
                    fin_packets += 1

            if is_dns(packet):
                dns_packets += 1

            packet_timestamps.append(
                float(packet.time)
            )

        packet_count = len(source_packets)

        syn_ratio = (
            syn_packets / tcp_packets
            if tcp_packets > 0
            else 0.0
        )

        ack_ratio = (
            ack_packets / tcp_packets
            if tcp_packets > 0
            else 0.0
        )

        rst_ratio = (
            rst_packets / tcp_packets
            if tcp_packets > 0
            else 0.0
        )

        fin_ratio = (
            fin_packets / tcp_packets
            if tcp_packets > 0
            else 0.0
        )

        packet_timestamps.sort()

        if len(packet_timestamps) > 1:

            inter_arrivals = []

            for i in range(
                1,
                len(packet_timestamps)
            ):

                inter_arrivals.append(
                    packet_timestamps[i]
                    - packet_timestamps[i - 1]
                )

            average_inter_arrival = (
                sum(inter_arrivals)
                / len(inter_arrivals)
            )

        else:

            average_inter_arrival = 0.0

        record = {
            "window_id": window_id,
            "source_ip": source_ip,

            "packets": packet_count,
            "bytes": total_bytes,

            "unique_destination_ips":
                len(destination_ips),

            "unique_destination_ports":
                len(destination_ports),

            "duration": duration,

            "packets_per_sec":
                packets_per_sec,

            "bytes_per_sec":
                bytes_per_sec,

            "tcp_packets":
                tcp_packets,

            "syn_packets":
                syn_packets,

            "ack_packets":
                ack_packets,

            "rst_packets":
                rst_packets,

            "fin_packets":
                fin_packets,

            "syn_ratio":
                syn_ratio,

            "ack_ratio":
                ack_ratio,

            "rst_ratio":
                rst_ratio,

            "fin_ratio":
                fin_ratio,

            "dns_packets":
                dns_packets,

            "average_inter_arrival":
                average_inter_arrival,

            "label": label
        }

        records.append(record)

    print(
        f"Generated feature records: {len(records)}"
    )

    return records


# ============================================================
# DATASET WRITER
# ============================================================

def save_dataset(records):

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    fieldnames = [
        "window_id",
        "source_ip",

        "packets",
        "bytes",

        "unique_destination_ips",
        "unique_destination_ports",

        "duration",

        "packets_per_sec",
        "bytes_per_sec",

        "tcp_packets",

        "syn_packets",
        "ack_packets",
        "rst_packets",
        "fin_packets",

        "syn_ratio",
        "ack_ratio",
        "rst_ratio",
        "fin_ratio",

        "dns_packets",

        "average_inter_arrival",

        "label"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(records)

    print()
    print("=" * 100)
    print("DATASET SAVED")
    print("=" * 100)
    print()
    print(f"File: {OUTPUT_FILE}")
    print(f"Total records: {len(records)}")
    print()


# ============================================================
# DATASET SUMMARY
# ============================================================

def print_summary(records):

    counts = defaultdict(int)

    for record in records:

        counts[
            record["label"]
        ] += 1

    print()
    print("=" * 100)
    print("DATASET SUMMARY")
    print("=" * 100)

    for label, count in counts.items():

        print(
            f"{label:20s}: {count}"
        )

    print("=" * 100)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 100)
    print("STEP 10 - NETWORK DATASET BUILDER")
    print("=" * 100)

    datasets = [
        (
            "step9/generated/normal.pcap",
            "BENIGN"
        ),

        (
            "step9/generated/syn_flood.pcap",
            "DDOS"
        ),

        (
            "step9/generated/port_scan.pcap",
            "RECONNAISSANCE"
        ),

        (
            "step9/generated/dns_burst.pcap",
            "DNS_ANOMALY"
        )
    ]

    all_records = []

    for pcap_file, label in datasets:

        if not os.path.exists(pcap_file):

            print()
            print(
                f"WARNING: File not found: {pcap_file}"
            )

            continue

        records = extract_features(
            pcap_file,
            label
        )

        all_records.extend(records)

    if len(all_records) == 0:

        print()
        print("ERROR: No records generated.")

        return

    print_summary(
        all_records
    )

    save_dataset(
        all_records
    )

    print()
    print("=" * 100)
    print("STEP 10 COMPLETE")
    print("=" * 100)


if __name__ == "__main__":
    main()