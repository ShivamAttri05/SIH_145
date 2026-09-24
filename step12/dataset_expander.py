import csv
import os
import random


# ============================================================
# CONFIGURATION
# ============================================================

OUTPUT_DIR = "step12/dataset"

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "expanded_network_dataset.csv"
)

RANDOM_SEED = 42

SAMPLES_PER_CLASS = 500


random.seed(
    RANDOM_SEED
)


# ============================================================
# FEATURE GENERATOR
# ============================================================

def create_record(
    packets,
    bytes_count,
    unique_destination_ips,
    unique_destination_ports,
    duration,
    packets_per_sec,
    bytes_per_sec,
    tcp_packets,
    syn_packets,
    ack_packets,
    rst_packets,
    fin_packets,
    dns_packets,
    average_inter_arrival,
    label
):

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

    return {

        "window_id": 0,

        "source_ip":
            f"192.168.{random.randint(1, 250)}."
            f"{random.randint(1, 254)}",

        "packets": packets,

        "bytes": bytes_count,

        "unique_destination_ips":
            unique_destination_ips,

        "unique_destination_ports":
            unique_destination_ports,

        "duration":
            duration,

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

        "label":
            label
    }


# ============================================================
# BENIGN TRAFFIC
# ============================================================

def generate_benign():

    records = []

    for _ in range(SAMPLES_PER_CLASS):

        packets = random.randint(
            5,
            80
        )

        avg_packet_size = random.randint(
            60,
            1000
        )

        bytes_count = (
            packets *
            avg_packet_size
        )

        duration = random.uniform(
            2.0,
            10.0
        )

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            bytes_count / duration
        )

        tcp_packets = random.randint(
            int(packets * 0.4),
            packets
        )

        syn_packets = random.randint(
            0,
            max(1, int(tcp_packets * 0.1))
        )

        ack_packets = random.randint(
            0,
            tcp_packets
        )

        rst_packets = random.randint(
            0,
            max(1, int(tcp_packets * 0.05))
        )

        fin_packets = random.randint(
            0,
            max(1, int(tcp_packets * 0.1))
        )

        dns_packets = random.randint(
            0,
            min(10, packets)
        )

        unique_destination_ips = random.randint(
            1,
            5
        )

        unique_destination_ports = random.randint(
            1,
            4
        )

        average_inter_arrival = (
            duration / packets
            if packets > 1
            else 0
        )

        records.append(
            create_record(
                packets,
                bytes_count,
                unique_destination_ips,
                unique_destination_ports,
                duration,
                packets_per_sec,
                bytes_per_sec,
                tcp_packets,
                syn_packets,
                ack_packets,
                rst_packets,
                fin_packets,
                dns_packets,
                average_inter_arrival,
                "BENIGN"
            )
        )

    return records


# ============================================================
# DDOS
# ============================================================

def generate_ddos():

    records = []

    for _ in range(SAMPLES_PER_CLASS):

        packets = random.randint(
            100,
            5000
        )

        avg_packet_size = random.randint(
            40,
            300
        )

        bytes_count = (
            packets *
            avg_packet_size
        )

        duration = random.uniform(
            0.5,
            10.0
        )

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            bytes_count / duration
        )

        tcp_packets = packets

        syn_packets = int(
            tcp_packets *
            random.uniform(
                0.85,
                1.0
            )
        )

        ack_packets = random.randint(
            0,
            max(1, int(packets * 0.05))
        )

        rst_packets = random.randint(
            0,
            max(1, int(packets * 0.02))
        )

        fin_packets = random.randint(
            0,
            max(1, int(packets * 0.01))
        )

        dns_packets = 0

        unique_destination_ips = random.randint(
            1,
            3
        )

        unique_destination_ports = random.randint(
            1,
            3
        )

        average_inter_arrival = (
            duration / packets
        )

        records.append(
            create_record(
                packets,
                bytes_count,
                unique_destination_ips,
                unique_destination_ports,
                duration,
                packets_per_sec,
                bytes_per_sec,
                tcp_packets,
                syn_packets,
                ack_packets,
                rst_packets,
                fin_packets,
                dns_packets,
                average_inter_arrival,
                "DDOS"
            )
        )

    return records


# ============================================================
# RECONNAISSANCE
# ============================================================

def generate_reconnaissance():

    records = []

    for _ in range(SAMPLES_PER_CLASS):

        unique_destination_ports = random.randint(
            5,
            100
        )

        packets = unique_destination_ports + random.randint(
            0,
            20
        )

        bytes_count = (
            packets *
            random.randint(
                40,
                80
            )
        )

        duration = random.uniform(
            1.0,
            20.0
        )

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            bytes_count / duration
        )

        tcp_packets = packets

        syn_packets = int(
            tcp_packets *
            random.uniform(
                0.7,
                1.0
            )
        )

        ack_packets = random.randint(
            0,
            max(1, int(tcp_packets * 0.1))
        )

        rst_packets = random.randint(
            0,
            max(1, int(tcp_packets * 0.2))
        )

        fin_packets = 0

        dns_packets = 0

        unique_destination_ips = random.randint(
            1,
            10
        )

        average_inter_arrival = (
            duration / packets
        )

        records.append(
            create_record(
                packets,
                bytes_count,
                unique_destination_ips,
                unique_destination_ports,
                duration,
                packets_per_sec,
                bytes_per_sec,
                tcp_packets,
                syn_packets,
                ack_packets,
                rst_packets,
                fin_packets,
                dns_packets,
                average_inter_arrival,
                "RECONNAISSANCE"
            )
        )

    return records


# ============================================================
# DNS ANOMALY
# ============================================================

def generate_dns_anomaly():

    records = []

    for _ in range(SAMPLES_PER_CLASS):

        packets = random.randint(
            20,
            300
        )

        dns_packets = int(
            packets *
            random.uniform(
                0.7,
                1.0
            )
        )

        avg_packet_size = random.randint(
            60,
            500
        )

        bytes_count = (
            packets *
            avg_packet_size
        )

        duration = random.uniform(
            1.0,
            15.0
        )

        packets_per_sec = (
            packets / duration
        )

        bytes_per_sec = (
            bytes_count / duration
        )

        tcp_packets = 0

        syn_packets = 0
        ack_packets = 0
        rst_packets = 0
        fin_packets = 0

        unique_destination_ips = random.randint(
            1,
            3
        )

        unique_destination_ports = 1

        average_inter_arrival = (
            duration / packets
        )

        records.append(
            create_record(
                packets,
                bytes_count,
                unique_destination_ips,
                unique_destination_ports,
                duration,
                packets_per_sec,
                bytes_per_sec,
                tcp_packets,
                syn_packets,
                ack_packets,
                rst_packets,
                fin_packets,
                dns_packets,
                average_inter_arrival,
                "DNS_ANOMALY"
            )
        )

    return records


# ============================================================
# SAVE DATASET
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

        writer.writerows(
            records
        )


# ============================================================
# SUMMARY
# ============================================================

def show_summary(records):

    counts = {}

    for record in records:

        label = record["label"]

        counts[label] = (
            counts.get(label, 0) + 1
        )

    print()
    print("=" * 90)
    print("EXPANDED DATASET SUMMARY")
    print("=" * 90)

    print()

    for label, count in counts.items():

        print(
            f"{label:20s}: {count}"
        )

    print()

    print(
        f"Total records: {len(records)}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 90)
    print("STEP 12 - DATASET EXPANSION")
    print("=" * 90)

    print()
    print(
        f"Samples per class: {SAMPLES_PER_CLASS}"
    )

    print()

    all_records = []

    print("Generating BENIGN samples...")

    all_records.extend(
        generate_benign()
    )

    print("Generating DDOS samples...")

    all_records.extend(
        generate_ddos()
    )

    print("Generating RECONNAISSANCE samples...")

    all_records.extend(
        generate_reconnaissance()
    )

    print("Generating DNS_ANOMALY samples...")

    all_records.extend(
        generate_dns_anomaly()
    )

    # Shuffle the complete dataset.
    random.shuffle(
        all_records
    )

    show_summary(
        all_records
    )

    save_dataset(
        all_records
    )

    print("=" * 90)
    print("DATASET SAVED")
    print("=" * 90)

    print()
    print(
        f"File: {OUTPUT_FILE}"
    )

    print()

    print("=" * 90)
    print("STEP 12 COMPLETE")
    print("=" * 90)


if __name__ == "__main__":
    main()