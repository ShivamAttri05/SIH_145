import sys
import os
import time
import joblib
import pandas as pd

from scapy.all import rdpcap, IP, TCP, UDP


# ============================================================
# CONFIGURATION
# ============================================================

WINDOW_SIZE = 10.0

MODEL_FILE = (
    "step14/models/threat_detection_model.pkl"
)

FEATURE_COLUMNS = [
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
]


# ============================================================
# RULE THRESHOLDS
# ============================================================

HIGH_PACKET_RATE = 1000
HIGH_BYTE_RATE = 1_000_000
PORT_SCAN_THRESHOLD = 10
DNS_QUERY_THRESHOLD = 20
HIGH_SYN_RATIO = 0.80


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_FILE):

        print()
        print("ERROR: ML model not found.")
        print(f"Expected model: {MODEL_FILE}")
        print()

        sys.exit(1)

    print()
    print("Loading persistent ML model...")
    print(f"Model: {MODEL_FILE}")

    model = joblib.load(MODEL_FILE)

    print("ML model loaded successfully.")

    return model


# ============================================================
# GET PACKET SIZE
# ============================================================

def get_packet_size(packet):

    return len(packet)


# ============================================================
# GET SOURCE IP
# ============================================================

def get_source_ip(packet):

    if IP in packet:

        return packet[IP].src

    return None


# ============================================================
# GET DESTINATION IP
# ============================================================

def get_destination_ip(packet):

    if IP in packet:

        return packet[IP].dst

    return None


# ============================================================
# GET DESTINATION PORT
# ============================================================

def get_destination_port(packet):

    if TCP in packet:

        return packet[TCP].dport

    if UDP in packet:

        return packet[UDP].dport

    return None


# ============================================================
# CHECK DNS
# ============================================================

def is_dns_packet(packet):

    if UDP in packet:

        sport = packet[UDP].sport
        dport = packet[UDP].dport

        if sport == 53 or dport == 53:
            return True

    if TCP in packet:

        sport = packet[TCP].sport
        dport = packet[TCP].dport

        if sport == 53 or dport == 53:
            return True

    return False


# ============================================================
# CREATE SOURCE RECORD
# ============================================================

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


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(record, packet):

    if IP not in packet:

        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    record["packets"] += 1

    record["bytes"] += get_packet_size(packet)

    record["destination_ips"].add(dst_ip)

    record["timestamps"].append(float(packet.time))

    destination_port = get_destination_port(packet)

    if destination_port is not None:

        record["destination_ports"].add(destination_port)

    # --------------------------------------------------------
    # TCP FEATURES
    # --------------------------------------------------------

    if TCP in packet:

        record["tcp_packets"] += 1

        flags = packet[TCP].flags

        if flags & 0x02:
            record["syn_packets"] += 1

        if flags & 0x10:
            record["ack_packets"] += 1

        if flags & 0x04:
            record["rst_packets"] += 1

        if flags & 0x01:
            record["fin_packets"] += 1

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    if is_dns_packet(packet):

        record["dns_packets"] += 1


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(record):

    packets = record["packets"]

    bytes_count = record["bytes"]

    timestamps = record["timestamps"]

    if packets == 0:

        return None

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    if len(timestamps) > 1:

        duration = max(timestamps) - min(timestamps)

    else:

        duration = 0.0

    # Prevent division by zero
    if duration <= 0:

        packets_per_sec = 0.0
        bytes_per_sec = 0.0

    else:

        packets_per_sec = packets / duration
        bytes_per_sec = bytes_count / duration

    # --------------------------------------------------------
    # TCP ratios
    # --------------------------------------------------------

    tcp_packets = record["tcp_packets"]

    if tcp_packets > 0:

        syn_ratio = (
            record["syn_packets"] / tcp_packets
        )

        ack_ratio = (
            record["ack_packets"] / tcp_packets
        )

        rst_ratio = (
            record["rst_packets"] / tcp_packets
        )

        fin_ratio = (
            record["fin_packets"] / tcp_packets
        )

    else:

        syn_ratio = 0.0
        ack_ratio = 0.0
        rst_ratio = 0.0
        fin_ratio = 0.0

    # --------------------------------------------------------
    # Inter-arrival time
    # --------------------------------------------------------

    timestamps_sorted = sorted(timestamps)

    if len(timestamps_sorted) > 1:

        intervals = []

        for i in range(1, len(timestamps_sorted)):

            intervals.append(
                timestamps_sorted[i]
                - timestamps_sorted[i - 1]
            )

        average_inter_arrival = (
            sum(intervals) / len(intervals)
        )

    else:

        average_inter_arrival = 0.0

    # --------------------------------------------------------
    # Feature dictionary
    # --------------------------------------------------------

    features = {

        "packets": packets,

        "bytes": bytes_count,

        "unique_destination_ips":
            len(record["destination_ips"]),

        "unique_destination_ports":
            len(record["destination_ports"]),

        "duration":
            duration,

        "packets_per_sec":
            packets_per_sec,

        "bytes_per_sec":
            bytes_per_sec,

        "tcp_packets":
            tcp_packets,

        "syn_packets":
            record["syn_packets"],

        "ack_packets":
            record["ack_packets"],

        "rst_packets":
            record["rst_packets"],

        "fin_packets":
            record["fin_packets"],

        "syn_ratio":
            syn_ratio,

        "ack_ratio":
            ack_ratio,

        "rst_ratio":
            rst_ratio,

        "fin_ratio":
            fin_ratio,

        "dns_packets":
            record["dns_packets"],

        "average_inter_arrival":
            average_inter_arrival,
    }

    return features


# ============================================================
# RULE ENGINE
# ============================================================

def evaluate_rules(features):

    evidence = []

    rule_score = 0

    # --------------------------------------------------------
    # HIGH PACKET RATE
    # --------------------------------------------------------

    if features["packets_per_sec"] >= HIGH_PACKET_RATE:

        evidence.append(
            "[HIGH_PACKET_RATE] "
            f"Packet rate "
            f"{features['packets_per_sec']:.2f} packets/sec"
        )

        rule_score += 20

    # --------------------------------------------------------
    # HIGH BYTE RATE
    # --------------------------------------------------------

    if features["bytes_per_sec"] >= HIGH_BYTE_RATE:

        evidence.append(
            "[HIGH_BYTE_RATE] "
            f"Byte rate "
            f"{features['bytes_per_sec']:.2f} bytes/sec"
        )

        rule_score += 15

    # --------------------------------------------------------
    # PORT SCANNING
    # --------------------------------------------------------

    if (
        features["unique_destination_ports"]
        >= PORT_SCAN_THRESHOLD
    ):

        evidence.append(
            "[PORT_SCAN_BEHAVIOR] "
            f"Contacted "
            f"{features['unique_destination_ports']} "
            f"destination ports"
        )

        rule_score += 25

    # --------------------------------------------------------
    # DNS ACTIVITY
    # --------------------------------------------------------

    if features["dns_packets"] >= DNS_QUERY_THRESHOLD:

        evidence.append(
            "[HIGH_DNS_ACTIVITY] "
            f"Generated "
            f"{features['dns_packets']} DNS packets"
        )

        rule_score += 20

    # --------------------------------------------------------
    # SYN RATIO
    # --------------------------------------------------------

    if (
        features["tcp_packets"] > 0
        and features["syn_ratio"] >= HIGH_SYN_RATIO
    ):

        evidence.append(
            "[HIGH_SYN_RATIO] "
            f"SYN ratio "
            f"{features['syn_ratio']:.2f}"
        )

        rule_score += 20

    # Maximum deterministic contribution

    rule_score = min(rule_score, 30)

    return rule_score, evidence


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    prediction,
    confidence,
    rule_score
):

    if prediction == "BENIGN":

        ml_score = 0.0
        behavior_score = 0.0

        risk_score = 0.0

        severity = "LOW"

    else:

        ml_score = confidence * 60

        behavior_score = 10.0

        risk_score = (
            ml_score
            + rule_score
            + behavior_score
        )

        risk_score = min(risk_score, 100)

        if risk_score >= 80:

            severity = "CRITICAL"

        elif risk_score >= 60:

            severity = "HIGH"

        elif risk_score >= 30:

            severity = "MEDIUM"

        else:

            severity = "LOW"

    return (
        ml_score,
        behavior_score,
        risk_score,
        severity
    )


# ============================================================
# PROCESS WINDOW
# ============================================================

def process_window(
    source_records,
    model,
    event_number
):

    for source_ip, record in source_records.items():

        features = build_features(record)

        if features is None:

            continue

        # ----------------------------------------------------
        # Prepare ML input
        # ----------------------------------------------------

        feature_df = pd.DataFrame(
            [features],
            columns=FEATURE_COLUMNS
        )

        # ----------------------------------------------------
        # ML prediction
        # ----------------------------------------------------

        prediction = model.predict(feature_df)[0]

        probabilities = model.predict_proba(
            feature_df
        )[0]

        confidence = max(probabilities)

        # ----------------------------------------------------
        # Rule engine
        # ----------------------------------------------------

        rule_score, evidence = evaluate_rules(
            features
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        (
            ml_score,
            behavior_score,
            risk_score,
            severity
        ) = calculate_risk(
            prediction,
            confidence,
            rule_score
        )

        # ----------------------------------------------------
        # Display
        # ----------------------------------------------------

        print()
        print("=" * 80)

        print(
            f"LIVE PCAP EVENT #{event_number}"
        )

        print("=" * 80)

        print()

        print(
            f"Source IP:              {source_ip}"
        )

        print(
            f"Packets:                {features['packets']}"
        )

        print(
            f"Bytes:                  {features['bytes']}"
        )

        print(
            "Destination IPs:        "
            f"{features['unique_destination_ips']}"
        )

        print(
            "Destination Ports:      "
            f"{features['unique_destination_ports']}"
        )

        print(
            f"TCP Packets:            "
            f"{features['tcp_packets']}"
        )

        print(
            f"SYN Ratio:              "
            f"{features['syn_ratio']:.2f}"
        )

        print(
            f"DNS Packets:            "
            f"{features['dns_packets']}"
        )

        print()

        print(
            f"ML Threat Class:        "
            f"{prediction}"
        )

        print(
            f"ML Confidence:          "
            f"{confidence:.4f}"
        )

        print()

        print(
            f"ML Risk Contribution:   "
            f"{ml_score:.2f}"
        )

        print(
            f"Rule Contribution:      "
            f"{rule_score:.2f}"
        )

        print(
            f"Behavior Contribution:  "
            f"{behavior_score:.2f}"
        )

        print()

        print(
            f"FINAL RISK SCORE:       "
            f"{risk_score:.2f}/100"
        )

        print(
            f"SEVERITY:               "
            f"{severity}"
        )

        print()

        print("Supporting Evidence:")

        if evidence:

            for item in evidence:

                print(f"  {item}")

        else:

            print(
                "  No deterministic rule triggered."
            )

        print()

        event_number += 1

    return event_number


# ============================================================
# PCAP STREAM
# ============================================================

def stream_pcap(
    pcap_file,
    model
):

    print()
    print("=" * 80)
    print("STEP 15 — LIVE PCAP STREAMING")
    print("=" * 80)

    print()
    print(f"PCAP File: {pcap_file}")
    print(f"Window Size: {WINDOW_SIZE} seconds")

    packets = rdpcap(pcap_file)

    print()
    print(
        f"Total packets loaded: {len(packets)}"
    )

    if len(packets) == 0:

        print("No packets found.")

        return

    print()
    print("Starting passive packet replay...")
    print("Packets are NOT transmitted onto the network.")
    print()

    # --------------------------------------------------------
    # Determine starting timestamp
    # --------------------------------------------------------

    first_timestamp = float(
        packets[0].time
    )

    window_start = first_timestamp

    current_window = {}

    event_number = 1

    previous_timestamp = first_timestamp

    # --------------------------------------------------------
    # Process packets
    # --------------------------------------------------------

    for packet in packets:

        packet_timestamp = float(packet.time)

        # ----------------------------------------------------
        # Simulate real-time delay
        # ----------------------------------------------------

        delay = (
            packet_timestamp
            - previous_timestamp
        )

        if delay > 0:

            # Limit delay for practical demonstration
            time.sleep(
                min(delay, 0.5)
            )

        previous_timestamp = packet_timestamp

        # ----------------------------------------------------
        # Check window boundary
        # ----------------------------------------------------

        while (
            packet_timestamp
            >= window_start + WINDOW_SIZE
        ):

            if current_window:

                event_number = process_window(
                    current_window,
                    model,
                    event_number
                )

            current_window = {}

            window_start += WINDOW_SIZE

        # ----------------------------------------------------
        # Ignore non-IP traffic
        # ----------------------------------------------------

        if IP not in packet:

            continue

        source_ip = packet[IP].src

        if source_ip not in current_window:

            current_window[source_ip] = (
                create_source_record()
            )

        process_packet(
            current_window[source_ip],
            packet
        )

    # --------------------------------------------------------
    # Process final window
    # --------------------------------------------------------

    if current_window:

        event_number = process_window(
            current_window,
            model,
            event_number
        )

    print()
    print("=" * 80)
    print("PCAP STREAMING COMPLETE")
    print("=" * 80)

    print()
    print(
        f"Total live events generated: "
        f"{event_number - 1}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print()
        print(
            "Usage:"
        )

        print(
            "python step15/live_pcap_stream.py "
            "<pcap_file>"
        )

        print()

        print(
            "Example:"
        )

        print(
            "python step15/live_pcap_stream.py "
            "step9/generated/port_scan.pcap"
        )

        print()

        sys.exit(1)

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):

        print()
        print(
            f"ERROR: PCAP file not found: "
            f"{pcap_file}"
        )

        print()

        sys.exit(1)

    model = load_model()

    stream_pcap(
        pcap_file,
        model
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()