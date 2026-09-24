from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import sys
import os


# ============================================================
# STEP 4 - RULE-BASED THREAT DETECTION
# ============================================================


# ------------------------------------------------------------
# Detection thresholds
# ------------------------------------------------------------

HIGH_PACKET_RATE = 1000
HIGH_BYTE_RATE = 1_000_000

PORT_SCAN_THRESHOLD = 10

DNS_QUERY_THRESHOLD = 5


# ------------------------------------------------------------
# Protocol detection
# ------------------------------------------------------------

def get_protocol(packet):

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    else:
        return "OTHER"


# ------------------------------------------------------------
# Flow identification
# ------------------------------------------------------------

def get_flow_key(packet):

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    if protocol == "TCP":

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif protocol == "UDP":

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:

        src_port = 0
        dst_port = 0

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


# ------------------------------------------------------------
# Extract flows
# ------------------------------------------------------------

def extract_flows(pcap_file):

    print(f"\nReading PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Total packets: {len(packets)}")

    flows = defaultdict(lambda: {

        "first_timestamp": None,

        "last_timestamp": None,

        "packets": 0,

        "bytes": 0

    })

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        flow_key = get_flow_key(packet)

        timestamp = float(packet.time)

        packet_size = len(packet)

        if flows[flow_key]["first_timestamp"] is None:

            flows[flow_key]["first_timestamp"] = timestamp

        flows[flow_key]["last_timestamp"] = timestamp

        flows[flow_key]["packets"] += 1

        flows[flow_key]["bytes"] += packet_size

    return flows


# ------------------------------------------------------------
# Calculate features
# ------------------------------------------------------------

def calculate_features(flows):

    feature_list = []

    for flow_key, flow_data in flows.items():

        src_ip, dst_ip, src_port, dst_port, protocol = flow_key

        duration = (
            flow_data["last_timestamp"]
            - flow_data["first_timestamp"]
        )

        # Avoid division by zero
        if duration > 0:

            packets_per_sec = (
                flow_data["packets"]
                / duration
            )

            bytes_per_sec = (
                flow_data["bytes"]
                / duration
            )

        else:

            packets_per_sec = 0

            bytes_per_sec = 0

        avg_packet_size = (
            flow_data["bytes"]
            / flow_data["packets"]
        )

        features = {

            "src_ip": src_ip,

            "dst_ip": dst_ip,

            "src_port": src_port,

            "dst_port": dst_port,

            "protocol": protocol,

            "packets": flow_data["packets"],

            "bytes": flow_data["bytes"],

            "duration": duration,

            "packets_per_sec": packets_per_sec,

            "bytes_per_sec": bytes_per_sec,

            "avg_packet_size": avg_packet_size

        }

        feature_list.append(features)

    return feature_list


# ============================================================
# ALERT CREATION
# ============================================================

def create_alert(
    threat_class,
    severity,
    confidence,
    feature,
    evidence
):

    alert = {

        "timestamp":
            datetime.now().isoformat(),

        "flow_id":
            (
                f"{feature['src_ip']}:"
                f"{feature['src_port']}"
                " -> "
                f"{feature['dst_ip']}:"
                f"{feature['dst_port']}"
            ),

        "threat_class":
            threat_class,

        "severity":
            severity,

        "confidence":
            confidence,

        "source_ip":
            feature["src_ip"],

        "destination_ip":
            feature["dst_ip"],

        "evidence":
            evidence

    }

    return alert


# ============================================================
# INDIVIDUAL FLOW DETECTION
# ============================================================

def detect_high_rate_traffic(feature):

    alerts = []

    packet_rate = feature["packets_per_sec"]

    byte_rate = feature["bytes_per_sec"]


    # --------------------------------------------------------
    # High packet rate
    # --------------------------------------------------------

    if packet_rate >= HIGH_PACKET_RATE:

        evidence = (
            f"Packet rate is "
            f"{packet_rate:.2f} packets/sec"
        )

        alert = create_alert(

            threat_class="HIGH_RATE_TRAFFIC",

            severity="HIGH",

            confidence=0.90,

            feature=feature,

            evidence=evidence
        )

        alerts.append(alert)


    # --------------------------------------------------------
    # High byte rate
    # --------------------------------------------------------

    elif byte_rate >= HIGH_BYTE_RATE:

        evidence = (
            f"Byte rate is "
            f"{byte_rate:.2f} bytes/sec"
        )

        alert = create_alert(

            threat_class="HIGH_RATE_TRAFFIC",

            severity="HIGH",

            confidence=0.85,

            feature=feature,

            evidence=evidence
        )

        alerts.append(alert)


    return alerts


# ============================================================
# DNS DETECTION
# ============================================================

def detect_dns_activity(features):

    alerts = []

    dns_flows = []

    for feature in features:

        if feature["dst_port"] == 53:

            dns_flows.append(feature)


    # --------------------------------------------------------
    # Count DNS activity per source
    # --------------------------------------------------------

    source_dns_count = defaultdict(int)

    for feature in dns_flows:

        source_dns_count[
            feature["src_ip"]
        ] += feature["packets"]


    # --------------------------------------------------------
    # Detect excessive DNS activity
    # --------------------------------------------------------

    for source_ip, count in source_dns_count.items():

        if count >= DNS_QUERY_THRESHOLD:

            matching_feature = next(

                (
                    f for f in dns_flows
                    if f["src_ip"] == source_ip
                ),

                dns_flows[0]
            )

            evidence = (

                f"Source generated "
                f"{count} DNS packets"
            )

            alert = create_alert(

                threat_class="SUSPICIOUS_DNS_ACTIVITY",

                severity="MEDIUM",

                confidence=0.70,

                feature=matching_feature,

                evidence=evidence
            )

            alerts.append(alert)


    return alerts


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def detect_port_scanning(features):

    alerts = []

    source_ports = defaultdict(set)

    source_features = defaultdict(list)


    # --------------------------------------------------------
    # Collect destination ports per source
    # --------------------------------------------------------

    for feature in features:

        source_ip = feature["src_ip"]

        destination_port = feature["dst_port"]

        if destination_port != 0:

            source_ports[source_ip].add(
                destination_port
            )

            source_features[source_ip].append(
                feature
            )


    # --------------------------------------------------------
    # Detect many destination ports
    # --------------------------------------------------------

    for source_ip, ports in source_ports.items():

        unique_ports = len(ports)

        if unique_ports >= PORT_SCAN_THRESHOLD:

            feature = source_features[source_ip][0]

            evidence = (

                f"Source contacted "
                f"{unique_ports} unique "
                f"destination ports"
            )

            alert = create_alert(

                threat_class="PORT_SCAN",

                severity="HIGH",

                confidence=0.88,

                feature=feature,

                evidence=evidence
            )

            alerts.append(alert)


    return alerts


# ============================================================
# RUN ALL DETECTIONS
# ============================================================

def detect_threats(features):

    alerts = []


    # --------------------------------------------------------
    # Individual-flow detection
    # --------------------------------------------------------

    for feature in features:

        alerts.extend(
            detect_high_rate_traffic(feature)
        )


    # --------------------------------------------------------
    # Multi-flow detection
    # --------------------------------------------------------

    alerts.extend(
        detect_dns_activity(features)
    )

    alerts.extend(
        detect_port_scanning(features)
    )


    return alerts


# ============================================================
# DISPLAY ALERTS
# ============================================================

def display_alerts(alerts):

    print("\n")

    print("=" * 110)

    print("THREAT DETECTION RESULTS")

    print("=" * 110)


    if not alerts:

        print("\nNo threats detected.")

        print("=" * 110)

        return


    for index, alert in enumerate(
        alerts,
        start=1
    ):

        print(
            f"\nALERT #{index}"
        )

        print(
            f"Timestamp:          "
            f"{alert['timestamp']}"
        )

        print(
            f"Flow ID:            "
            f"{alert['flow_id']}"
        )

        print(
            f"Threat Class:       "
            f"{alert['threat_class']}"
        )

        print(
            f"Severity:           "
            f"{alert['severity']}"
        )

        print(
            f"Confidence:         "
            f"{alert['confidence']:.2f}"
        )

        print(
            f"Source IP:          "
            f"{alert['source_ip']}"
        )

        print(
            f"Destination IP:     "
            f"{alert['destination_ip']}"
        )

        print(
            f"Evidence:           "
            f"{alert['evidence']}"
        )

        print("-" * 90)


    print("\n")

    print("=" * 110)

    print(
        f"Total alerts: {len(alerts)}"
    )

    print("=" * 110)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: "
            "python step4/threat_detector.py "
            "step1/sample.pcapng"
        )

        return


    pcap_file = sys.argv[1]


    if not os.path.exists(pcap_file):

        print(
            f"\nERROR: PCAP file not found: "
            f"{pcap_file}"
        )

        return


    # --------------------------------------------------------
    # STEP 1
    # --------------------------------------------------------

    flows = extract_flows(
        pcap_file
    )


    # --------------------------------------------------------
    # STEP 2
    # --------------------------------------------------------

    features = calculate_features(
        flows
    )


    print(
        f"\nFeature records analyzed: "
        f"{len(features)}"
    )


    # --------------------------------------------------------
    # STEP 3
    # --------------------------------------------------------

    alerts = detect_threats(
        features
    )


    # --------------------------------------------------------
    # STEP 4
    # --------------------------------------------------------

    display_alerts(
        alerts
    )


if __name__ == "__main__":

    main()