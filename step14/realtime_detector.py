import time

import joblib
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = (
    "step14/models/threat_detection_model.pkl"
)

DATASET_FILE = (
    "step12/dataset/expanded_network_dataset.csv"
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

    "average_inter_arrival"
]


# ============================================================
# RULE THRESHOLDS
# ============================================================

HIGH_PACKET_RATE = 1000.0

HIGH_BYTE_RATE = 1_000_000.0

PORT_SCAN_THRESHOLD = 10

DNS_QUERY_THRESHOLD = 20

HIGH_SYN_RATIO = 0.80


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    print()
    print("=" * 100)
    print("LOADING PERSISTENT ML MODEL")
    print("=" * 100)

    model = joblib.load(
        MODEL_FILE
    )

    print()
    print(
        f"Model loaded: {MODEL_FILE}"
    )

    return model


# ============================================================
# RULE ENGINE
# ============================================================

def evaluate_rules(row):

    rules = []

    # --------------------------------------------------------
    # HIGH PACKET RATE
    # --------------------------------------------------------

    if (
        row["packets_per_sec"]
        >= HIGH_PACKET_RATE
    ):

        rules.append({
            "name":
                "HIGH_PACKET_RATE",

            "score":
                20,

            "evidence":
                f"Packet rate "
                f"{row['packets_per_sec']:.2f} "
                f"packets/sec"
        })


    # --------------------------------------------------------
    # HIGH BYTE RATE
    # --------------------------------------------------------

    if (
        row["bytes_per_sec"]
        >= HIGH_BYTE_RATE
    ):

        rules.append({
            "name":
                "HIGH_BYTE_RATE",

            "score":
                15,

            "evidence":
                f"Byte rate "
                f"{row['bytes_per_sec']:.2f} "
                f"bytes/sec"
        })


    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    if (
        row["unique_destination_ports"]
        >= PORT_SCAN_THRESHOLD
    ):

        rules.append({
            "name":
                "PORT_SCAN_BEHAVIOR",

            "score":
                25,

            "evidence":
                f"Contacted "
                f"{int(row['unique_destination_ports'])} "
                f"destination ports"
        })


    # --------------------------------------------------------
    # DNS BURST
    # --------------------------------------------------------

    if (
        row["dns_packets"]
        >= DNS_QUERY_THRESHOLD
    ):

        rules.append({
            "name":
                "HIGH_DNS_ACTIVITY",

            "score":
                20,

            "evidence":
                f"Generated "
                f"{int(row['dns_packets'])} "
                f"DNS packets"
        })


    # --------------------------------------------------------
    # HIGH SYN RATIO
    # --------------------------------------------------------

    if (
        row["tcp_packets"] > 0
        and
        row["syn_ratio"]
        >= HIGH_SYN_RATIO
    ):

        rules.append({
            "name":
                "HIGH_SYN_RATIO",

            "score":
                20,

            "evidence":
                f"SYN ratio "
                f"{row['syn_ratio']:.2f}"
        })


    return rules


# ============================================================
# ML PREDICTION
# ============================================================

def predict(
    model,
    row
):

    values = [
        row[column]
        for column in FEATURE_COLUMNS
    ]

    input_data = pd.DataFrame(
        [values],
        columns=FEATURE_COLUMNS
    )

    prediction = model.predict(
        input_data
    )[0]

    probabilities = model.predict_proba(
        input_data
    )[0]

    confidence = max(
        probabilities
    )

    return prediction, confidence


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    prediction,
    confidence,
    rules
):

    # --------------------------------------------------------
    # BENIGN TRAFFIC
    # --------------------------------------------------------

    if prediction == "BENIGN":

        ml_score = 0

        behavior_score = 0

    else:

        ml_score = (
            confidence * 60
        )

        behavior_score = 10


    # --------------------------------------------------------
    # RULE SCORE
    # --------------------------------------------------------

    rule_score = sum(
        rule["score"]
        for rule in rules
    )

    rule_score = min(
        rule_score,
        30
    )


    # --------------------------------------------------------
    # FINAL RISK
    # --------------------------------------------------------

    risk_score = (
        ml_score
        + rule_score
        + behavior_score
    )

    risk_score = min(
        risk_score,
        100
    )


    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    if prediction == "BENIGN":

        severity = "LOW"

    elif risk_score >= 80:

        severity = "CRITICAL"

    elif risk_score >= 60:

        severity = "HIGH"

    elif risk_score >= 30:

        severity = "MEDIUM"

    else:

        severity = "LOW"


    return (
        risk_score,
        severity,
        ml_score,
        rule_score,
        behavior_score
    )


# ============================================================
# ALERT
# ============================================================

def display_result(
    record_number,
    row,
    prediction,
    confidence,
    rules,
    risk_data
):

    (
        risk_score,
        severity,
        ml_score,
        rule_score,
        behavior_score
    ) = risk_data

    print()
    print("=" * 100)

    print(
        f"REAL-TIME EVENT #{record_number}"
    )

    print("=" * 100)

    print()

    print(
        f"Source IP:              "
        f"{row['source_ip']}"
    )

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

    if rules:

        print(
            "Supporting Evidence:"
        )

        for rule in rules:

            print(
                f"  [{rule['name']}] "
                f"{rule['evidence']}"
            )

    else:

        print(
            "Supporting Evidence: "
            "No deterministic rule triggered."
        )


# ============================================================
# REAL-TIME REPLAY
# ============================================================

def run_realtime_replay(
    model
):

    print()
    print("=" * 100)
    print("STARTING REAL-TIME FEATURE REPLAY")
    print("=" * 100)

    print()

    print(
        "Reading feature records..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()

    df = pd.read_csv(
        DATASET_FILE
    )

    record_number = 0

    try:

        for _, row in df.iterrows():

            record_number += 1

            prediction, confidence = (
                predict(
                    model,
                    row
                )
            )

            rules = evaluate_rules(
                row
            )

            risk_data = calculate_risk(
                prediction,
                confidence,
                rules
            )

            display_result(
                record_number,
                row,
                prediction,
                confidence,
                rules,
                risk_data
            )

            # Simulate a bounded-latency stream.
            time.sleep(0.1)

    except KeyboardInterrupt:

        print()
        print()
        print(
            "Real-time replay stopped."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 100)
    print(
        "STEP 14 - REAL-TIME THREAT DETECTOR"
    )
    print("=" * 100)

    model = load_model()

    run_realtime_replay(
        model
    )

    print()
    print("=" * 100)
    print(
        "STEP 14 COMPLETE"
    )
    print("=" * 100)


if __name__ == "__main__":
    main()