import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

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
# LOAD DATASET
# ============================================================

def load_dataset():

    print()
    print("=" * 100)
    print("LOADING DATASET")
    print("=" * 100)

    df = pd.read_csv(
        DATASET_FILE
    )

    print()
    print(
        f"Dataset file : {DATASET_FILE}"
    )

    print(
        f"Total records: {len(df)}"
    )

    return df


# ============================================================
# TRAIN ML MODEL
# ============================================================

def train_model(df):

    print()
    print("=" * 100)
    print("TRAINING ML MODEL")
    print("=" * 100)

    X = df[FEATURE_COLUMNS].copy()

    y = df["label"].copy()

    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(
        X_train,
        y_train
    )

    print()
    print(
        f"Training records: {len(X_train)}"
    )

    print(
        f"Testing records : {len(X_test)}"
    )

    print()
    print("ML model training complete.")

    return model


# ============================================================
# RULE ENGINE
# ============================================================

def evaluate_rules(row):

    rules = []

    # --------------------------------------------------------
    # HIGH TRAFFIC
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
    # PORT SCANNING
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

def get_ml_prediction(
    model,
    row
):

    feature_values = [
        row[column]
        for column in FEATURE_COLUMNS
    ]

    prediction_input = pd.DataFrame(
        [feature_values],
        columns=FEATURE_COLUMNS
    )

    prediction = model.predict(
        prediction_input
    )[0]

    probabilities = model.predict_proba(
        prediction_input
    )[0]

    confidence = max(
        probabilities
    )

    return prediction, confidence


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(
    ml_prediction,
    ml_confidence,
    rules
):

    # --------------------------------------------------------
    # ML SCORE
    # --------------------------------------------------------

    ml_score = (
        ml_confidence * 60
    )

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
    # BEHAVIOR SCORE
    # --------------------------------------------------------

    behavior_score = 0

    if ml_prediction != "BENIGN":

        behavior_score = 10

    # --------------------------------------------------------
    # FINAL SCORE
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

    if risk_score >= 80:

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
# ALERT DISPLAY
# ============================================================

def display_alert(
    index,
    row,
    ml_prediction,
    ml_confidence,
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
        f"ALERT #{index}"
    )
    print("=" * 100)

    print()

    print(
        f"Source IP:              "
        f"{row['source_ip']}"
    )

    print(
        f"ML Threat Class:        "
        f"{ml_prediction}"
    )

    print(
        f"ML Confidence:          "
        f"{ml_confidence:.4f}"
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

        print("Supporting Evidence:")

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
# ANALYZE RECORDS
# ============================================================

def analyze_dataset(
    model,
    df
):

    print()
    print("=" * 100)
    print("HYBRID THREAT ANALYSIS")
    print("=" * 100)

    alert_count = 0

    # Analyze a limited number of records
    # for readable terminal output.

    for index, (_, row) in enumerate(
        df.iterrows()
    ):

        ml_prediction, ml_confidence = (
            get_ml_prediction(
                model,
                row
            )
        )

        rules = evaluate_rules(
            row
        )

        risk_data = calculate_risk(
            ml_prediction,
            ml_confidence,
            rules
        )

        risk_score = risk_data[0]

        # Display only meaningful alerts.

        if (
            ml_prediction != "BENIGN"
            or
            risk_score >= 30
        ):

            alert_count += 1

            display_alert(
                alert_count,
                row,
                ml_prediction,
                ml_confidence,
                rules,
                risk_data
            )

        if alert_count >= 10:

            break

    print()
    print("=" * 100)
    print(
        f"Displayed alerts: {alert_count}"
    )
    print("=" * 100)


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 100)
    print(
        "STEP 13 - HYBRID THREAT DETECTION"
    )
    print("=" * 100)

    df = load_dataset()

    model = train_model(
        df
    )

    analyze_dataset(
        model,
        df
    )

    print()
    print("=" * 100)
    print(
        "STEP 13 COMPLETE"
    )
    print("=" * 100)


if __name__ == "__main__":
    main()