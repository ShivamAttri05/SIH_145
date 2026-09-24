import os
import joblib
import pandas as pd


# ============================================================
# MODEL CONFIGURATION
# ============================================================

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
# DETECTION SERVICE
# ============================================================

class DetectionService:

    def __init__(self):

        if not os.path.exists(MODEL_FILE):

            raise FileNotFoundError(
                f"ML model not found: {MODEL_FILE}"
            )

        print()
        print("Loading ML model...")

        self.model = joblib.load(
            MODEL_FILE
        )

        print("ML model loaded successfully.")

    # ========================================================
    # RULE ENGINE
    # ========================================================

    def evaluate_rules(self, features):

        evidence = []

        rule_score = 0

        # ----------------------------------------------------
        # HIGH PACKET RATE
        # ----------------------------------------------------

        if (
            features["packets_per_sec"]
            >= HIGH_PACKET_RATE
        ):

            evidence.append(
                "[HIGH_PACKET_RATE] "
                f"Packet rate "
                f"{features['packets_per_sec']:.2f} "
                f"packets/sec"
            )

            rule_score += 20

        # ----------------------------------------------------
        # HIGH BYTE RATE
        # ----------------------------------------------------

        if (
            features["bytes_per_sec"]
            >= HIGH_BYTE_RATE
        ):

            evidence.append(
                "[HIGH_BYTE_RATE] "
                f"Byte rate "
                f"{features['bytes_per_sec']:.2f} "
                f"bytes/sec"
            )

            rule_score += 15

        # ----------------------------------------------------
        # PORT SCANNING
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # DNS ACTIVITY
        # ----------------------------------------------------

        if (
            features["dns_packets"]
            >= DNS_QUERY_THRESHOLD
        ):

            evidence.append(
                "[HIGH_DNS_ACTIVITY] "
                f"Generated "
                f"{features['dns_packets']} "
                f"DNS packets"
            )

            rule_score += 20

        # ----------------------------------------------------
        # SYN RATIO
        # ----------------------------------------------------

        if (
            features["tcp_packets"] > 0
            and
            features["syn_ratio"]
            >= HIGH_SYN_RATIO
        ):

            evidence.append(
                "[HIGH_SYN_RATIO] "
                f"SYN ratio "
                f"{features['syn_ratio']:.2f}"
            )

            rule_score += 20

        # Cap deterministic contribution

        rule_score = min(
            rule_score,
            30
        )

        return rule_score, evidence

    # ========================================================
    # RISK ENGINE
    # ========================================================

    def calculate_risk(
        self,
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

            ml_score = (
                confidence * 60
            )

            behavior_score = 10.0

            risk_score = (
                ml_score
                + rule_score
                + behavior_score
            )

            risk_score = min(
                risk_score,
                100
            )

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

    # ========================================================
    # ANALYZE FEATURES
    # ========================================================

    def analyze(
        self,
        features
    ):

        # ----------------------------------------------------
        # Create DataFrame
        # ----------------------------------------------------

        feature_df = pd.DataFrame(
            [features],
            columns=FEATURE_COLUMNS
        )

        # ----------------------------------------------------
        # ML prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            feature_df
        )[0]

        probabilities = (
            self.model.predict_proba(
                feature_df
            )[0]
        )

        confidence = float(
            max(probabilities)
        )

        # ----------------------------------------------------
        # Rules
        # ----------------------------------------------------

        rule_score, evidence = (
            self.evaluate_rules(
                features
            )
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        (
            ml_score,
            behavior_score,
            risk_score,
            severity
        ) = self.calculate_risk(
            prediction,
            confidence,
            rule_score
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        return {

            "threat_class":
                str(prediction),

            "confidence":
                round(confidence, 4),

            "ml_risk_contribution":
                round(ml_score, 2),

            "rule_contribution":
                round(rule_score, 2),

            "behavior_contribution":
                round(behavior_score, 2),

            "risk_score":
                round(risk_score, 2),

            "severity":
                severity,

            "evidence":
                evidence,
        }