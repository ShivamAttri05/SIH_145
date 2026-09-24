import os

import joblib
import pandas as pd
from step20.feature_engine.security_features import (
    FEATURE_COLUMNS,
    validate_feature_record,
)


MODEL_FILE = "step14/models/threat_detection_model.pkl"


HIGH_PACKET_RATE = 1000
HIGH_BYTE_RATE = 1_000_000
PORT_SCAN_THRESHOLD = 10
DNS_QUERY_THRESHOLD = 20
HIGH_SYN_RATIO = 0.80


class DetectionService:

    def __init__(self):

        if not os.path.exists(MODEL_FILE):

            raise FileNotFoundError(
                f"ML model not found: {MODEL_FILE}"
            )

        print("Loading ML model...")

        self.model = joblib.load(
            MODEL_FILE
        )

        print(
            "ML model loaded successfully."
        )


    # ============================================================
    # DETERMINISTIC RULE ENGINE
    # ============================================================

    def evaluate_rules(self, features):

        evidence = []

        rule_score = 0


        if (
            features["packets_per_sec"]
            >= HIGH_PACKET_RATE
        ):

            evidence.append(
                "[HIGH_PACKET_RATE] "
                f"Packet rate "
                f"{features['packets_per_sec']:.2f} "
                "packets/sec"
            )

            rule_score += 20


        if (
            features["bytes_per_sec"]
            >= HIGH_BYTE_RATE
        ):

            evidence.append(
                "[HIGH_BYTE_RATE] "
                f"Byte rate "
                f"{features['bytes_per_sec']:.2f} "
                "bytes/sec"
            )

            rule_score += 15


        if (
            features["unique_destination_ports"]
            >= PORT_SCAN_THRESHOLD
        ):

            evidence.append(
                "[PORT_SCAN_BEHAVIOR] "
                f"Contacted "
                f"{features['unique_destination_ports']} "
                "destination ports"
            )

            rule_score += 25


        if (
            features["dns_packets"]
            >= DNS_QUERY_THRESHOLD
        ):

            evidence.append(
                "[HIGH_DNS_ACTIVITY] "
                f"Generated "
                f"{features['dns_packets']} "
                "DNS packets"
            )

            rule_score += 20


        if (
            features["tcp_packets"] > 0
            and features["syn_ratio"]
            >= HIGH_SYN_RATIO
        ):

            evidence.append(
                "[HIGH_SYN_RATIO] "
                f"SYN ratio "
                f"{features['syn_ratio']:.2f}"
            )

            rule_score += 20


        rule_score = min(
            rule_score,
            30
        )


        return (
            rule_score,
            evidence
        )


    # ============================================================
    # BEHAVIORAL RISK ENGINE
    # ============================================================

    def calculate_behavior_score(
        self,
        features
    ):

        behavior_score = 0.0

        evidence = []


        # --------------------------------------------------------
        # 1. DESTINATION PORT FAN-OUT
        # --------------------------------------------------------

        destination_ports = float(
            features.get(
                "unique_destination_ports",
                0
            )
        )

        if destination_ports >= 20:

            port_score = 30.0

            evidence.append(
                "[BEHAVIOR_PORT_FANOUT] "
                f"{int(destination_ports)} "
                "unique destination ports"
            )

        elif destination_ports >= 10:

            port_score = 22.0

            evidence.append(
                "[BEHAVIOR_PORT_FANOUT] "
                f"{int(destination_ports)} "
                "unique destination ports"
            )

        elif destination_ports >= 5:

            port_score = 12.0

        else:

            port_score = 0.0


        behavior_score += port_score


        # --------------------------------------------------------
        # 2. DESTINATION IP FAN-OUT
        # --------------------------------------------------------

        destination_ips = float(
            features.get(
                "unique_destination_ips",
                0
            )
        )

        if destination_ips >= 20:

            ip_score = 20.0

            evidence.append(
                "[BEHAVIOR_IP_FANOUT] "
                f"{int(destination_ips)} "
                "unique destination IPs"
            )

        elif destination_ips >= 10:

            ip_score = 15.0

        elif destination_ips >= 5:

            ip_score = 10.0

        elif destination_ips >= 2:

            ip_score = 5.0

        else:

            ip_score = 0.0


        behavior_score += ip_score


        # --------------------------------------------------------
        # 3. PACKET RATE
        # --------------------------------------------------------

        packet_rate = float(
            features.get(
                "packets_per_sec",
                0
            )
        )

        if packet_rate >= 10000:

            rate_score = 20.0

            evidence.append(
                "[BEHAVIOR_PACKET_RATE] "
                f"{packet_rate:.2f} "
                "packets/sec"
            )

        elif packet_rate >= 5000:

            rate_score = 15.0

        elif packet_rate >= 1000:

            rate_score = 10.0

        elif packet_rate >= 500:

            rate_score = 5.0

        else:

            rate_score = 0.0


        behavior_score += rate_score


        # --------------------------------------------------------
        # 4. SYN BEHAVIOR
        # --------------------------------------------------------

        syn_ratio = float(
            features.get(
                "syn_ratio",
                0
            )
        )

        tcp_packets = float(
            features.get(
                "tcp_packets",
                0
            )
        )


        if (
            tcp_packets > 0
            and syn_ratio >= 0.95
        ):

            syn_score = 15.0

            evidence.append(
                "[BEHAVIOR_SYN_PATTERN] "
                f"SYN ratio "
                f"{syn_ratio:.2f}"
            )

        elif (
            tcp_packets > 0
            and syn_ratio >= 0.80
        ):

            syn_score = 10.0

        elif (
            tcp_packets > 0
            and syn_ratio >= 0.60
        ):

            syn_score = 5.0

        else:

            syn_score = 0.0


        behavior_score += syn_score


        # --------------------------------------------------------
        # 5. DNS ACTIVITY
        # --------------------------------------------------------

        dns_packets = float(
            features.get(
                "dns_packets",
                0
            )
        )


        if dns_packets >= 100:

            dns_score = 15.0

            evidence.append(
                "[BEHAVIOR_DNS_VOLUME] "
                f"{int(dns_packets)} "
                "DNS packets"
            )

        elif dns_packets >= 50:

            dns_score = 12.0

        elif dns_packets >= 20:

            dns_score = 8.0

        elif dns_packets >= 10:

            dns_score = 4.0

        else:

            dns_score = 0.0


        behavior_score += dns_score


        # --------------------------------------------------------
        # FINAL BOUND
        # --------------------------------------------------------

        behavior_score = min(
            behavior_score,
            100.0
        )


        return (
            behavior_score,
            evidence
        )


    # ============================================================
    # RISK CALCULATION
    # ============================================================

    def calculate_risk(
        self,
        prediction,
        confidence,
        rule_score,
        behavior_score
    ):

        if prediction == "BENIGN":

            ml_score = 0.0

            behavior_contribution = 0.0

            risk_score = 0.0

            severity = "LOW"

        else:

            ml_score = confidence * 60.0

            behavior_contribution = (
                behavior_score * 0.10
            )

            risk_score = min(
                ml_score
                + rule_score
                + behavior_contribution,
                100.0
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
            behavior_contribution,
            risk_score,
            severity
        )


    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(self, features):

        validate_feature_record(features)

        feature_df = pd.DataFrame(
            [features],
            columns=FEATURE_COLUMNS
        )


        # --------------------------------------------------------
        # ML PREDICTION
        # --------------------------------------------------------

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


        # --------------------------------------------------------
        # RULE ANALYSIS
        # --------------------------------------------------------

        (
            rule_score,
            rule_evidence
        ) = self.evaluate_rules(
            features
        )


        # --------------------------------------------------------
        # BEHAVIOR ANALYSIS
        # --------------------------------------------------------

        (
            behavior_score,
            behavior_evidence
        ) = self.calculate_behavior_score(
            features
        )


        # --------------------------------------------------------
        # FINAL RISK
        # --------------------------------------------------------

        (
            ml_score,
            behavior_contribution,
            risk_score,
            severity
        ) = self.calculate_risk(
            prediction,
            confidence,
            rule_score,
            behavior_score
        )


        evidence = (
            rule_evidence
            + behavior_evidence
        )


        return {

            "threat_class":
                str(prediction),

            "confidence":
                round(
                    confidence,
                    4
                ),

            "ml_risk_contribution":
                round(
                    ml_score,
                    2
                ),

            "rule_contribution":
                round(
                    rule_score,
                    2
                ),

            "behavior_contribution":
                round(
                    behavior_contribution,
                    2
                ),

            "risk_score":
                round(
                    risk_score,
                    2
                ),

            "severity":
                severity,

            "evidence":
                evidence,
        }