import os

import joblib
import pandas as pd
from step20.feature_engine.security_features import (
    FEATURE_COLUMNS,
    validate_feature_record,
)

from step20.dns_engine.dns_features import (
    analyze_dns_packets,
)

from step20.dns_engine.dns_aggregate import (
    aggregate_dns_features,
)

from step20.dns_engine.dga_detector import (
    calculate_dga_score,
)

from step20.dns_engine.dns_tunnel_detector import (
    calculate_tunnel_score,
)

from step20.c2_engine.c2_features import (
    analyze_c2_timing,
)

from step20.c2_engine.c2_destinations import (
    analyze_destination_behavior,
)

from step20.c2_engine.c2_detector import (
    calculate_c2_behavior_score,
)

from step20.tls_engine.tls_intelligence import (
    analyze_tls_intelligence,
)

MODEL_FILE = "step14/models/threat_detection_model.pkl"


HIGH_PACKET_RATE = 1000
HIGH_BYTE_RATE = 1_000_000
PORT_SCAN_THRESHOLD = 10
DNS_QUERY_THRESHOLD = 100
HIGH_SYN_RATIO = 0.80

MIN_TCP_PACKETS_FOR_SYN_ANALYSIS = 10

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
            features["tcp_packets"]
            >= MIN_TCP_PACKETS_FOR_SYN_ANALYSIS
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
            tcp_packets
            >= MIN_TCP_PACKETS_FOR_SYN_ANALYSIS
            and syn_ratio >= 0.95
        ):

            syn_score = 15.0

            evidence.append(
                "[BEHAVIOR_SYN_PATTERN] "
                f"SYN ratio "
                f"{syn_ratio:.2f}"
            )

        elif (
            tcp_packets
            >= MIN_TCP_PACKETS_FOR_SYN_ANALYSIS
            and syn_ratio >= 0.80
        ):

            syn_score = 10.0

        elif (
            tcp_packets
            >= MIN_TCP_PACKETS_FOR_SYN_ANALYSIS
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

    def analyze_dns_intelligence(
        self,
        packets: list,
    ) -> dict:

        if not packets:
            return {
                "dga_score": 0.0,
                "dga_classification": "DGA_UNLIKELY",
                "tunnel_score": 0.0,
                "tunnel_classification": "TUNNEL_UNLIKELY",
                "evidence": [],
                "aggregate": {},
            }

        query_features = analyze_dns_packets(
            packets
        )

        if not query_features:
            return {
                "dga_score": 0.0,
                "dga_classification": "DGA_UNLIKELY",
                "tunnel_score": 0.0,
                "tunnel_classification": "TUNNEL_UNLIKELY",
                "evidence": [],
                "aggregate": {},
            }

        aggregate = aggregate_dns_features(
            query_features
        )

        dga_result = calculate_dga_score(
            aggregate
        )

        tunnel_result = calculate_tunnel_score(
            aggregate
        )

        evidence = (
            dga_result["evidence"]
            + tunnel_result["evidence"]
        )

        return {
            "dga_score": dga_result["dga_score"],
            "dga_classification": dga_result[
                "classification"
            ],
            "tunnel_score": tunnel_result[
                "tunnel_score"
            ],
            "tunnel_classification": tunnel_result[
                "classification"
            ],
            "evidence": evidence,
            "aggregate": aggregate,
        }


    def analyze_c2_intelligence(
        self,
        packets: list,
    ) -> dict:

        if not packets:
            return {
                "c2_behavior_score": 0.0,
                "c2_classification": "C2_UNLIKELY",
                "evidence": [],
                "timing": [],
                "destinations": [],
                "pairs": [],
            }

        timing_results = analyze_c2_timing(
            packets
        )

        destination_results = (
            analyze_destination_behavior(
                packets
            )
        )

        if not timing_results:
            return {
                "c2_behavior_score": 0.0,
                "c2_classification": "C2_UNLIKELY",
                "evidence": [],
                "timing": [],
                "destinations": destination_results,
                "pairs": [],
            }

        if not destination_results:
            return {
                "c2_behavior_score": 0.0,
                "c2_classification": "C2_UNLIKELY",
                "evidence": [],
                "timing": timing_results,
                "destinations": [],
                "pairs": [],
            }

        results = []

        for timing in timing_results:

            matching_destination = next(
                (
                    destination
                    for destination in destination_results
                    if (
                        destination["source_ip"]
                        == timing["source_ip"]
                        and destination[
                            "dominant_destination"
                        ]
                        == timing["destination_ip"]
                    )
                ),
                None,
            )

            if matching_destination is None:
                continue

            c2_result = (
                calculate_c2_behavior_score(
                    timing,
                    matching_destination,
                )
            )

            results.append(
                {
                    "source_ip": timing[
                        "source_ip"
                    ],
                    "destination_ip": timing[
                        "destination_ip"
                    ],
                    **c2_result,
                }
            )

        if not results:
            return {
                "c2_behavior_score": 0.0,
                "c2_classification": "C2_UNLIKELY",
                "evidence": [],
                "timing": timing_results,
                "destinations": destination_results,
                "pairs": [],
            }

        strongest_result = max(
            results,
            key=lambda item: item[
                "c2_behavior_score"
            ],
        )

        return {
            "c2_behavior_score": (
                strongest_result[
                    "c2_behavior_score"
                ]
            ),
            "c2_classification": (
                strongest_result[
                    "classification"
                ]
            ),
            "evidence": (
                strongest_result[
                    "evidence"
                ]
            ),
            "timing": timing_results,
            "destinations": destination_results,
            "pairs": results,
        }


    # ============================================================
    # RISK CALCULATION
    # ============================================================

    def calculate_risk(
        self,
        prediction,
        confidence,
        rule_score,
        behavior_score,
        c2_behavior_score=0.0,
        c2_classification="C2_UNLIKELY"
    ):

        ml_score = 0.0

        behavior_contribution = 0.0

        c2_contribution = 0.0

        # --------------------------------------------------------
        # ML CONTRIBUTION
        # --------------------------------------------------------

        if prediction != "BENIGN":

            ml_score = (
                confidence * 60.0
            )

            behavior_contribution = (
                behavior_score * 0.10
            )

        # --------------------------------------------------------
        # C2 CONTRIBUTION
        # --------------------------------------------------------

        if (
            c2_classification == "C2_LIKELY"
        ):

            c2_contribution = (
                c2_behavior_score * 0.20
            )

        # --------------------------------------------------------
        # FINAL RISK
        # --------------------------------------------------------

        risk_score = min(
            ml_score
            + rule_score
            + behavior_contribution
            + c2_contribution,
            100.0
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
            ml_score,
            behavior_contribution,
            c2_contribution,
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
            c2_contribution,
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

            "c2_risk_contribution":
                round(
                    c2_contribution,
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

    def analyze_with_packets(
        self,
        features: dict,
        packets: list,
    ) -> dict:

        # --------------------------------------------------------
        # BASE ANALYSIS
        # --------------------------------------------------------

        result = self.analyze(
            features
        )

        # --------------------------------------------------------
        # DNS INTELLIGENCE
        # --------------------------------------------------------

        dns_intelligence = (
            self.analyze_dns_intelligence(
                packets
            )
        )

        # --------------------------------------------------------
        # C2 INTELLIGENCE
        # --------------------------------------------------------

        c2_intelligence = (
            self.analyze_c2_intelligence(
                packets
            )
        )

        # --------------------------------------------------------
        # TLS INTELLIGENCE
        # --------------------------------------------------------

        tls_intelligence = (
            self.analyze_tls_intelligence(
                packets
            )
        )

        # --------------------------------------------------------
        # EXTRACT C2 INFORMATION
        # --------------------------------------------------------

        c2_behavior_score = float(
            c2_intelligence.get(
                "c2_behavior_score",
                0.0
            )
        )

        c2_classification = (
            c2_intelligence.get(
                "c2_classification",
                "C2_UNLIKELY"
            )
        )

        # --------------------------------------------------------
        # RE-CALCULATE UNIFIED RISK
        # --------------------------------------------------------

        (
            ml_score,
            behavior_contribution,
            c2_contribution,
            risk_score,
            severity
        ) = self.calculate_risk(
            result["threat_class"],
            result["confidence"],
            result["rule_contribution"],
            result["behavior_contribution"] / 0.10
            if result["behavior_contribution"] > 0
            else 0.0,
            c2_behavior_score,
            c2_classification
        )

        # --------------------------------------------------------
        # UPDATE PRIMARY RESULT
        # --------------------------------------------------------

        result["ml_risk_contribution"] = round(
            ml_score,
            2
        )

        result["behavior_contribution"] = round(
            behavior_contribution,
            2
        )

        result["c2_risk_contribution"] = round(
            c2_contribution,
            2
        )

        result["risk_score"] = round(
            risk_score,
            2
        )

        result["severity"] = severity

        # --------------------------------------------------------
        # C2 CAN OVERRIDE BENIGN CLASSIFICATION
        # --------------------------------------------------------

        if (
            c2_classification == "C2_LIKELY"
            and result["threat_class"] == "BENIGN"
        ):

            result["threat_class"] = (
                "C2_BEACONING"
            )

            result["confidence"] = round(
                c2_behavior_score / 100.0,
                4
            )

        # --------------------------------------------------------
        # ADD C2 EVIDENCE
        # --------------------------------------------------------

        result["evidence"] = (
            result.get("evidence", [])
            + c2_intelligence.get(
                "evidence",
                []
            )
        )

        # --------------------------------------------------------
        # ATTACH INTELLIGENCE
        # --------------------------------------------------------

        result["dns_intelligence"] = (
            dns_intelligence
        )

        result["c2_intelligence"] = (
            c2_intelligence
        )

        result["tls_intelligence"] = (
            tls_intelligence
        )

        return result
        
    def analyze_tls_intelligence(
        self,
        packets: list,
    ) -> dict:
        """
        Analyze passive TLS metadata.

        No TLS decryption is performed.
        """

        return analyze_tls_intelligence(
            packets
        )