from step16 import detection_service
from step16 import detection_service
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL

from scapy.all import rdpcap, IP

from step6.security_features import (
    analyze_packets,
    calculate_security_features,
)

from step8.time_window_engine import (
    create_windows,
    analyze_window,
    calculate_window_features,
)

from step20.feature_engine.security_features import (
    analyze_packet_metadata,
)

from .detection_service import DetectionService


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PCAP = Path(
    "step9/generated/port_scan.pcap"
)


# ============================================================
# FLOW SERVICE
# ============================================================

class FlowService:

    """
    Converts observed PCAP traffic into API-ready
    flow records and associates each flow with
    authoritative detection results.

    This service is passive:
    it only reads and analyzes captured traffic.
    """

    def __init__(
        self,
        pcap_file: str | Path = DEFAULT_PCAP,
    ):

        self.pcap_file = Path(
            pcap_file
        )

        self.detector = DetectionService()


    # ========================================================
    # SOURCE DETECTION
    # ========================================================

    def extract_source_detections(
        self,
        pcap_file
    ):

        packets = rdpcap(
            str(pcap_file)
        )

        windows = create_windows(
            packets
        )

        all_packets = rdpcap(
            str(pcap_file)
        )

        detections = {}

        for window_number in sorted(
            windows.keys()
        ):

            window_packets = windows[
                window_number
            ]

            sources = analyze_window(
                window_packets
            )

            features = calculate_window_features(
                sources
            )

            for feature in features:

                source_ip = feature[
                    "source_ip"
                ]

                source_packets = [
                    packet
                    for packet in window_packets
                    if (
                        packet.haslayer(IP)
                        and packet[IP].src == source_ip
                    )
                ]

                source_history_packets = [
                    packet
                    for packet in all_packets
                    if (
                        packet.haslayer(IP)
                        and packet[IP].src == source_ip
                    )
                ]

                packet_metadata = analyze_packet_metadata(
                    source_packets
                )

                # ------------------------------------------------
                # DNS and inter-arrival features
                #
                # The current Step 8 engine does not calculate
                # these two fields. They are required by the
                # Step 14 model.
                #
                # For this integration, use safe defaults.
                # ------------------------------------------------

                detection_features = {

                    "packets":
                        feature["packets"],

                    "bytes":
                        feature["bytes"],

                    "unique_destination_ips":
                        feature[
                            "unique_destination_ips"
                        ],

                    "unique_destination_ports":
                        feature[
                            "unique_destination_ports"
                        ],

                    "duration":
                        feature["duration"],

                    "packets_per_sec":
                        feature[
                            "packets_per_sec"
                        ],

                    "bytes_per_sec":
                        feature[
                            "bytes_per_sec"
                        ],

                    "tcp_packets":
                        feature["tcp_packets"],

                    "syn_packets":
                        feature["syn_packets"],

                    "ack_packets":
                        feature["ack_packets"],

                    "rst_packets":
                        feature["rst_packets"],

                    "fin_packets":
                        feature["fin_packets"],

                    "syn_ratio":
                        feature["syn_ratio"],

                    "ack_ratio":
                        feature["ack_ratio"],

                    "rst_ratio":
                        feature["rst_ratio"],

                    "fin_ratio":
                        feature["fin_ratio"],

                    "dns_packets":
                        packet_metadata[
                            "dns_packets"
                        ],

                    "average_inter_arrival":
                        packet_metadata[
                            "average_inter_arrival"
                        ], 

                }

                detection = self.detector.analyze_with_packets(
                    detection_features,
                    source_packets,
                )

                c2_intelligence = (
                    self.detector.analyze_c2_intelligence(
                        source_history_packets
                    )
                )

                detection["c2_intelligence"] = (
                    c2_intelligence
                )

                tls_intelligence = (
                   self.detector.analyze_tls_intelligence(
                        source_packets
                    )
                )

                detection["tls_intelligence"] = (
                    tls_intelligence
                )

                detections[source_ip] = {
                    "window_id":
                        window_number,

                    "features":
                        detection_features,

                    "detection":
                        detection
                }

        return detections


    # ========================================================
    # EXTRACT FLOWS
    # ========================================================

    def extract_flows(self) -> list[dict]:

        """
        Read the configured PCAP and convert
        reconstructed flows into API records.
        """

        if not self.pcap_file.exists():

            raise FileNotFoundError(
                f"PCAP file not found: "
                f"{self.pcap_file}"
            )


        # ----------------------------------------------------
        # Packet analysis
        # ----------------------------------------------------

        flows = analyze_packets(
            str(self.pcap_file)
        )


        # ----------------------------------------------------
        # Security-specific flow features
        # ----------------------------------------------------

        features = calculate_security_features(
            flows
        )


        # ----------------------------------------------------
        # Source-level authoritative detection
        # ----------------------------------------------------

        source_detections = (
            self.extract_source_detections(
                self.pcap_file
            )
        )


        flow_records = []


        # ====================================================
        # BUILD FLOW RECORDS
        # ====================================================

        for feature in features:

            # ------------------------------------------------
            # Deterministic flow identifier
            # ------------------------------------------------

            flow_identity = (

                f"{feature['initiator_ip']}:"

                f"{feature['initiator_port']}-"

                f"{feature['responder_ip']}:"

                f"{feature['responder_port']}-"

                f"{feature['protocol']}"

            )


            flow_id = str(

                uuid5(

                    NAMESPACE_URL,

                    flow_identity

                )

            )


            # ------------------------------------------------
            # Authoritative detection
            # ------------------------------------------------

            source_ip = (
                feature["initiator_ip"]
            )

            source_detection = (
                source_detections.get(
                    source_ip
                )
            )


            if source_detection:

                detection = (
                    source_detection[
                        "detection"
                    ]
                )

                detection_features = (
                    source_detection[
                        "features"
                    ]
                )

            else:

                detection = {

                    "threat_class":
                        "UNKNOWN",

                    "confidence":
                        0.0,

                    "ml_risk_contribution":
                        0.0,

                    "rule_contribution":
                        0.0,

                    "behavior_contribution":
                        0.0,

                    "risk_score":
                        0.0,

                    "severity":
                        "LOW",

                    "evidence":
                        []

                }

                detection_features = {}


            # ------------------------------------------------
            # API flow record
            # ------------------------------------------------

            record = {

                "flow_id":
                    flow_id,

                "source_ip":
                    feature[
                        "initiator_ip"
                    ],

                "source_port":
                    feature[
                        "initiator_port"
                    ],

                "destination_ip":
                    feature[
                        "responder_ip"
                    ],

                "destination_port":
                    feature[
                        "responder_port"
                    ],

                "protocol":
                    feature[
                        "protocol"
                    ],


                # ------------------------------------------------
                # Directional traffic
                # ------------------------------------------------

                "forward_packets":
                    feature[
                        "forward_packets"
                    ],

                "reverse_packets":
                    feature[
                        "reverse_packets"
                    ],

                "forward_bytes":
                    feature[
                        "forward_bytes"
                    ],

                "reverse_bytes":
                    feature[
                        "reverse_bytes"
                    ],


                # ------------------------------------------------
                # General traffic
                # ------------------------------------------------

                "packets":
                    feature[
                        "total_packets"
                    ],

                "bytes":
                    feature[
                        "total_bytes"
                    ],

                "duration":
                    feature[
                        "duration"
                    ],

                "packets_per_sec":
                    feature[
                        "packets_per_sec"
                    ],

                "bytes_per_sec":
                    feature[
                        "bytes_per_sec"
                    ],

                "avg_packet_size":
                    feature[
                        "avg_packet_size"
                    ],

                "packet_size_std":
                    feature[
                        "packet_size_std"
                    ],


                # ------------------------------------------------
                # TCP
                # ------------------------------------------------

                "syn_packets":
                    feature[
                        "syn_packets"
                    ],

                "ack_packets":
                    feature[
                        "ack_packets"
                    ],

                "rst_packets":
                    feature[
                        "rst_packets"
                    ],

                "fin_packets":
                    feature[
                        "fin_packets"
                    ],

                "syn_ratio":
                    feature[
                        "syn_ratio"
                    ],

                "ack_ratio":
                    feature[
                        "ack_ratio"
                    ],

                "rst_ratio":
                    feature[
                        "rst_ratio"
                    ],

                "fin_ratio":
                    feature[
                        "fin_ratio"
                    ],


                # ------------------------------------------------
                # Timing
                # ------------------------------------------------

                "average_inter_arrival":
                    feature[
                        "average_inter_arrival"
                    ],


                # ------------------------------------------------
                # DNS
                # ------------------------------------------------

                "dns_packets":
                    feature[
                        "dns_packet_count"
                    ],

                "average_dns_length":
                    feature[
                        "average_dns_length"
                    ],

                "average_dns_entropy":
                    feature[
                        "average_dns_entropy"
                    ],


                # =================================================
                # AUTHORITATIVE DETECTION
                # =================================================

                "detection": detection,

                "dns_intelligence": detection[
                    "dns_intelligence"
                ],

                "c2_intelligence": detection["c2_intelligence"],

                "dga_score": detection[
                    "dns_intelligence"
                ]["dga_score"],

                "dga_classification": detection[
                    "dns_intelligence"
                ]["dga_classification"],

                "tunnel_score": detection[
                    "dns_intelligence"
                ]["tunnel_score"],

                "tunnel_classification": detection[
                    "dns_intelligence"
                ]["tunnel_classification"],

                "c2_classification": detection[
                    "c2_intelligence"
                ]["c2_classification"],

                "c2_behavior_score": detection[
                    "c2_intelligence"
                ]["c2_behavior_score"],

                "detection_features": detection_features,

                "tls_intelligence": detection[
                    "tls_intelligence"
                ],

                "tls_detected": detection[
                    "tls_intelligence"
                ]["tls_detected"],

                "tls_versions": detection[
                    "tls_intelligence"
                ]["tls_versions"],

                "sni_values": detection[
                    "tls_intelligence"
                ]["sni_values"],

                "alpn_values": detection[
                    "tls_intelligence"
                ]["alpn_values"],

                "ja3_fingerprints": detection[
                    "tls_intelligence"
                ]["ja3_fingerprints"],
            }


            flow_records.append(
                record
            )


        return flow_records