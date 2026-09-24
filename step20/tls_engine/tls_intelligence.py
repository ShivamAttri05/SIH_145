from __future__ import annotations

import hashlib
from typing import Any

from scapy.layers.tls.handshake import (
    TLSClientHello,
    TLSServerHello,
)

from .tls_features import analyze_tls_packet
from .tls_fingerprint import analyze_tls_fingerprint


def analyze_tls_server_fingerprint(
    server_hello: TLSServerHello,
) -> dict[str, Any]:
    """
    Generate JA3S fingerprint from a TLS ServerHello.

    JA3S format:
        TLSVersion,Cipher,Extensions

    The resulting JA3S string is MD5 hashed.

    No TLS decryption is performed.
    """

    # ---------------------------------------------------------
    # TLS VERSION
    # ---------------------------------------------------------

    version = server_hello.version

    if version is None:
        version_value = 0
    else:
        version_value = int(version)

    # ---------------------------------------------------------
    # CIPHER SUITE
    # ---------------------------------------------------------

    cipher = server_hello.cipher

    if cipher is None:
        cipher_value = 0
    else:
        cipher_value = int(cipher)

    # ---------------------------------------------------------
    # SERVER HELLO EXTENSIONS
    # ---------------------------------------------------------

    extension_ids = []

    extensions = server_hello.ext

    if extensions:
        for extension in extensions:

            extension_type = getattr(
                extension,
                "type",
                None,
            )

            if extension_type is not None:
                extension_ids.append(
                    int(extension_type)
                )

    # JA3S extension format:
    # 0-11-16
    extension_string = "-".join(
        str(extension_id)
        for extension_id in extension_ids
    )

    # ---------------------------------------------------------
    # JA3S STRING
    # ---------------------------------------------------------

    ja3s_string = (
        f"{version_value},"
        f"{cipher_value},"
        f"{extension_string}"
    )

    # ---------------------------------------------------------
    # JA3S MD5
    # ---------------------------------------------------------

    ja3s_hash = hashlib.md5(
        ja3s_string.encode("utf-8")
    ).hexdigest()

    return {
        "tls_version": version_value,
        "cipher_suite": cipher_value,
        "extension_ids": extension_ids,
        "ja3s_string": ja3s_string,
        "ja3s_hash": ja3s_hash,
    }


def analyze_tls_intelligence(
    packets: list,
) -> dict[str, Any]:
    """
    Analyze passive TLS metadata across packets.

    Includes:

    - TLS version
    - ClientHello detection
    - ServerHello detection
    - SNI
    - ALPN
    - JA3
    - JA3S

    No TLS decryption is performed.
    """

    # =========================================================
    # TLS PACKET DETECTION
    # =========================================================

    tls_packets = []

    for packet in packets:

        result = analyze_tls_packet(packet)

        if result["tls_detected"]:
            tls_packets.append(result)

    # =========================================================
    # NO TLS TRAFFIC
    # =========================================================

    if not tls_packets:
        return {
            "tls_detected": False,
            "tls_packet_count": 0,
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_versions": [],
            "sni_values": [],
            "alpn_values": [],
            "ja3_fingerprints": [],
            "ja3s_fingerprints": [],
            "evidence": [],
        }

    # =========================================================
    # BASIC TLS COUNTS
    # =========================================================

    client_hello_count = sum(
        result["client_hello"]
        for result in tls_packets
    )

    server_hello_count = sum(
        result["server_hello"]
        for result in tls_packets
    )

    # =========================================================
    # TLS VERSIONS
    # =========================================================

    tls_versions = sorted(
        {
            result["tls_version"]
            for result in tls_packets
            if result["tls_version"]
        }
    )

    # =========================================================
    # SNI
    # =========================================================

    sni_values = sorted(
        {
            result["sni"]
            for result in tls_packets
            if result["sni"]
        }
    )

    # =========================================================
    # ALPN
    # =========================================================

    alpn_values = sorted(
        {
            protocol
            for result in tls_packets
            for protocol in result["alpn"]
        }
    )

    # =========================================================
    # JA3
    # =========================================================

    ja3_fingerprints = []

    for packet in packets:

        analysis = analyze_tls_packet(packet)

        if not analysis["client_hello"]:
            continue

        if not packet.haslayer(
            TLSClientHello
        ):
            continue

        client_hello = packet[
            TLSClientHello
        ]

        fingerprint = analyze_tls_fingerprint(
            client_hello
        )

        ja3_fingerprints.append(
            {
                "ja3_hash":
                    fingerprint["ja3_hash"],

                "ja3_string":
                    fingerprint["ja3_string"],
            }
        )

    # =========================================================
    # JA3S
    # =========================================================

    ja3s_fingerprints = []

    for packet in packets:

        analysis = analyze_tls_packet(packet)

        if not analysis["server_hello"]:
            continue

        if not packet.haslayer(
            TLSServerHello
        ):
            continue

        server_hello = packet[
            TLSServerHello
        ]

        fingerprint = analyze_tls_server_fingerprint(
            server_hello
        )

        ja3s_fingerprints.append(
            {
                "ja3s_hash":
                    fingerprint["ja3s_hash"],

                "ja3s_string":
                    fingerprint["ja3s_string"],
            }
        )

    # =========================================================
    # EVIDENCE
    # =========================================================

    evidence = []

    # ---------------------------------------------------------
    # ClientHello
    # ---------------------------------------------------------

    if client_hello_count > 0:

        evidence.append(
            f"[TLS_CLIENT_HELLO] "
            f"{client_hello_count} ClientHello packet(s)"
        )

    # ---------------------------------------------------------
    # ServerHello
    # ---------------------------------------------------------

    if server_hello_count > 0:

        evidence.append(
            f"[TLS_SERVER_HELLO] "
            f"{server_hello_count} ServerHello packet(s)"
        )

    # ---------------------------------------------------------
    # SNI
    # ---------------------------------------------------------

    if sni_values:

        evidence.append(
            f"[TLS_SNI] "
            f"Observed SNI: "
            f"{', '.join(sni_values)}"
        )

    # ---------------------------------------------------------
    # ALPN
    # ---------------------------------------------------------

    if alpn_values:

        evidence.append(
            f"[TLS_ALPN] "
            f"Observed protocols: "
            f"{', '.join(alpn_values)}"
        )

    # ---------------------------------------------------------
    # JA3
    # ---------------------------------------------------------

    if ja3_fingerprints:

        unique_ja3 = sorted(
            {
                item["ja3_hash"]
                for item in ja3_fingerprints
            }
        )

        evidence.append(
            f"[TLS_JA3] "
            f"Observed {len(unique_ja3)} "
            f"JA3 fingerprint(s)"
        )

    # ---------------------------------------------------------
    # JA3S
    # ---------------------------------------------------------

    if ja3s_fingerprints:

        unique_ja3s = sorted(
            {
                item["ja3s_hash"]
                for item in ja3s_fingerprints
            }
        )

        evidence.append(
            f"[TLS_JA3S] "
            f"Observed {len(unique_ja3s)} "
            f"JA3S fingerprint(s)"
        )

    # =========================================================
    # FINAL RESULT
    # =========================================================

    return {
        "tls_detected": True,

        "tls_packet_count":
            len(tls_packets),

        "client_hello_count":
            client_hello_count,

        "server_hello_count":
            server_hello_count,

        "tls_versions":
            tls_versions,

        "sni_values":
            sni_values,

        "alpn_values":
            alpn_values,

        "ja3_fingerprints":
            ja3_fingerprints,

        "ja3s_fingerprints":
            ja3s_fingerprints,

        "evidence":
            evidence,
    }