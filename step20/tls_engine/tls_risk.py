from __future__ import annotations

from typing import Any


def calculate_tls_risk(
    tls_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate a bounded TLS intelligence score.

    This is an intelligence/risk contribution, not a standalone
    maliciousness verdict.

    No TLS decryption is performed.
    """

    score = 0.0
    evidence: list[str] = []

    tls_detected = bool(
        tls_intelligence.get(
            "tls_detected",
            False,
        )
    )

    if not tls_detected:
        return {
            "tls_score": 0.0,
            "classification": "TLS_NOT_DETECTED",
            "evidence": [],
        }

    # ---------------------------------------------------------
    # TLS PRESENCE
    # ---------------------------------------------------------

    score += 5

    evidence.append(
        "[TLS_DETECTED] TLS traffic detected."
    )

    # ---------------------------------------------------------
    # CLIENT HELLO
    # ---------------------------------------------------------

    client_hello_count = int(
        tls_intelligence.get(
            "client_hello_count",
            0,
        )
    )

    if client_hello_count > 0:

        score += 5

        evidence.append(
            f"[TLS_CLIENT_HELLO] "
            f"{client_hello_count} ClientHello packet(s)."
        )

    # ---------------------------------------------------------
    # SERVER HELLO
    # ---------------------------------------------------------

    server_hello_count = int(
        tls_intelligence.get(
            "server_hello_count",
            0,
        )
    )

    if server_hello_count > 0:

        score += 5

        evidence.append(
            f"[TLS_SERVER_HELLO] "
            f"{server_hello_count} ServerHello packet(s)."
        )

    # ---------------------------------------------------------
    # SNI
    # ---------------------------------------------------------

    sni_values = tls_intelligence.get(
        "sni_values",
        [],
    )

    if sni_values:

        score += 5

        evidence.append(
            f"[TLS_SNI_PRESENT] "
            f"{len(sni_values)} SNI value(s) observed."
        )

    # ---------------------------------------------------------
    # JA3
    # ---------------------------------------------------------

    ja3_fingerprints = tls_intelligence.get(
        "ja3_fingerprints",
        [],
    )

    if ja3_fingerprints:

        score += 10

        evidence.append(
            f"[TLS_JA3_PRESENT] "
            f"{len(ja3_fingerprints)} JA3 "
            f"fingerprint record(s) observed."
        )

    # ---------------------------------------------------------
    # JA3S
    # ---------------------------------------------------------

    ja3s_fingerprints = tls_intelligence.get(
        "ja3s_fingerprints",
        [],
    )

    if ja3s_fingerprints:

        score += 10

        evidence.append(
            f"[TLS_JA3S_PRESENT] "
            f"{len(ja3s_fingerprints)} JA3S "
            f"fingerprint record(s) observed."
        )

    # ---------------------------------------------------------
    # TLS VERSION
    # ---------------------------------------------------------

    tls_versions = tls_intelligence.get(
        "tls_versions",
        [],
    )

    if tls_versions:

        evidence.append(
            f"[TLS_VERSION] "
            f"Observed: {', '.join(tls_versions)}"
        )

    # ---------------------------------------------------------
    # FINGERPRINT DIVERSITY
    # ---------------------------------------------------------

    unique_ja3 = {
        item.get("ja3_hash")
        for item in ja3_fingerprints
        if item.get("ja3_hash")
    }

    unique_ja3s = {
        item.get("ja3s_hash")
        for item in ja3s_fingerprints
        if item.get("ja3s_hash")
    }

    if len(unique_ja3) > 1:

        score += 5

        evidence.append(
            f"[TLS_JA3_DIVERSITY] "
            f"{len(unique_ja3)} unique JA3 fingerprints observed."
        )

    if len(unique_ja3s) > 1:

        score += 5

        evidence.append(
            f"[TLS_JA3S_DIVERSITY] "
            f"{len(unique_ja3s)} unique JA3S fingerprints observed."
        )

    # ---------------------------------------------------------
    # CAP SCORE
    # ---------------------------------------------------------

    score = min(
        score,
        50.0,
    )

    # ---------------------------------------------------------
    # CLASSIFICATION
    # ---------------------------------------------------------

    if score >= 35:

        classification = "TLS_HIGH_INTELLIGENCE"

    elif score >= 20:

        classification = "TLS_MODERATE_INTELLIGENCE"

    elif score > 0:

        classification = "TLS_LOW_INTELLIGENCE"

    else:

        classification = "TLS_NOT_DETECTED"

    return {
        "tls_score": round(
            score,
            2,
        ),
        "classification": classification,
        "evidence": evidence,
    }