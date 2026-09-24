import re
from typing import Any


BASE64_PATTERN = re.compile(
    r"^[A-Za-z0-9+/]+={0,2}$"
)

HEX_PATTERN = re.compile(
    r"^[0-9a-fA-F]+$"
)


def score_length(features: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    evidence = []

    query_length = float(
        features.get("query_length", 0)
    )

    longest_label = float(
        features.get("longest_label_length", 0)
    )

    if query_length >= 100:
        score += 30
        evidence.append(
            f"[DNS_LONG_QUERY] Query length {int(query_length)}"
        )
    elif query_length >= 60:
        score += 20
        evidence.append(
            f"[DNS_LONG_QUERY] Query length {int(query_length)}"
        )
    elif query_length >= 40:
        score += 10
        evidence.append(
            f"[DNS_LONG_QUERY] Query length {int(query_length)}"
        )

    if longest_label >= 50:
        score += 20
        evidence.append(
            f"[DNS_LONG_LABEL] Longest label {int(longest_label)} characters"
        )
    elif longest_label >= 30:
        score += 10
        evidence.append(
            f"[DNS_LONG_LABEL] Longest label {int(longest_label)} characters"
        )

    return score, evidence


def score_entropy(features: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    evidence = []

    entropy = float(
        features.get("character_entropy", 0)
    )

    if entropy >= 4.5:
        score += 25
        evidence.append(
            f"[DNS_HIGH_ENTROPY] Character entropy {entropy:.2f}"
        )
    elif entropy >= 4.0:
        score += 15
        evidence.append(
            f"[DNS_HIGH_ENTROPY] Character entropy {entropy:.2f}"
        )
    elif entropy >= 3.5:
        score += 8
        evidence.append(
            f"[DNS_MODERATE_ENTROPY] Character entropy {entropy:.2f}"
        )

    return score, evidence


def score_character_composition(
    features: dict[str, Any],
) -> tuple[float, list[str]]:

    score = 0.0
    evidence = []

    digit_ratio = float(
        features.get("digit_ratio", 0)
    )

    unique_ratio = float(
        features.get(
            "unique_character_ratio",
            0,
        )
    )

    if digit_ratio >= 0.40:
        score += 20
        evidence.append(
            f"[DNS_HIGH_DIGIT_RATIO] Digit ratio {digit_ratio:.2f}"
        )
    elif digit_ratio >= 0.25:
        score += 10
        evidence.append(
            f"[DNS_HIGH_DIGIT_RATIO] Digit ratio {digit_ratio:.2f}"
        )

    if unique_ratio >= 0.90:
        score += 15
        evidence.append(
            f"[DNS_HIGH_DIVERSITY] Unique-character ratio {unique_ratio:.2f}"
        )
    elif unique_ratio >= 0.80:
        score += 8
        evidence.append(
            f"[DNS_HIGH_DIVERSITY] Unique-character ratio {unique_ratio:.2f}"
        )

    return score, evidence


def detect_encoding_pattern(
    query_name: str,
) -> tuple[float, list[str]]:

    score = 0.0
    evidence = []

    labels = [
        label
        for label in query_name.split(".")
        if label
    ]

    for label in labels:

        if len(label) < 16:
            continue

        if BASE64_PATTERN.fullmatch(label):

            score += 20

            evidence.append(
                "[DNS_BASE64_PATTERN] "
                f"Encoding-like label '{label}'"
            )

        elif (
            len(label) >= 16
            and len(label) % 2 == 0
            and HEX_PATTERN.fullmatch(label)
        ):

            score += 20

            evidence.append(
                "[DNS_HEX_PATTERN] "
                f"Hex-like label '{label}'"
            )

    return min(score, 30.0), evidence


def calculate_dns_anomaly_score(
    features: dict[str, Any],
) -> dict[str, Any]:

    length_score, length_evidence = score_length(
        features
    )

    entropy_score, entropy_evidence = score_entropy(
        features
    )

    composition_score, composition_evidence = (
        score_character_composition(
            features
        )
    )

    encoding_score, encoding_evidence = (
        detect_encoding_pattern(
            features.get("query_name", "")
        )
    )

    total_score = (
        length_score
        + entropy_score
        + composition_score
        + encoding_score
    )

    total_score = min(
        total_score,
        100.0,
    )

    evidence = (
        length_evidence
        + entropy_evidence
        + composition_evidence
        + encoding_evidence
    )

    if total_score >= 70:
        classification = "HIGHLY_SUSPICIOUS"
    elif total_score >= 40:
        classification = "SUSPICIOUS"
    else:
        classification = "NORMAL"

    return {
        "dns_anomaly_score": round(
            total_score,
            2,
        ),
        "classification": classification,
        "evidence": evidence,
    }