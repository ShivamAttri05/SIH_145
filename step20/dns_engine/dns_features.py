import math
from collections import Counter
from typing import Any

from scapy.all import DNS, DNSQR


def normalize_query_name(query_name: Any) -> str:
    """
    Convert a Scapy DNS query name into a normalized string.
    """

    if query_name is None:
        return ""

    if isinstance(query_name, bytes):
        query_name = query_name.decode(
            "utf-8",
            errors="ignore",
        )

    query_name = str(query_name)

    return query_name.rstrip(".").lower()


def extract_dns_query_names(packets: list) -> list[str]:
    """
    Extract DNS query names from DNS query packets.

    Only packets containing a DNS question record are considered.
    """

    query_names = []

    for packet in packets:

        if not packet.haslayer(DNS):
            continue

        dns_layer = packet[DNS]

        if dns_layer.qr != 0:
            continue

        if not packet.haslayer(DNSQR):
            continue

        query_name = normalize_query_name(
            packet[DNSQR].qname
        )

        if query_name:
            query_names.append(query_name)

    return query_names


def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a string.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():

        probability = count / length

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


def calculate_digit_ratio(value: str) -> float:
    """
    Calculate the fraction of characters that are digits.
    """

    if not value:
        return 0.0

    digits = sum(
        1
        for character in value
        if character.isdigit()
    )

    return digits / len(value)


def calculate_alpha_ratio(value: str) -> float:
    """
    Calculate the fraction of characters that are alphabetic.
    """

    if not value:
        return 0.0

    alphabetic = sum(
        1
        for character in value
        if character.isalpha()
    )

    return alphabetic / len(value)


def calculate_unique_character_ratio(value: str) -> float:
    """
    Calculate the fraction of unique characters.
    """

    if not value:
        return 0.0

    return len(set(value)) / len(value)


def calculate_label_count(query_name: str) -> int:
    """
    Count DNS labels in a query name.
    """

    if not query_name:
        return 0

    return len(
        [
            label
            for label in query_name.split(".")
            if label
        ]
    )


def calculate_longest_label(query_name: str) -> int:
    """
    Return the length of the longest DNS label.
    """

    labels = [
        label
        for label in query_name.split(".")
        if label
    ]

    if not labels:
        return 0

    return max(
        len(label)
        for label in labels
    )


def analyze_dns_query(query_name: str) -> dict[str, Any]:
    """
    Extract lexical DNS features from one query.
    """

    normalized = normalize_query_name(
        query_name
    )

    labels = [
        label
        for label in normalized.split(".")
        if label
    ]

    longest_label = (
        max(len(label) for label in labels)
        if labels
        else 0
    )

    return {
        "query_name": normalized,
        "query_length": len(normalized),
        "label_count": len(labels),
        "longest_label_length": longest_label,
        "character_entropy": calculate_entropy(
            normalized
        ),
        "digit_ratio": calculate_digit_ratio(
            normalized
        ),
        "alpha_ratio": calculate_alpha_ratio(
            normalized
        ),
        "unique_character_ratio": (
            calculate_unique_character_ratio(
                normalized
            )
        ),
    }


def analyze_dns_packets(
    packets: list,
) -> list[dict[str, Any]]:
    """
    Extract DNS query features from packets.
    """

    query_names = extract_dns_query_names(
        packets
    )

    return [
        analyze_dns_query(query_name)
        for query_name in query_names
    ]
