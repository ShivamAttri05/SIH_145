from statistics import mean
from typing import Any


def aggregate_dns_features(
    query_features: list[dict[str, Any]],
) -> dict[str, Any]:

    if not query_features:
        return {
            "total_queries": 0,
            "unique_queries": 0,
            "average_query_length": 0.0,
            "maximum_query_length": 0,
            "average_label_count": 0.0,
            "average_longest_label_length": 0.0,
            "maximum_longest_label_length": 0,
            "average_entropy": 0.0,
            "maximum_entropy": 0.0,
            "average_digit_ratio": 0.0,
            "average_alpha_ratio": 0.0,
            "average_unique_character_ratio": 0.0,
        }

    query_names = [
        feature["query_name"]
        for feature in query_features
    ]

    query_lengths = [
        feature["query_length"]
        for feature in query_features
    ]

    label_counts = [
        feature["label_count"]
        for feature in query_features
    ]

    longest_labels = [
        feature["longest_label_length"]
        for feature in query_features
    ]

    entropies = [
        feature["character_entropy"]
        for feature in query_features
    ]

    digit_ratios = [
        feature["digit_ratio"]
        for feature in query_features
    ]

    alpha_ratios = [
        feature["alpha_ratio"]
        for feature in query_features
    ]

    unique_character_ratios = [
        feature["unique_character_ratio"]
        for feature in query_features
    ]

    return {
        "total_queries": len(query_features),

        "unique_queries": len(
            set(query_names)
        ),

        "average_query_length": round(
            mean(query_lengths),
            4,
        ),

        "maximum_query_length": max(
            query_lengths
        ),

        "average_label_count": round(
            mean(label_counts),
            4,
        ),

        "average_longest_label_length": round(
            mean(longest_labels),
            4,
        ),

        "maximum_longest_label_length": max(
            longest_labels
        ),

        "average_entropy": round(
            mean(entropies),
            4,
        ),

        "maximum_entropy": max(
            entropies
        ),

        "average_digit_ratio": round(
            mean(digit_ratios),
            4,
        ),

        "average_alpha_ratio": round(
            mean(alpha_ratios),
            4,
        ),

        "average_unique_character_ratio": round(
            mean(unique_character_ratios),
            4,
        ),
    }


def calculate_suspicious_query_ratio(
    query_features: list[dict[str, Any]],
) -> float:

    if not query_features:
        return 0.0

    suspicious = 0

    for feature in query_features:

        suspicious_signals = 0

        if feature["query_length"] >= 40:
            suspicious_signals += 1

        if feature["longest_label_length"] >= 30:
            suspicious_signals += 1

        if feature["character_entropy"] >= 4.0:
            suspicious_signals += 1

        if feature["digit_ratio"] >= 0.25:
            suspicious_signals += 1

        if feature["unique_character_ratio"] >= 0.80:
            suspicious_signals += 1

        if suspicious_signals >= 2:
            suspicious += 1

    return round(
        suspicious / len(query_features),
        4,
    )