from typing import Any


def calculate_tunnel_score(
    aggregate: dict[str, Any],
) -> dict[str, Any]:

    score = 0.0
    evidence = []

    total_queries = float(
        aggregate.get("total_queries", 0)
    )

    unique_queries = float(
        aggregate.get("unique_queries", 0)
    )

    average_length = float(
        aggregate.get("average_query_length", 0)
    )

    maximum_length = float(
        aggregate.get("maximum_query_length", 0)
    )

    average_entropy = float(
        aggregate.get("average_entropy", 0)
    )

    maximum_entropy = float(
        aggregate.get("maximum_entropy", 0)
    )

    average_digit_ratio = float(
        aggregate.get("average_digit_ratio", 0)
    )

    average_unique_ratio = float(
        aggregate.get(
            "average_unique_character_ratio",
            0,
        )
    )

    if total_queries > 0:
        unique_ratio = (
            unique_queries / total_queries
        )
    else:
        unique_ratio = 0.0

    # ---------------------------------------------------------
    # Long query names
    # ---------------------------------------------------------

    if average_length >= 60:
        score += 25
        evidence.append(
            f"[DNS_TUNNEL_LONG_QUERIES] "
            f"Average query length {average_length:.2f}"
        )

    elif average_length >= 40:
        score += 15
        evidence.append(
            f"[DNS_TUNNEL_ELEVATED_LENGTH] "
            f"Average query length {average_length:.2f}"
        )

    elif average_length >= 25:
        score += 5

    # ---------------------------------------------------------
    # Maximum query length
    # ---------------------------------------------------------

    if maximum_length >= 100:
        score += 15
        evidence.append(
            f"[DNS_TUNNEL_LONG_MAX_QUERY] "
            f"Maximum query length {int(maximum_length)}"
        )

    elif maximum_length >= 60:
        score += 8

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------

    if average_entropy >= 4.5:
        score += 20
        evidence.append(
            f"[DNS_TUNNEL_HIGH_ENTROPY] "
            f"Average entropy {average_entropy:.2f}"
        )

    elif average_entropy >= 4.0:
        score += 12
        evidence.append(
            f"[DNS_TUNNEL_ELEVATED_ENTROPY] "
            f"Average entropy {average_entropy:.2f}"
        )

    # ---------------------------------------------------------
    # Query uniqueness
    # ---------------------------------------------------------

    if (
        total_queries >= 20
        and unique_ratio >= 0.80
    ):
        score += 20
        evidence.append(
            f"[DNS_TUNNEL_HIGH_UNIQUENESS] "
            f"{unique_queries:.0f}/{total_queries:.0f} "
            f"queries are unique"
        )

    elif (
        total_queries >= 10
        and unique_ratio >= 0.60
    ):
        score += 10
        evidence.append(
            f"[DNS_TUNNEL_ELEVATED_UNIQUENESS] "
            f"{unique_queries:.0f}/{total_queries:.0f} "
            f"queries are unique"
        )

    # ---------------------------------------------------------
    # Digit / encoded-looking composition
    # ---------------------------------------------------------

    if average_digit_ratio >= 0.30:
        score += 10
        evidence.append(
            f"[DNS_TUNNEL_DIGIT_COMPOSITION] "
            f"Average digit ratio {average_digit_ratio:.2f}"
        )

    elif average_digit_ratio >= 0.20:
        score += 5

    # ---------------------------------------------------------
    # Character diversity
    # ---------------------------------------------------------

    if average_unique_ratio >= 0.90:
        score += 10
        evidence.append(
            f"[DNS_TUNNEL_HIGH_DIVERSITY] "
            f"Average unique-character ratio "
            f"{average_unique_ratio:.2f}"
        )

    # ---------------------------------------------------------
    # Very high maximum entropy
    # ---------------------------------------------------------

    if maximum_entropy >= 5.0:
        score += 10
        evidence.append(
            f"[DNS_TUNNEL_MAX_ENTROPY] "
            f"Maximum entropy {maximum_entropy:.2f}"
        )

    score = min(
        score,
        100.0,
    )

    if score >= 70:
        classification = "TUNNEL_LIKELY"

    elif score >= 40:
        classification = "TUNNEL_SUSPICIOUS"

    else:
        classification = "TUNNEL_UNLIKELY"

    return {
        "tunnel_score": round(
            score,
            2,
        ),
        "classification": classification,
        "evidence": evidence,
    }