from typing import Any


def calculate_dga_score(
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
    # Entropy
    # ---------------------------------------------------------

    if average_entropy >= 4.5:
        score += 25
        evidence.append(
            f"[DGA_HIGH_AVG_ENTROPY] "
            f"Average entropy {average_entropy:.2f}"
        )

    elif average_entropy >= 4.0:
        score += 15
        evidence.append(
            f"[DGA_ELEVATED_AVG_ENTROPY] "
            f"Average entropy {average_entropy:.2f}"
        )

    elif average_entropy >= 3.5:
        score += 8

    # ---------------------------------------------------------
    # Query length
    # ---------------------------------------------------------

    if average_length >= 50:
        score += 20
        evidence.append(
            f"[DGA_LONG_DOMAINS] "
            f"Average query length {average_length:.2f}"
        )

    elif average_length >= 35:
        score += 12
        evidence.append(
            f"[DGA_ELEVATED_LENGTH] "
            f"Average query length {average_length:.2f}"
        )

    # ---------------------------------------------------------
    # Maximum length
    # ---------------------------------------------------------

    if maximum_length >= 80:
        score += 10
        evidence.append(
            f"[DGA_LONG_MAX_DOMAIN] "
            f"Maximum query length {int(maximum_length)}"
        )

    # ---------------------------------------------------------
    # Digit composition
    # ---------------------------------------------------------

    if average_digit_ratio >= 0.30:
        score += 15
        evidence.append(
            f"[DGA_HIGH_DIGIT_RATIO] "
            f"Average digit ratio {average_digit_ratio:.2f}"
        )

    elif average_digit_ratio >= 0.20:
        score += 8
        evidence.append(
            f"[DGA_ELEVATED_DIGIT_RATIO] "
            f"Average digit ratio {average_digit_ratio:.2f}"
        )

    # ---------------------------------------------------------
    # Character diversity
    # ---------------------------------------------------------

    if average_unique_ratio >= 0.90:
        score += 15
        evidence.append(
            f"[DGA_HIGH_CHARACTER_DIVERSITY] "
            f"Average unique-character ratio "
            f"{average_unique_ratio:.2f}"
        )

    elif average_unique_ratio >= 0.80:
        score += 8

    # ---------------------------------------------------------
    # Domain uniqueness
    # ---------------------------------------------------------

    if unique_ratio >= 0.90 and total_queries >= 10:
        score += 15
        evidence.append(
            f"[DGA_HIGH_QUERY_UNIQUENESS] "
            f"{unique_queries:.0f}/{total_queries:.0f} "
            f"queries are unique"
        )

    elif unique_ratio >= 0.70 and total_queries >= 10:
        score += 8
        evidence.append(
            f"[DGA_ELEVATED_QUERY_UNIQUENESS] "
            f"{unique_queries:.0f}/{total_queries:.0f} "
            f"queries are unique"
        )

    score = min(
        score,
        100.0,
    )

    if score >= 70:
        classification = "DGA_LIKELY"

    elif score >= 40:
        classification = "DGA_SUSPICIOUS"

    else:
        classification = "DGA_UNLIKELY"

    return {
        "dga_score": round(
            score,
            2,
        ),
        "classification": classification,
        "evidence": evidence,
    }