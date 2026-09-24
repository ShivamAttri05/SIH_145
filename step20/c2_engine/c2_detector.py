from typing import Any


def calculate_c2_behavior_score(
    timing: dict[str, Any],
    destination: dict[str, Any],
) -> dict[str, Any]:

    score = 0.0
    evidence = []

    communication_count = int(
        timing.get(
            "communication_count",
            0,
        )
    )

    periodicity_score = float(
        timing.get(
            "periodicity_score",
            0,
        )
    )

    coefficient_of_variation = float(
        timing.get(
            "coefficient_of_variation",
            0,
        )
    )

    average_interval = float(
        timing.get(
            "average_interval",
            0,
        )
    )

    unique_destinations = int(
        destination.get(
            "unique_destinations",
            0,
        )
    )

    destination_concentration = float(
        destination.get(
            "destination_concentration",
            0,
        )
    )

    dominant_destination_count = int(
        destination.get(
            "dominant_destination_count",
            0,
        )
    )

    # ---------------------------------------------------------
    # Repeated communication
    # ---------------------------------------------------------

    if communication_count >= 50:

        score += 15

        evidence.append(
            f"[C2_HIGH_COMMUNICATION_COUNT] "
            f"{communication_count} communications"
        )

    elif communication_count >= 20:

        score += 10

        evidence.append(
            f"[C2_REPEATED_COMMUNICATION] "
            f"{communication_count} communications"
        )

    elif communication_count >= 10:

        score += 5

    # ---------------------------------------------------------
    # Strong periodicity
    # ---------------------------------------------------------

    if periodicity_score >= 90:

        score += 40

        evidence.append(
            f"[C2_STRONG_PERIODICITY] "
            f"Periodicity score "
            f"{periodicity_score:.1f}"
        )

    elif periodicity_score >= 75:

        score += 30

        evidence.append(
            f"[C2_HIGH_PERIODICITY] "
            f"Periodicity score "
            f"{periodicity_score:.1f}"
        )

    elif periodicity_score >= 60:

        score += 20

        evidence.append(
            f"[C2_MODERATE_PERIODICITY] "
            f"Periodicity score "
            f"{periodicity_score:.1f}"
        )

    elif periodicity_score >= 40:

        score += 10

    # ---------------------------------------------------------
    # Timing stability
    # ---------------------------------------------------------

    if (
        communication_count >= 5
        and coefficient_of_variation <= 0.20
    ):

        score += 20

        evidence.append(
            f"[C2_STABLE_TIMING] "
            f"Coefficient of variation "
            f"{coefficient_of_variation:.3f}"
        )

    # ---------------------------------------------------------
    # Reasonable beacon interval
    # ---------------------------------------------------------

    if (
        communication_count >= 5
        and 5.0 <= average_interval <= 3600.0
    ):

        score += 10

        evidence.append(
            f"[C2_BEACON_INTERVAL] "
            f"Average interval "
            f"{average_interval:.2f} seconds"
        )
    # ---------------------------------------------------------
    # Destination persistence
    # ---------------------------------------------------------

    unique_destination_ports = int(
        destination.get(
            "unique_destination_ports",
            0,
        )
    )

    destination_port_concentration = float(
        destination.get(
            "destination_port_concentration",
            0,
        )
    )

    if (
        communication_count >= 10
        and unique_destinations <= 3
        and destination_concentration >= 0.80
        and unique_destination_ports <= 3
        and destination_port_concentration >= 0.80
    ):

        score += 15

        evidence.append(
            f"[C2_DESTINATION_PERSISTENCE] "
            f"{dominant_destination_count}/"
            f"{communication_count} communications "
            f"to dominant destination "
            f"with {unique_destination_ports} "
            f"destination port(s)"
        )

    elif (
        communication_count >= 10
        and destination_concentration >= 0.60
        and destination_port_concentration >= 0.60
    ):

        score += 8

        evidence.append(
            f"[C2_DESTINATION_CONCENTRATION] "
            f"Destination concentration "
            f"{destination_concentration:.2f}; "
            f"port concentration "
            f"{destination_port_concentration:.2f}"
        )

    score = min(
        score,
        100.0,
    )

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    if (
        communication_count >= 5
        and periodicity_score >= 75
        and coefficient_of_variation <= 0.20
        and destination_concentration >= 0.80
        and unique_destination_ports <= 3
        and destination_port_concentration >= 0.80
    ):

        classification = "C2_LIKELY"

    elif (
        communication_count >= 5
        and periodicity_score >= 40
        and coefficient_of_variation <= 0.50
    ):

        classification = "C2_SUSPICIOUS"

    else:

        classification = "C2_UNLIKELY"

    return {
        "c2_behavior_score": round(
            score,
            2,
        ),
        "classification": classification,
        "evidence": evidence,
    }