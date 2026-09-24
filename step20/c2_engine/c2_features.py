from collections import defaultdict
from statistics import mean, stdev
from typing import Any

from scapy.all import IP


def extract_communication_timestamps(
    packets: list,
) -> dict[tuple[str, str], list[float]]:
    """
    Group packet timestamps by source -> destination pair.

    Only IP packets are considered.
    """

    communications = defaultdict(list)

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        timestamp = float(packet.time)

        key = (
            source_ip,
            destination_ip,
        )

        communications[key].append(
            timestamp
        )

    for key in communications:
        communications[key].sort()

    return dict(communications)


def calculate_inter_arrival_times(
    timestamps: list[float],
) -> list[float]:
    """
    Calculate time differences between consecutive
    communications.
    """

    if len(timestamps) < 2:
        return []

    return [
        timestamps[index]
        - timestamps[index - 1]
        for index in range(1, len(timestamps))
    ]


def calculate_coefficient_of_variation(
    intervals: list[float],
) -> float:
    """
    Calculate coefficient of variation:

        standard deviation / mean

    Lower values indicate more regular timing.
    """

    if len(intervals) < 2:
        return 0.0

    average = mean(intervals)

    if average <= 0:
        return 0.0

    deviation = stdev(intervals)

    return deviation / average


def calculate_periodicity_score(
    intervals: list[float],
) -> float:
    """
    Convert timing regularity into a 0-100 score.

    Lower coefficient of variation means stronger
    periodicity.
    """

    if len(intervals) < 3:
        return 0.0

    coefficient = (
        calculate_coefficient_of_variation(
            intervals
        )
    )

    if coefficient <= 0.05:
        return 100.0

    if coefficient <= 0.10:
        return 90.0

    if coefficient <= 0.20:
        return 75.0

    if coefficient <= 0.30:
        return 60.0

    if coefficient <= 0.50:
        return 40.0

    if coefficient <= 0.75:
        return 20.0

    return 0.0


def analyze_communication_timing(
    timestamps: list[float],
) -> dict[str, Any]:

    intervals = calculate_inter_arrival_times(
        timestamps
    )

    if not intervals:

        return {
            "communication_count": len(
                timestamps
            ),
            "average_interval": 0.0,
            "minimum_interval": 0.0,
            "maximum_interval": 0.0,
            "interval_std": 0.0,
            "coefficient_of_variation": 0.0,
            "periodicity_score": 0.0,
        }

    average_interval = mean(
        intervals
    )

    if len(intervals) >= 2:
        interval_std = stdev(
            intervals
        )
    else:
        interval_std = 0.0

    coefficient = (
        calculate_coefficient_of_variation(
            intervals
        )
    )

    periodicity = (
        calculate_periodicity_score(
            intervals
        )
    )

    return {
        "communication_count": len(
            timestamps
        ),
        "average_interval": round(
            average_interval,
            6,
        ),
        "minimum_interval": round(
            min(intervals),
            6,
        ),
        "maximum_interval": round(
            max(intervals),
            6,
        ),
        "interval_std": round(
            interval_std,
            6,
        ),
        "coefficient_of_variation": round(
            coefficient,
            6,
        ),
        "periodicity_score": round(
            periodicity,
            2,
        ),
    }


def analyze_c2_timing(
    packets: list,
) -> list[dict[str, Any]]:
    """
    Analyze temporal communication behavior
    for every source -> destination pair.
    """

    communications = (
        extract_communication_timestamps(
            packets
        )
    )

    results = []

    for (
        source_ip,
        destination_ip,
    ), timestamps in communications.items():

        timing = analyze_communication_timing(
            timestamps
        )

        results.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                **timing,
            }
        )

    return results